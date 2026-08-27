"""Evidence ledger: one SQLite file holding invoices, payments, approvals, jobs.

Idempotency contract (the double-pay defence, in order):
  1. An invoice row is claimed with INSERT ... ON CONFLICT DO NOTHING on the
     UNIQUE (merchant, invoice_id) key BEFORE any rail is called. The row pins
     the invoice digest (amount/currency/memo hash); a later invoice with the
     same key but different terms fails the digest check and is never paid.
  2. The claim moves atomically NEW -> PAYING via a conditional UPDATE; only the
     process that wins that UPDATE may talk to the rail. A concurrent second
     run loses the UPDATE and must back off.
  3. After the rail settles, the row records the receipt and becomes PAID
     (terminal). Re-running the same invoice afterwards is a no-op.

Crash window: if the process dies after the rail settled but before step 3
committed, the row is left PAYING. Recovery policy (documented, deliberate):
a PAYING row is never re-paid automatically - reconciliation queries the rail's
own settlement lookup by (merchant, invoice_id); if the rail confirms a
settlement, the receipt is adopted (PAYING -> PAID) without moving money again;
if the rail has no record, the row stays PAYING for a human/verifier decision.
Losing a receipt is recoverable; paying twice is not.

Approvals are terminal: PRIMARY KEY (merchant, invoice_id) admits exactly one
decision (APPROVED or REJECTED) per invoice, bound to the invoice digest at
decision time. There is no revision path; a wrong decision means issuing a new
invoice_id.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from decimal import Decimal
from pathlib import Path

from .policy import Invoice

SCHEMA = """
CREATE TABLE IF NOT EXISTS invoices (
  merchant   TEXT NOT NULL,
  invoice_id TEXT NOT NULL,
  amount     TEXT NOT NULL,
  currency   TEXT NOT NULL,
  memo       TEXT NOT NULL DEFAULT '',
  digest     TEXT NOT NULL,
  state      TEXT NOT NULL DEFAULT 'NEW',  -- NEW | PAYING | PAID | ASK_PENDING | DENIED
  verdict    TEXT,
  receipt    TEXT,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  PRIMARY KEY (merchant, invoice_id)
);
CREATE TABLE IF NOT EXISTS approvals (
  merchant       TEXT NOT NULL,
  invoice_id     TEXT NOT NULL,
  action         TEXT NOT NULL,           -- APPROVED | REJECTED (terminal, exactly one row)
  actor          TEXT NOT NULL,
  note           TEXT,
  invoice_digest TEXT NOT NULL,
  created_at     REAL NOT NULL,
  PRIMARY KEY (merchant, invoice_id)
);
CREATE TABLE IF NOT EXISTS jobs (
  job_id     TEXT PRIMARY KEY,
  state      TEXT NOT NULL,               -- RUNNING | WAITING_APPROVAL | DONE | FAILED
  payload    TEXT NOT NULL,
  merchant   TEXT,
  invoice_id TEXT,
  result     TEXT,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_events (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id     TEXT NOT NULL,
  actor          TEXT NOT NULL,           -- authenticated principal, never caller input
  action         TEXT NOT NULL,           -- APPROVED | REJECTED | RESUME
  outcome        TEXT NOT NULL,           -- recorded | idempotent-noop | conflict | resumed
  job_id         TEXT,
  merchant       TEXT,
  invoice_id     TEXT,
  invoice_digest TEXT,
  state_before   TEXT,
  state_after    TEXT,
  created_at     REAL NOT NULL
);
"""


class Ledger:
    def __init__(self, path: str | Path):
        self.conn = sqlite3.connect(str(path), timeout=10)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        # The ledger is the evidence store: keep it owner-only. SQLite copies
        # the main file's mode onto -wal/-shm sidecars it creates afterwards.
        try:
            os.chmod(str(path), 0o600)
        except OSError:
            pass  # e.g. ":memory:" or a filesystem without chmod

    def integrity_ok(self) -> bool:
        return self.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    def close(self) -> None:
        self.conn.close()

    # -- invoice lifecycle -------------------------------------------------

    def claim(self, inv: Invoice) -> None:
        """Ensure the unique row exists before any payment attempt (contract step 1)."""
        now = time.time()
        self.conn.execute(
            "INSERT INTO invoices (merchant, invoice_id, amount, currency, memo, digest, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(merchant, invoice_id) DO NOTHING",
            (inv.merchant, inv.invoice_id, str(inv.amount), inv.currency, inv.memo, inv.digest(), now, now),
        )
        self.conn.commit()

    def digest_ok(self, inv: Invoice) -> bool:
        """True iff the presented invoice matches the terms pinned at first claim."""
        row = self.conn.execute(
            "SELECT digest FROM invoices WHERE merchant=? AND invoice_id=?",
            (inv.merchant, inv.invoice_id),
        ).fetchone()
        return row is not None and row[0] == inv.digest()

    def state(self, inv: Invoice) -> str | None:
        row = self.conn.execute(
            "SELECT state FROM invoices WHERE merchant=? AND invoice_id=?",
            (inv.merchant, inv.invoice_id),
        ).fetchone()
        return row[0] if row else None

    def try_begin_payment(self, inv: Invoice) -> bool:
        """Contract step 2: exactly one caller wins NEW/ASK_PENDING -> PAYING."""
        cur = self.conn.execute(
            "UPDATE invoices SET state='PAYING', updated_at=? "
            "WHERE merchant=? AND invoice_id=? AND state IN ('NEW','ASK_PENDING')",
            (time.time(), inv.merchant, inv.invoice_id),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def record_paid(self, inv: Invoice, receipt: dict) -> None:
        self.conn.execute(
            "UPDATE invoices SET state='PAID', receipt=?, updated_at=? "
            "WHERE merchant=? AND invoice_id=? AND state='PAYING'",
            (json.dumps(receipt), time.time(), inv.merchant, inv.invoice_id),
        )
        self.conn.commit()

    def mark(self, inv: Invoice, state: str, verdict: str | None = None) -> None:
        self.conn.execute(
            "UPDATE invoices SET state=?, verdict=COALESCE(?, verdict), updated_at=? "
            "WHERE merchant=? AND invoice_id=?",
            (state, verdict, time.time(), inv.merchant, inv.invoice_id),
        )
        self.conn.commit()

    def spent_this_week(self, currency: str) -> Decimal:
        cutoff = time.time() - 7 * 86400
        rows = self.conn.execute(
            "SELECT amount FROM invoices WHERE state='PAID' AND currency=? AND updated_at>=?",
            (currency, cutoff),
        ).fetchall()
        return sum((Decimal(r[0]) for r in rows), Decimal("0"))

    def receipt(self, inv: Invoice) -> dict | None:
        row = self.conn.execute(
            "SELECT receipt FROM invoices WHERE merchant=? AND invoice_id=?",
            (inv.merchant, inv.invoice_id),
        ).fetchone()
        return json.loads(row[0]) if row and row[0] else None

    def invoice_row(self, merchant: str, invoice_id: str) -> Invoice | None:
        row = self.conn.execute(
            "SELECT amount, currency, memo FROM invoices WHERE merchant=? AND invoice_id=?",
            (merchant, invoice_id),
        ).fetchone()
        if not row:
            return None
        return Invoice(
            invoice_id=invoice_id, merchant=merchant,
            amount=Decimal(row[0]), currency=row[1], memo=row[2],
        )

    # -- approvals ---------------------------------------------------------

    def record_decision(self, inv: Invoice, action: str, actor: str, note: str = "") -> tuple[bool, str]:
        """Terminal, atomic, race-safe. Returns (created, effective_action):
        created is True only for the single INSERT that won the (merchant,
        invoice_id) primary key; every loser - same action or conflicting -
        gets created=False plus the action that is actually stored. Callers
        MUST branch on effective_action, never on what they asked for.
        The decision is bound to the invoice digest at decision time."""
        try:
            self.conn.execute(
                "INSERT INTO approvals (merchant, invoice_id, action, actor, note, invoice_digest, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (inv.merchant, inv.invoice_id, action, actor, note, inv.digest(), time.time()),
            )
            self.conn.commit()
            return True, action
        except sqlite3.IntegrityError:
            stored = self.decision(inv)
            assert stored is not None  # the PK conflict proves the row exists
            return False, stored[0]

    def decision(self, inv: Invoice) -> tuple[str, str] | None:
        """Returns (action, invoice_digest) of the terminal decision, or None."""
        row = self.conn.execute(
            "SELECT action, invoice_digest FROM approvals WHERE merchant=? AND invoice_id=?",
            (inv.merchant, inv.invoice_id),
        ).fetchone()
        return (row[0], row[1]) if row else None

    def approved(self, inv: Invoice) -> bool:
        """True only for an APPROVED decision whose digest matches THIS invoice's
        terms - an approval given for different terms never authorizes payment."""
        d = self.decision(inv)
        return d is not None and d[0] == "APPROVED" and d[1] == inv.digest()

    # -- jobs ---------------------------------------------------------------

    def upsert_job(self, job_id: str, state: str, payload: dict, inv: Invoice | None = None, result: str | None = None) -> None:
        now = time.time()
        self.conn.execute(
            "INSERT INTO jobs (job_id, state, payload, merchant, invoice_id, result, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET"
            " state=excluded.state, payload=excluded.payload, merchant=excluded.merchant,"
            " invoice_id=excluded.invoice_id, result=excluded.result, updated_at=excluded.updated_at",
            (
                job_id, state, json.dumps(payload),
                inv.merchant if inv else None, inv.invoice_id if inv else None,
                result, now, now,
            ),
        )
        self.conn.commit()

    def job(self, job_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT job_id, state, payload, merchant, invoice_id, result FROM jobs WHERE job_id=?",
            (job_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "job_id": row[0], "state": row[1], "payload": json.loads(row[2]),
            "merchant": row[3], "invoice_id": row[4], "result": row[5],
        }

    def waiting_jobs(self, limit: int = 50, offset: int = 0) -> list[dict]:
        rows = self.conn.execute(
            "SELECT job_id FROM jobs WHERE state='WAITING_APPROVAL'"
            " ORDER BY created_at, job_id LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [self.job(r[0]) for r in rows]

    # -- API evidence events -------------------------------------------------

    def record_event(
        self, request_id: str, actor: str, action: str, outcome: str,
        job_id: str | None, merchant: str | None, invoice_id: str | None,
        invoice_digest: str | None, state_before: str | None, state_after: str | None,
    ) -> None:
        """Append-only audit row for every authenticated API action. The actor
        is the authenticated principal; credentials themselves are never stored."""
        self.conn.execute(
            "INSERT INTO api_events (request_id, actor, action, outcome, job_id, merchant,"
            " invoice_id, invoice_digest, state_before, state_after, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (request_id, actor, action, outcome, job_id, merchant,
             invoice_id, invoice_digest, state_before, state_after, time.time()),
        )
        self.conn.commit()

    def events(self, job_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT request_id, actor, action, outcome, invoice_digest, state_before, state_after"
            " FROM api_events WHERE job_id=? ORDER BY seq",
            (job_id,),
        ).fetchall()
        keys = ["request_id", "actor", "action", "outcome", "invoice_digest", "state_before", "state_after"]
        return [dict(zip(keys, r)) for r in rows]
