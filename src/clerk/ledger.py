"""Evidence ledger: one SQLite file holding invoices, payments, approvals, jobs.

Idempotency contract (the double-pay defence, in order):
  1. An invoice row is claimed with INSERT ... ON CONFLICT DO NOTHING on the
     UNIQUE (merchant, invoice_id) key BEFORE any rail is called.
  2. The claim moves atomically NEW -> PAYING via a conditional UPDATE; only the
     process that wins that UPDATE may talk to the rail. A concurrent second
     run loses the UPDATE and must back off.
  3. After the rail settles, the row records the receipt and becomes PAID
     (terminal). Re-running the same invoice afterwards is a no-op.

Crash window: if the process dies after the rail settled but before step 3
committed, the row is left PAYING. Recovery policy (documented, deliberate):
a PAYING row is never re-paid automatically - `recover` surfaces it with the
rail's own transaction lookup so a human (or a verifier job) reconciles it.
Losing a receipt is recoverable; paying twice is not.
"""

from __future__ import annotations

import json
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
  state      TEXT NOT NULL DEFAULT 'NEW',  -- NEW | PAYING | PAID | ASK_PENDING | DENIED
  verdict    TEXT,
  receipt    TEXT,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  PRIMARY KEY (merchant, invoice_id)
);
CREATE TABLE IF NOT EXISTS approvals (
  merchant   TEXT NOT NULL,
  invoice_id TEXT NOT NULL,
  action     TEXT NOT NULL,               -- APPROVED | REJECTED
  actor      TEXT NOT NULL,
  note       TEXT,
  created_at REAL NOT NULL,
  PRIMARY KEY (merchant, invoice_id, action)
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
"""


class Ledger:
    def __init__(self, path: str | Path):
        self.conn = sqlite3.connect(str(path), timeout=10)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- invoice lifecycle -------------------------------------------------

    def claim(self, inv: Invoice) -> None:
        """Ensure the unique row exists before any payment attempt (contract step 1)."""
        now = time.time()
        self.conn.execute(
            "INSERT INTO invoices (merchant, invoice_id, amount, currency, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?) ON CONFLICT(merchant, invoice_id) DO NOTHING",
            (inv.merchant, inv.invoice_id, str(inv.amount), inv.currency, now, now),
        )
        self.conn.commit()

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

    # -- approvals ---------------------------------------------------------

    def record_approval(self, inv: Invoice, action: str, actor: str, note: str = "") -> bool:
        """Idempotent: the PRIMARY KEY makes a duplicate approval a no-op (returns False)."""
        try:
            self.conn.execute(
                "INSERT INTO approvals (merchant, invoice_id, action, actor, note, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (inv.merchant, inv.invoice_id, action, actor, note, time.time()),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def approved(self, inv: Invoice) -> bool:
        return (
            self.conn.execute(
                "SELECT 1 FROM approvals WHERE merchant=? AND invoice_id=? AND action='APPROVED'",
                (inv.merchant, inv.invoice_id),
            ).fetchone()
            is not None
        )

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

    def waiting_jobs(self) -> list[dict]:
        rows = self.conn.execute("SELECT job_id FROM jobs WHERE state='WAITING_APPROVAL'").fetchall()
        return [self.job(r[0]) for r in rows]
