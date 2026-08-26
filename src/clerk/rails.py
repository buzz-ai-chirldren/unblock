"""Payment rails behind one interface so the state machine never cares which
rail moved the money. MockRail proves the mechanics (Gate A provisional);
FileRail persists settlements to its own SQLite file so crash/concurrency tests
can observe, from outside the clerk process, exactly how many times money moved;
X402Rail (Base Sepolia) provides the real settlement; an AgentCore Payments
adapter can slot in later without touching policy/ledger/jobs.

Every rail exposes `lookup(invoice)`: the rail's own settlement query, used by
reconciliation to adopt a receipt for a PAYING row without paying again.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Protocol

from .policy import Invoice


class PaymentRail(Protocol):
    name: str

    def pay(self, invoice: Invoice) -> dict:
        """Settle the invoice; return a receipt dict. Raise RailError on failure."""
        ...

    def lookup(self, invoice: Invoice) -> dict | None:
        """Return the rail's settlement record for this invoice, or None."""
        ...


class RailError(RuntimeError):
    pass


def _receipt(rail_name: str, network: str, facilitator: str, invoice: Invoice, tx: str) -> dict:
    return {
        "rail": rail_name,
        "network": network,
        "facilitator": facilitator,
        "tx": tx,
        "amount": str(invoice.amount),
        "currency": invoice.currency,
        "settled_at": time.time(),
    }


def _key(invoice: Invoice) -> str:
    return f"{invoice.merchant}/{invoice.invoice_id}"


class MockRail:
    """In-memory settlement for single-process tests.

    Counts every settle call so tests can assert the rail was hit exactly once
    per invoice regardless of how many times the job was retried.
    """

    name = "mock"

    def __init__(self, fail_times: int = 0):
        self.settled: list[str] = []
        self.receipts: dict[str, dict] = {}
        self._fail_times = fail_times

    def pay(self, invoice: Invoice) -> dict:
        if self._fail_times > 0:
            self._fail_times -= 1
            raise RailError("mock rail transient failure")
        key = _key(invoice)
        receipt = _receipt(self.name, "mock", "none", invoice, f"mock-{uuid.uuid4().hex[:12]}")
        self.settled.append(key)
        self.receipts[key] = receipt
        return receipt

    def lookup(self, invoice: Invoice) -> dict | None:
        return self.receipts.get(_key(invoice))


class FileRail:
    """Mock rail whose settlements live in their own SQLite file, independent of
    the clerk's ledger. This is the external observer for the hard tests: kill
    the clerk between settle and receipt-record, or race two whole processes,
    then count settlement rows from the parent process."""

    name = "filemock"

    def __init__(self, path: str | Path):
        self.path = str(path)
        conn = self._conn()
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS settlements ("
            " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
            " key TEXT NOT NULL,"
            " receipt TEXT NOT NULL,"
            " settled_at REAL NOT NULL)"
        )
        conn.commit()
        return conn

    def pay(self, invoice: Invoice) -> dict:
        receipt = _receipt(self.name, "filemock", "none", invoice, f"file-{uuid.uuid4().hex[:12]}")
        conn = self._conn()
        conn.execute(
            "INSERT INTO settlements (key, receipt, settled_at) VALUES (?,?,?)",
            (_key(invoice), json.dumps(receipt), time.time()),
        )
        conn.commit()
        conn.close()
        return receipt

    def lookup(self, invoice: Invoice) -> dict | None:
        conn = self._conn()
        row = conn.execute(
            "SELECT receipt FROM settlements WHERE key=? ORDER BY seq LIMIT 1",
            (_key(invoice),),
        ).fetchone()
        conn.close()
        return json.loads(row[0]) if row else None

    def settle_count(self, invoice: Invoice) -> int:
        conn = self._conn()
        n = conn.execute(
            "SELECT COUNT(*) FROM settlements WHERE key=?", (_key(invoice),)
        ).fetchone()[0]
        conn.close()
        return n
