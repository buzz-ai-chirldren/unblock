"""Payment rails behind one interface so the state machine never cares which
rail moved the money. MockRail proves the mechanics (Gate A provisional);
X402Rail (Base Sepolia) provides the real settlement; an AgentCore Payments
adapter can slot in later without touching policy/ledger/jobs.
"""

from __future__ import annotations

import time
import uuid
from typing import Protocol

from .policy import Invoice


class PaymentRail(Protocol):
    name: str

    def pay(self, invoice: Invoice) -> dict:
        """Settle the invoice; return a receipt dict. Raise RailError on failure."""
        ...


class RailError(RuntimeError):
    pass


class MockRail:
    """In-memory settlement for tests and Gate-A-provisional runs.

    Counts every settle call so tests can assert the rail was hit exactly once
    per invoice regardless of how many times the job was retried.
    """

    name = "mock"

    def __init__(self, fail_times: int = 0):
        self.settled: list[str] = []
        self._fail_times = fail_times

    def pay(self, invoice: Invoice) -> dict:
        if self._fail_times > 0:
            self._fail_times -= 1
            raise RailError("mock rail transient failure")
        key = f"{invoice.merchant}/{invoice.invoice_id}"
        self.settled.append(key)
        return {
            "rail": self.name,
            "network": "mock",
            "facilitator": "none",
            "tx": f"mock-{uuid.uuid4().hex[:12]}",
            "amount": str(invoice.amount),
            "currency": invoice.currency,
            "settled_at": time.time(),
        }
