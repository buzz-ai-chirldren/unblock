"""The Clerk state machine: the part the official payment stack does not have.

run_job() drives one unit of work that hits a paywall:

  RUNNING -> (invoice) -> policy verdict
    ALLOW -> claim -> begin_payment (idempotent gate) -> rail.pay -> PAID -> DONE
    ASK   -> WAITING_APPROVAL (durable; survives restarts)
    DENY  -> FAILED

approve() records the human decision (idempotent). resume() re-runs the SAME
job with the SAME invoice: policy is bypassed only by the recorded approval,
and the ledger's PAYING/PAID states still guarantee at-most-once settlement.
"""

from __future__ import annotations

from .ledger import Ledger
from .policy import Decision, Invoice, Policy, evaluate
from .rails import PaymentRail, RailError


class Clerk:
    def __init__(self, ledger: Ledger, policy: Policy, rail: PaymentRail):
        self.ledger = ledger
        self.policy = policy
        self.rail = rail

    # -- core --------------------------------------------------------------

    def run_job(self, job_id: str, invoice: Invoice, work: str) -> str:
        """Returns the job's final state for this attempt."""
        self.ledger.upsert_job(job_id, "RUNNING", {"work": work}, invoice)
        self.ledger.claim(invoice)

        state = self.ledger.state(invoice)
        if state == "PAID":
            # Invoice already settled in an earlier run: finish the job, pay nothing.
            return self._finish(job_id, invoice, note="already-paid")
        if state == "PAYING":
            # Another run is mid-payment, or a crash left an unreconciled row.
            self.ledger.upsert_job(job_id, "WAITING_APPROVAL", {"work": work, "why": "reconcile PAYING"}, invoice)
            return "WAITING_APPROVAL"

        verdict = evaluate(invoice, self.policy, self.ledger.spent_this_week(self.policy.currency))
        if verdict.decision is Decision.DENY:
            self.ledger.mark(invoice, "DENIED", verdict.reason)
            self.ledger.upsert_job(job_id, "FAILED", {"work": work, "why": verdict.reason}, invoice)
            return "FAILED"
        if verdict.decision is Decision.ASK and not self.ledger.approved(invoice):
            self.ledger.mark(invoice, "ASK_PENDING", verdict.reason)
            self.ledger.upsert_job(job_id, "WAITING_APPROVAL", {"work": work, "why": verdict.reason}, invoice)
            return "WAITING_APPROVAL"

        return self._pay_and_finish(job_id, invoice, work)

    def approve(self, invoice: Invoice, actor: str, note: str = "") -> bool:
        """Record the human decision; duplicate approvals are no-ops (False)."""
        return self.ledger.record_approval(invoice, "APPROVED", actor, note)

    def resume(self, job_id: str) -> str:
        """Re-drive a WAITING_APPROVAL job after (or without) an approval."""
        job = self.ledger.job(job_id)
        if job is None:
            raise KeyError(job_id)
        if job["state"] == "DONE":
            return "DONE"
        inv_state_row = self.ledger.conn.execute(
            "SELECT amount, currency FROM invoices WHERE merchant=? AND invoice_id=?",
            (job["merchant"], job["invoice_id"]),
        ).fetchone()
        invoice = Invoice(
            invoice_id=job["invoice_id"], merchant=job["merchant"],
            amount=__import__("decimal").Decimal(inv_state_row[0]), currency=inv_state_row[1],
        )
        state = self.ledger.state(invoice)
        if state == "PAID":
            return self._finish(job_id, invoice, note="already-paid")
        if not self.ledger.approved(invoice):
            return "WAITING_APPROVAL"  # still parked; not an error
        return self._pay_and_finish(job_id, invoice, job["payload"].get("work", ""))

    # -- internals ----------------------------------------------------------

    def _pay_and_finish(self, job_id: str, invoice: Invoice, work: str) -> str:
        if not self.ledger.try_begin_payment(invoice):
            # Lost the race (concurrent run) or row in an unexpected state: park, never double-pay.
            self.ledger.upsert_job(job_id, "WAITING_APPROVAL", {"work": work, "why": "lost payment race"}, invoice)
            return "WAITING_APPROVAL"
        try:
            receipt = self.rail.pay(invoice)
        except RailError as e:
            # Rail refused before settlement: safe to retry later from ASK_PENDING.
            self.ledger.mark(invoice, "ASK_PENDING", f"rail error: {e}")
            self.ledger.upsert_job(job_id, "WAITING_APPROVAL", {"work": work, "why": str(e)}, invoice)
            return "WAITING_APPROVAL"
        self.ledger.record_paid(invoice, receipt)
        return self._finish(job_id, invoice, note=receipt.get("tx", ""))

    def _finish(self, job_id: str, invoice: Invoice, note: str) -> str:
        job = self.ledger.job(job_id)
        payload = job["payload"] if job else {}
        self.ledger.upsert_job(job_id, "DONE", payload, invoice, result=note)
        return "DONE"
