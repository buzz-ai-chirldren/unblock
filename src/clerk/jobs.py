"""The Clerk state machine: the part the official payment stack does not have.

run_job() drives one unit of work that hits a paywall:

  RUNNING -> (invoice) -> policy verdict
    ALLOW -> claim -> begin_payment (idempotent gate) -> rail.pay -> PAID -> DONE
    ASK   -> WAITING_APPROVAL (durable; survives restarts)
    DENY  -> FAILED

Invoice substitution: the ledger pins the invoice digest at first claim. A
later invoice reusing the same (merchant, invoice_id) with different
amount/currency/memo fails the digest check and the job FAILs before any
payment path is reachable.

approve()/reject() record the terminal human decision (first one wins; later
calls are no-ops). resume() re-runs the SAME job with the invoice terms read
back from the ledger: an APPROVED decision authorizes payment only if its
digest matches those terms, a REJECTED decision ends the job, and the ledger's
PAYING/PAID states still guarantee at-most-once settlement.

reconcile() handles the crash window (rail settled, receipt not recorded): it
adopts the rail's own settlement record for a PAYING row - never pays again -
and leaves the row PAYING for a human if the rail has no record either.
"""

from __future__ import annotations

from .ledger import Ledger
from .policy import Decision, Invoice, Policy, evaluate
from .rails import PaymentRail, RailError, SettlementUncertain


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

        if not self.ledger.digest_ok(invoice):
            # Same (merchant, invoice_id), different terms: substitution. Never payable.
            self.ledger.upsert_job(
                job_id, "FAILED",
                {"work": work, "why": "invoice terms differ from first-claimed digest"},
                invoice,
            )
            return "FAILED"

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
            decision = self.ledger.decision(invoice)
            if decision is not None and decision[0] == "REJECTED":
                self.ledger.mark(invoice, "DENIED", "rejected by human decision")
                self.ledger.upsert_job(job_id, "FAILED", {"work": work, "why": "rejected"}, invoice)
                return "FAILED"
            self.ledger.mark(invoice, "ASK_PENDING", verdict.reason)
            self.ledger.upsert_job(job_id, "WAITING_APPROVAL", {"work": work, "why": verdict.reason}, invoice)
            return "WAITING_APPROVAL"

        return self._pay_and_finish(job_id, invoice, work)

    def approve(self, invoice: Invoice, actor: str, note: str = "") -> bool:
        """Record the terminal APPROVED decision; any later call is a no-op (False)."""
        return self.ledger.record_decision(invoice, "APPROVED", actor, note)

    def reject(self, invoice: Invoice, actor: str, note: str = "") -> bool:
        """Record the terminal REJECTED decision; any later call is a no-op (False)."""
        return self.ledger.record_decision(invoice, "REJECTED", actor, note)

    def resume(self, job_id: str) -> str:
        """Re-drive a WAITING_APPROVAL job after (or without) a decision."""
        job = self.ledger.job(job_id)
        if job is None:
            raise KeyError(job_id)
        if job["state"] == "DONE":
            return "DONE"
        # Rebuild the invoice from the ledger's pinned terms, never from caller input.
        invoice = self.ledger.invoice_row(job["merchant"], job["invoice_id"])
        if invoice is None:
            raise KeyError(f"no invoice row for job {job_id}")
        state = self.ledger.state(invoice)
        if state == "PAID":
            return self._finish(job_id, invoice, note="already-paid")
        if state == "PAYING":
            return self.reconcile(job_id)
        decision = self.ledger.decision(invoice)
        if decision is None:
            return "WAITING_APPROVAL"  # still parked; not an error
        action, digest = decision
        if action == "REJECTED":
            self.ledger.mark(invoice, "DENIED", "rejected by human decision")
            self.ledger.upsert_job(job_id, "FAILED", {**job["payload"], "why": "rejected"}, invoice)
            return "FAILED"
        if digest != invoice.digest():
            # Approval was given for different terms; it authorizes nothing.
            self.ledger.upsert_job(
                job_id, "WAITING_APPROVAL",
                {**job["payload"], "why": "approval digest mismatch; new decision required"},
                invoice,
            )
            return "WAITING_APPROVAL"
        return self._pay_and_finish(job_id, invoice, job["payload"].get("work", ""))

    def reconcile(self, job_id: str) -> str:
        """Crash-window recovery for a PAYING row: adopt the rail's settlement
        record if one exists (no new payment); otherwise leave the row PAYING
        for a human/verifier - never auto re-pay."""
        job = self.ledger.job(job_id)
        if job is None:
            raise KeyError(job_id)
        invoice = self.ledger.invoice_row(job["merchant"], job["invoice_id"])
        if invoice is None:
            raise KeyError(f"no invoice row for job {job_id}")
        if self.ledger.state(invoice) != "PAYING":
            return job["state"]
        settlement = self.rail.lookup(invoice)
        if settlement is None:
            return "WAITING_APPROVAL"  # unresolved: rail shows no settlement; human decides
        self.ledger.record_paid(invoice, settlement)
        return self._finish(job_id, invoice, note=settlement.get("tx", ""))

    # -- internals ----------------------------------------------------------

    def _pay_and_finish(self, job_id: str, invoice: Invoice, work: str) -> str:
        if not self.ledger.try_begin_payment(invoice):
            # Lost the race (concurrent run) or row in an unexpected state: park, never double-pay.
            self.ledger.upsert_job(job_id, "WAITING_APPROVAL", {"work": work, "why": "lost payment race"}, invoice)
            return "WAITING_APPROVAL"
        try:
            receipt = self.rail.pay(invoice)
        except RailError as e:
            # Rail refused BEFORE anything was signed: safe to retry later from ASK_PENDING.
            self.ledger.mark(invoice, "ASK_PENDING", f"rail error: {e}")
            self.ledger.upsert_job(job_id, "WAITING_APPROVAL", {"work": work, "why": str(e)}, invoice)
            return "WAITING_APPROVAL"
        except SettlementUncertain as e:
            # An authorization may be in flight: the row STAYS PAYING and only
            # reconcile() (rail's own settlement lookup) can move it. No retry.
            self.ledger.upsert_job(
                job_id, "WAITING_APPROVAL",
                {"work": work, "why": f"settlement uncertain: {e}; reconcile required"},
                invoice,
            )
            return "WAITING_APPROVAL"
        self.ledger.record_paid(invoice, receipt)
        return self._finish(job_id, invoice, note=receipt.get("tx", ""))

    def _finish(self, job_id: str, invoice: Invoice, note: str) -> str:
        job = self.ledger.job(job_id)
        payload = job["payload"] if job else {}
        self.ledger.upsert_job(job_id, "DONE", payload, invoice, result=note)
        return "DONE"
