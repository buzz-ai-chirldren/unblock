"""Codex-requested Gate A hardening: true restart (fresh connections), crash
AFTER rail settlement, whole-process concurrency with an externally observable
rail, invoice substitution, and terminal approval decisions. FileRail's own
settlement table is the oracle: it is a different SQLite file from the clerk's
ledger, so a clerk crash cannot take the evidence down with it.
"""

import multiprocessing
import os
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from clerk.jobs import Clerk  # noqa: E402
from clerk.ledger import Ledger  # noqa: E402
from clerk.policy import Invoice, Policy  # noqa: E402
from clerk.rails import FileRail  # noqa: E402

POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("5.00"),
    per_invoice_cap=Decimal("1.00"),
    merchant_allowlist=frozenset({"api.example"}),
    merchant_blocklist=frozenset({"evil.example"}),
)

SMALL = Invoice("inv-001", "api.example", Decimal("0.05"), "USDC")
BIG = Invoice("inv-002", "api.example", Decimal("20.00"), "USDC")


# -- 1. restart: close every connection, reopen from disk, complete the flow --

def test_restart_with_fresh_connections_ask_approve_resume(tmp_path):
    db, rail_db = tmp_path / "ledger.db", tmp_path / "rail.db"

    ledger1 = Ledger(db)
    clerk1 = Clerk(ledger1, POLICY, FileRail(rail_db))
    assert clerk1.run_job("job-big", BIG, "renew domain") == "WAITING_APPROVAL"
    ledger1.close()  # process 1 is gone; nothing survives but the files

    ledger2 = Ledger(db)
    clerk2 = Clerk(ledger2, POLICY, FileRail(rail_db))
    assert clerk2.ledger.job("job-big")["state"] == "WAITING_APPROVAL"
    assert clerk2.resume("job-big") == "WAITING_APPROVAL"  # no decision yet
    assert clerk2.approve(BIG, actor="akiyuki") is True
    ledger2.close()  # restart again between approval and resume

    ledger3 = Ledger(db)
    rail3 = FileRail(rail_db)
    clerk3 = Clerk(ledger3, POLICY, rail3)
    assert clerk3.resume("job-big") == "DONE"
    assert rail3.settle_count(BIG) == 1
    assert clerk3.ledger.receipt(BIG)["tx"].startswith("file-")


# -- 2. crash AFTER settlement, BEFORE receipt record -> reconcile, no re-pay --

class CrashAfterSettleRail(FileRail):
    """Settles for real (durable row in the rail's own file), then dies before
    the clerk can record the receipt - the worst-case crash window."""

    def pay(self, invoice):
        super().pay(invoice)
        os._exit(17)


def _crash_worker(db: str, rail_db: str):
    clerk = Clerk(Ledger(db), POLICY, CrashAfterSettleRail(rail_db))
    clerk.run_job("job-crash", SMALL, "fetch premium data")  # never returns


def test_crash_after_settle_reconciles_without_repay(tmp_path):
    db, rail_db = str(tmp_path / "ledger.db"), str(tmp_path / "rail.db")
    p = multiprocessing.Process(target=_crash_worker, args=(db, rail_db))
    p.start()
    p.join(timeout=30)
    assert p.exitcode == 17  # died exactly in the window

    rail = FileRail(rail_db)
    ledger = Ledger(db)
    assert ledger.state(SMALL) == "PAYING"  # receipt was never recorded
    assert rail.settle_count(SMALL) == 1  # but the money moved exactly once

    # A retry run must NOT pay again - it parks for reconciliation.
    clerk = Clerk(ledger, POLICY, rail)
    assert clerk.run_job("job-retry", SMALL, "retry after crash") == "WAITING_APPROVAL"
    assert rail.settle_count(SMALL) == 1

    # Reconcile adopts the rail's settlement record: PAYING -> PAID, no new payment.
    assert clerk.reconcile("job-crash") == "DONE"
    assert rail.settle_count(SMALL) == 1
    receipt = ledger.receipt(SMALL)
    assert receipt["tx"] == rail.lookup(SMALL)["tx"]
    # And the parked retry job now completes from the recorded receipt.
    assert clerk.resume("job-retry") == "DONE"
    assert rail.settle_count(SMALL) == 1


# -- 3. two whole processes race the same job -> one external settlement -------

def _race_worker(db: str, rail_db: str, job_id: str, results):
    clerk = Clerk(Ledger(db), POLICY, FileRail(rail_db))
    results.append(clerk.run_job(job_id, SMALL, "race"))


def test_concurrent_full_run_single_settlement(tmp_path):
    db, rail_db = str(tmp_path / "ledger.db"), str(tmp_path / "rail.db")
    Ledger(db).close()  # create schema up front
    mgr = multiprocessing.Manager()
    results = mgr.list()
    procs = [
        multiprocessing.Process(target=_race_worker, args=(db, rail_db, f"job-{i}", results))
        for i in range(2)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)

    rail = FileRail(rail_db)
    assert rail.settle_count(SMALL) == 1  # the merchant saw exactly one payment
    assert len(results) == 2
    assert "DONE" in results  # someone finished the job
    assert set(results) <= {"DONE", "WAITING_APPROVAL"}  # loser parked, never double-paid


# -- 4. invoice substitution: same id, different terms -> blocked --------------

def test_substituted_invoice_is_never_paid(tmp_path):
    rail = FileRail(tmp_path / "rail.db")
    clerk = Clerk(Ledger(tmp_path / "ledger.db"), POLICY, rail)
    assert clerk.run_job("job-1", SMALL, "work") == "DONE"

    swapped = Invoice("inv-001", "api.example", Decimal("0.95"), "USDC")  # same id, new price
    assert clerk.run_job("job-2", swapped, "work") == "FAILED"
    assert rail.settle_count(SMALL) == 1  # original settlement only
    assert rail.settle_count(swapped) == 1  # same key: no second settlement


def test_approval_for_other_terms_authorizes_nothing(tmp_path):
    rail = FileRail(tmp_path / "rail.db")
    clerk = Clerk(Ledger(tmp_path / "ledger.db"), POLICY, rail)
    assert clerk.run_job("job-big", BIG, "renew domain") == "WAITING_APPROVAL"

    # Human "approves" while looking at different terms (price changed in flight).
    altered = Invoice("inv-002", "api.example", Decimal("40.00"), "USDC")
    assert clerk.approve(altered, actor="akiyuki") is True

    # The ledger's pinned terms don't match the approved digest: still parked.
    assert clerk.resume("job-big") == "WAITING_APPROVAL"
    assert rail.settle_count(BIG) == 0

    # No second decision is possible for this invoice_id (terminal): a new
    # invoice_id is the only path forward.
    assert clerk.approve(BIG, actor="akiyuki") is False
    assert clerk.resume("job-big") == "WAITING_APPROVAL"
    assert rail.settle_count(BIG) == 0


# -- 5. approval decisions are terminal ----------------------------------------

def test_decision_is_terminal_approve_then_reject(tmp_path):
    rail = FileRail(tmp_path / "rail.db")
    clerk = Clerk(Ledger(tmp_path / "ledger.db"), POLICY, rail)
    assert clerk.run_job("job-big", BIG, "work") == "WAITING_APPROVAL"

    assert clerk.approve(BIG, actor="akiyuki") is True
    assert clerk.reject(BIG, actor="akiyuki") is False  # cannot flip a terminal decision
    assert clerk.ledger.decision(BIG)[0] == "APPROVED"
    assert clerk.resume("job-big") == "DONE"
    assert rail.settle_count(BIG) == 1


def test_decision_is_terminal_reject_then_approve(tmp_path):
    rail = FileRail(tmp_path / "rail.db")
    clerk = Clerk(Ledger(tmp_path / "ledger.db"), POLICY, rail)
    assert clerk.run_job("job-big", BIG, "work") == "WAITING_APPROVAL"

    assert clerk.reject(BIG, actor="akiyuki", note="too expensive") is True
    assert clerk.approve(BIG, actor="akiyuki") is False  # cannot flip a terminal decision
    assert clerk.resume("job-big") == "FAILED"
    assert clerk.ledger.state(BIG) == "DENIED"
    assert rail.settle_count(BIG) == 0


# -- 6. settlement-uncertain rail failure: stay PAYING, reconcile only ---------

class UncertainThenLookupRail(FileRail):
    """First pay() dies with SettlementUncertain AFTER settling (worst case:
    the settle response was lost); lookup() later finds the settlement."""

    def pay(self, invoice):
        from clerk.rails import SettlementUncertain
        super().pay(invoice)  # money moved
        raise SettlementUncertain("settle response lost")


def test_settlement_uncertain_stays_paying_then_reconciles(tmp_path):
    rail = UncertainThenLookupRail(tmp_path / "rail.db")
    clerk = Clerk(Ledger(tmp_path / "ledger.db"), POLICY, rail)
    assert clerk.run_job("job-u", SMALL, "work") == "WAITING_APPROVAL"
    assert clerk.ledger.state(SMALL) == "PAYING"  # not ASK_PENDING: no retry path
    assert rail.settle_count(SMALL) == 1

    # A rerun must not pay again.
    assert clerk.run_job("job-u2", SMALL, "retry") == "WAITING_APPROVAL"
    assert rail.settle_count(SMALL) == 1

    # resume() on a PAYING row routes through reconcile: adopts the settlement.
    assert clerk.resume("job-u") == "DONE"
    assert clerk.ledger.state(SMALL) == "PAID"
    assert rail.settle_count(SMALL) == 1
