"""Gate A mechanics on the mock rail: policy verdicts, durable ASK -> approve ->
resume, at-most-once settlement under sequential re-runs, concurrent double
execution, and restart-during-approval. Rail settlement counts are the oracle:
every test asserts how many times money actually moved.
"""

import multiprocessing
import sqlite3
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from unblock import Unblock  # noqa: E402
from unblock import Ledger  # noqa: E402
from unblock.policy import Decision, Invoice, Policy, evaluate  # noqa: E402
from unblock.rails import MockRail  # noqa: E402

POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("5.00"),
    per_invoice_cap=Decimal("1.00"),
    merchant_allowlist=frozenset({"api.example"}),
    merchant_blocklist=frozenset({"evil.example"}),
)

SMALL = Invoice("inv-001", "api.example", Decimal("0.05"), "USDC")
BIG = Invoice("inv-002", "api.example", Decimal("20.00"), "USDC")
UNKNOWN = Invoice("inv-003", "stranger.example", Decimal("0.05"), "USDC")


def make_unblock(tmp_path, rail=None):
    rail = rail or MockRail()
    return Unblock(Ledger(tmp_path / "ledger.db"), POLICY, rail), rail


# -- policy is deterministic and pure ----------------------------------------

def test_policy_verdicts():
    assert evaluate(SMALL, POLICY, Decimal("0")).decision is Decision.ALLOW
    assert evaluate(BIG, POLICY, Decimal("0")).decision is Decision.ASK
    assert evaluate(UNKNOWN, POLICY, Decimal("0")).decision is Decision.ASK
    assert evaluate(SMALL, POLICY, Decimal("4.99")).decision is Decision.ASK  # allowance exhausted
    bad = Invoice("x", "evil.example", Decimal("0.01"), "USDC")
    assert evaluate(bad, POLICY, Decimal("0")).decision is Decision.DENY


# -- ALLOW path: pay once, job completes -------------------------------------

def test_allow_pays_once_and_completes(tmp_path):
    unblock, rail = make_unblock(tmp_path)
    assert unblock.run_job("job-1", SMALL, "fetch premium data") == "DONE"
    assert rail.settled == ["api.example/inv-001"]
    assert unblock.ledger.receipt(SMALL)["tx"].startswith("mock-")


# -- idempotency: sequential re-run never pays twice ---------------------------

def test_rerun_same_invoice_is_noop(tmp_path):
    unblock, rail = make_unblock(tmp_path)
    assert unblock.run_job("job-1", SMALL, "work") == "DONE"
    assert unblock.run_job("job-2", SMALL, "same invoice, new job") == "DONE"
    assert rail.settled == ["api.example/inv-001"]  # exactly one settlement


# -- ASK path: durable wait -> approve -> resume same job ----------------------

def test_ask_approve_resume(tmp_path):
    unblock, rail = make_unblock(tmp_path)
    assert unblock.run_job("job-big", BIG, "renew domain") == "WAITING_APPROVAL"
    assert rail.settled == []  # nothing moved
    # restart: a fresh Unblock over the same ledger file still sees the parked job
    unblock2, rail2 = Unblock(unblock.ledger, POLICY, rail), rail
    assert unblock2.ledger.job("job-big")["state"] == "WAITING_APPROVAL"
    assert unblock2.resume("job-big") == "WAITING_APPROVAL"  # no approval yet: stays parked
    assert unblock2.approve(BIG, actor="akiyuki") is True
    assert unblock2.approve(BIG, actor="akiyuki") is False  # duplicate approval is a no-op
    assert unblock2.resume("job-big") == "DONE"
    assert rail.settled == ["api.example/inv-002"]
    assert unblock2.resume("job-big") == "DONE"  # resuming a done job is safe
    assert rail.settled == ["api.example/inv-002"]


# -- crash window: PAYING row is never auto re-paid ---------------------------

def test_paying_state_is_not_repaid(tmp_path):
    unblock, rail = make_unblock(tmp_path)
    unblock.ledger.claim(SMALL)
    assert unblock.ledger.try_begin_payment(SMALL) is True  # simulate crash right here
    assert unblock.run_job("job-after-crash", SMALL, "retry after crash") == "WAITING_APPROVAL"
    assert rail.settled == []  # reconciliation is a human/verifier step, never an auto re-pay


# -- concurrency: two processes, same invoice, one settlement ------------------

def _concurrent_worker(db_path: str, results):
    ledger = Ledger(db_path)
    inv = Invoice("inv-c", "api.example", Decimal("0.05"), "USDC")
    ledger.claim(inv)
    results.append(ledger.try_begin_payment(inv))


def test_concurrent_begin_payment_single_winner(tmp_path):
    db = str(tmp_path / "ledger.db")
    Ledger(db)  # create schema
    mgr = multiprocessing.Manager()
    results = mgr.list()
    procs = [
        multiprocessing.Process(target=_concurrent_worker, args=(db, results)) for _ in range(2)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=15)
    assert sorted(results) == [False, True]  # exactly one winner
    row = sqlite3.connect(db).execute("SELECT state FROM invoices").fetchone()
    assert row[0] == "PAYING"
