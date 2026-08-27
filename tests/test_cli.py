"""The `unblock` command line, which is a public entry point.

It shipped with 77 lines and no tests, caught in review. Everything here runs
offline: no network, no wallet, no rail.
"""

import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from unblock import Invoice, Ledger  # noqa: E402
from unblock.cli import main  # noqa: E402

MERCHANT = "threat-intel.example"


def run(capsys, argv):
    """The CLI's two answers: what it printed, and what it exited with."""
    code = main(argv)
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip() else None)


# -- check ------------------------------------------------------------------

@pytest.mark.parametrize("extra,decision,exit_code", [
    ([], "ALLOW", 0),
    (["--amount", "0.50"], "ASK", 0),                     # over the per-request cap
    (["--spent-this-week", "0.99"], "ASK", 0),            # over the weekly budget
    (["--merchant", "stranger.example"], "ASK", 0),       # not allowlisted
    (["--block", MERCHANT], "DENY", 2),                   # blocklisted
    (["--amount", "0"], "DENY", 2),                       # non-positive
    (["--amount", "-1"], "DENY", 2),
])
def test_check_reports_the_verdict_and_says_so_in_its_exit_code(
        capsys, extra, decision, exit_code):
    """ASK exits 0 on purpose: being stopped for a human is the product
    working, not a failure, and a script that treats it as one would page
    somebody every time the policy did its job. Only DENY is non-zero."""
    code, body = run(capsys, ["check", "--merchant", MERCHANT, "--amount", "0.05",
                              "--per-request-cap", "0.10", "--weekly-budget", "1.00",
                              "--allow", MERCHANT] + extra)
    assert body["decision"] == decision, body
    assert code == exit_code
    assert body["reason"]


def test_check_agrees_with_the_policy_it_claims_to_report(capsys):
    """The CLI must not grow its own opinion: the verdict has to be the one
    `evaluate` gives for the same inputs, reason string included."""
    from unblock import Policy, evaluate

    _, body = run(capsys, ["check", "--merchant", MERCHANT, "--amount", "0.50",
                           "--per-request-cap", "0.10", "--weekly-budget", "1.00",
                           "--allow", MERCHANT])
    verdict = evaluate(
        Invoice("cli", MERCHANT, Decimal("0.50"), "USDC"),
        Policy(currency="USDC", per_invoice_cap=Decimal("0.10"),
               weekly_allowance=Decimal("1.00"),
               merchant_allowlist=frozenset({MERCHANT})),
        Decimal("0"),
    )
    assert body == {"decision": verdict.decision.value, "reason": verdict.reason}


def test_a_blocklisted_merchant_is_denied_even_when_also_allowlisted(capsys):
    """Both lists naming the same merchant is a misconfiguration, and the safe
    reading of it is no."""
    code, body = run(capsys, ["check", "--merchant", MERCHANT, "--amount", "0.01",
                              "--allow", MERCHANT, "--block", MERCHANT])
    assert (body["decision"], code) == ("DENY", 2)


def test_an_amount_that_is_not_a_number_is_a_usage_error_not_a_verdict(capsys):
    """It must not fall through to a decision, and it must not print JSON --
    that is what separates it from DENY, which shares exit code 2."""
    with pytest.raises(SystemExit) as exit_info:
        main(["check", "--merchant", MERCHANT, "--amount", "not-a-number", "--allow", MERCHANT])
    assert exit_info.value.code == 2
    assert capsys.readouterr().out == ""


# -- jobs -------------------------------------------------------------------

@pytest.fixture
def ledger_with_jobs(tmp_path):
    db = tmp_path / "spend.db"
    ledger = Ledger(db)
    for job_id, state, amount in [("job-done", "DONE", "0.05"),
                                  ("job-parked", "WAITING_APPROVAL", "0.50"),
                                  ("job-failed", "FAILED", "0.50"),
                                  ("job-parked-2", "WAITING_APPROVAL", "0.70")]:
        ledger.upsert_job(job_id, state, {"work": "fetch intel"},
                          Invoice(f"inv-{job_id}", MERCHANT, Decimal(amount), "USDC"))
    ledger.conn.commit()
    ledger.close()
    return db


def test_jobs_lists_every_job_newest_first(capsys, ledger_with_jobs):
    code, rows = run(capsys, ["jobs", str(ledger_with_jobs)])
    assert code == 0
    assert [r["job_id"] for r in rows] == ["job-parked-2", "job-failed", "job-parked", "job-done"]
    assert {r["merchant"] for r in rows} == {MERCHANT}


def test_jobs_waiting_shows_only_what_a_human_still_owes_a_decision(capsys, ledger_with_jobs):
    code, rows = run(capsys, ["jobs", str(ledger_with_jobs), "--waiting"])
    assert code == 0
    assert sorted(r["job_id"] for r in rows) == ["job-parked", "job-parked-2"]
    assert {r["state"] for r in rows} == {"WAITING_APPROVAL"}


@pytest.mark.parametrize("blow_up", [False, True])
def test_jobs_closes_the_ledger_it_opened(capsys, monkeypatch, ledger_with_jobs, blow_up):
    """The command reads a database it does not own, so it has to hand the
    handle back -- including when printing the rows fails halfway.

    Re-opening the file proves nothing here: SQLite is happy to give a second
    connection to a database the first one is still holding, so a test written
    that way passes whether or not `close` was ever called. Watch the call."""
    closed = []
    original = Ledger.close
    monkeypatch.setattr(Ledger, "close", lambda self: (closed.append(1), original(self))[1])
    if blow_up:
        monkeypatch.setattr("unblock.cli.json.dumps",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        with pytest.raises(RuntimeError):
            main(["jobs", str(ledger_with_jobs)])
    else:
        assert main(["jobs", str(ledger_with_jobs)]) == 0
    assert closed == [1]


# -- the installed console script -------------------------------------------

def test_the_console_script_reaches_the_same_main():
    """`unblock` is what the README tells people to type, and pyproject is the
    only thing that connects that word to this code. Reading the toml would not
    prove the entry point resolves, so this runs the installed script."""
    result = subprocess.run(
        ["uv", "run", "unblock", "check", "--merchant", MERCHANT,
         "--amount", "0.50", "--allow", MERCHANT],
        cwd=REPO, capture_output=True, text=True, timeout=180,
        env={**os.environ, "UV_NO_SYNC": "1"},
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["decision"] == "ASK"


def test_the_console_script_carries_the_deny_exit_code_out_to_the_shell():
    result = subprocess.run(
        ["uv", "run", "unblock", "check", "--merchant", MERCHANT,
         "--amount", "0.01", "--allow", MERCHANT, "--block", MERCHANT],
        cwd=REPO, capture_output=True, text=True, timeout=180,
        env={**os.environ, "UV_NO_SYNC": "1"},
    )
    assert result.returncode == 2, result.stderr
    assert json.loads(result.stdout)["decision"] == "DENY"
