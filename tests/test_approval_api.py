"""Approval API against the Gate B threat model.

The rail's settlement count is the money oracle, same as the Gate A suite;
cross-process tests use FileRail so settlements are counted from the parent.
Properties under test: fail-closed auth with server-side actor resolution,
decisions keyed by job_id with terms read only from the pinned ledger row,
race-safe terminal decisions (the stored action is the only arbiter, proven
across real processes), decision + evidence persisted before resume with
crash recovery by re-sending the same decision (no resume endpoint exists),
strict schemas and boundary defense, and no secret ever leaving a response.
"""

import json
import multiprocessing
import os
import stat
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from clerk.approval_api import create_app  # noqa: E402
from clerk.jobs import Clerk  # noqa: E402
from clerk.ledger import Ledger  # noqa: E402
from clerk.policy import Invoice, Policy  # noqa: E402
from clerk.rails import FileRail, MockRail  # noqa: E402

POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("5.00"),
    per_invoice_cap=Decimal("1.00"),
    merchant_allowlist=frozenset({"api.example"}),
)

BIG = Invoice("inv-ask-1", "api.example", Decimal("2.00"), "USDC", memo="GET /premium")
SMALL = Invoice("inv-ok-1", "api.example", Decimal("0.05"), "USDC")
TOKENS = {"akiyuki": "owner-token", "auditor": "auditor-token"}
AUTH = {"Authorization": f"Bearer {TOKENS['akiyuki']}"}


@pytest.fixture
def env(tmp_path):
    """One shared rail (the money oracle) + a per-request clerk factory,
    exactly how the ASGI server uses it across worker threads."""
    db = tmp_path / "ledger.db"
    rail = MockRail()

    def factory():
        return Clerk(Ledger(db), POLICY, rail)

    client = TestClient(create_app(factory, tokens=TOKENS), raise_server_exceptions=False)
    return client, factory, rail


def park_job(factory, invoice=BIG, job_id="job-ask-1"):
    clerk = factory()
    try:
        assert clerk.run_job(job_id, invoice, "fetch premium") == "WAITING_APPROVAL"
    finally:
        clerk.ledger.close()


# -- auth is fail-closed, actor is the authenticated principal -----------------

def test_app_refuses_ambiguous_or_missing_auth_config(monkeypatch):
    monkeypatch.delenv("CLERK_APPROVAL_TOKENS", raising=False)
    bad_configs = [
        None,                                          # nothing configured
        {},                                            # empty map
        {"akiyuki": ""},                               # empty token
        {"": "tok"},                                   # empty actor name
        {"akiyuki": "same", "auditor": "same"},        # duplicate token = ambiguous principal
    ]
    for tokens in bad_configs:
        with pytest.raises(RuntimeError):
            create_app(lambda: None, tokens=tokens)


def test_all_routes_require_bearer_token(env):
    client, factory, _ = env
    park_job(factory)
    for attempt in ({}, {"Authorization": "Bearer wrong"}):
        assert client.get("/asks", headers=attempt).status_code == 401
        assert client.get("/approvals/job-ask-1", headers=attempt).status_code == 401
        assert client.post("/jobs/job-ask-1/decision", headers=attempt,
                           json={"action": "APPROVED"}).status_code == 401


def test_actor_comes_from_credential_not_body(env):
    client, factory, _ = env
    park_job(factory)
    # Body cannot carry an actor at all (strict schema)...
    r = client.post("/jobs/job-ask-1/decision", headers=AUTH,
                    json={"action": "APPROVED", "actor": "mallory"})
    assert r.status_code == 422
    # ...and the recorded actor is the principal behind the token used.
    r = client.post("/jobs/job-ask-1/decision",
                    headers={"Authorization": f"Bearer {TOKENS['auditor']}"},
                    json={"action": "REJECTED"})
    assert r.status_code == 200
    clerk = factory()
    try:
        row = clerk.ledger.conn.execute(
            "SELECT actor FROM approvals WHERE invoice_id=?", (BIG.invoice_id,)
        ).fetchone()
        assert row == ("auditor",)
        assert {e["actor"] for e in clerk.ledger.events("job-ask-1")} == {"auditor"}
    finally:
        clerk.ledger.close()


# -- the full human loop: list -> decide -> job completes ----------------------

def test_list_decide_completes_and_pays_once(env):
    client, factory, rail = env
    park_job(factory)

    asks = client.get("/asks", headers=AUTH).json()
    assert len(asks) == 1
    ask = asks[0]
    assert ask["job_id"] == "job-ask-1"
    assert (ask["merchant"], ask["invoice_id"]) == (BIG.merchant, BIG.invoice_id)
    assert ask["amount"] == "2.00"
    assert ask["digest"] == BIG.digest()  # terms served from the pinned row
    assert ask["decision"] is None

    r = client.post("/jobs/job-ask-1/decision", headers=AUTH,
                    json={"action": "APPROVED", "note": "ok for demo"})
    body = r.json()
    assert (body["decided"], body["action_in_effect"], body["state"]) == (True, "APPROVED", "DONE")
    assert rail.settled == ["api.example/inv-ask-1"]  # exactly one settlement
    assert client.get("/asks", headers=AUTH).json() == []  # queue drained

    detail = client.get("/approvals/job-ask-1", headers=AUTH).json()
    assert detail["job_state"] == "DONE" and detail["decision"] == "APPROVED"
    decision_event, resume_event = detail["events"]
    assert decision_event["actor"] == "akiyuki"
    assert (decision_event["action"], decision_event["outcome"]) == ("APPROVED", "recorded")
    assert decision_event["invoice_digest"] == BIG.digest()
    assert decision_event["state_before"] == "WAITING_APPROVAL/ASK_PENDING"
    assert (resume_event["action"], resume_event["outcome"]) == ("RESUME", "resumed")
    assert resume_event["state_after"] == "DONE/PAID"
    assert decision_event["request_id"] == body["request_id"]


def test_reject_ends_job_without_payment(env):
    client, factory, rail = env
    park_job(factory)
    r = client.post("/jobs/job-ask-1/decision", headers=AUTH,
                    json={"action": "REJECTED", "note": "not needed"})
    assert r.json()["state"] == "FAILED"
    assert rail.settled == []


# -- terminal decisions: idempotent resend, 409 on the opposite ----------------

def test_resend_is_idempotent_and_flip_is_conflict(env):
    client, factory, rail = env
    park_job(factory)
    first = client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "REJECTED"}).json()
    assert first["decided"] is True and first["state"] == "FAILED"

    resend = client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "REJECTED"}).json()
    assert resend["decided"] is False  # idempotent no-op, still 200
    assert resend["action_in_effect"] == "REJECTED"

    flip = client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "APPROVED"})
    assert flip.status_code == 409
    assert "REJECTED" in flip.json()["detail"]  # the stored decision, not the request's
    assert rail.settled == []

    clerk = factory()
    try:
        trail = [(e["action"], e["outcome"]) for e in clerk.ledger.events("job-ask-1")]
        assert trail == [
            ("REJECTED", "recorded"), ("RESUME", "resumed"),
            ("REJECTED", "idempotent-noop"), ("RESUME", "resumed"),
            ("APPROVED", "conflict:stored=REJECTED"),
        ]
    finally:
        clerk.ledger.close()


def test_first_decision_requires_waiting_job(env):
    client, factory, rail = env
    clerk = factory()
    try:
        assert clerk.run_job("job-done", SMALL, "auto-paid work") == "DONE"
    finally:
        clerk.ledger.close()
    r = client.post("/jobs/job-done/decision", headers=AUTH, json={"action": "REJECTED"})
    assert r.status_code == 409  # no after-the-fact decisions on settled work
    clerk = factory()
    try:
        assert clerk.ledger.decision(SMALL) is None  # nothing was recorded
        assert [e["outcome"] for e in clerk.ledger.events("job-done")] == ["refused-state"]
    finally:
        clerk.ledger.close()
    assert rail.settled == ["api.example/inv-ok-1"]  # unchanged


# -- real process race: the stored decision is the only arbiter ----------------

def _decision_worker(db, rail_db, job_id, action, results):
    def factory():
        return Clerk(Ledger(db), POLICY, FileRail(rail_db))

    client = TestClient(create_app(factory, tokens=TOKENS), raise_server_exceptions=False)
    r = client.post(f"/jobs/{job_id}/decision", headers=AUTH, json={"action": action})
    body = r.json() if r.status_code == 200 else {}
    results.append((action, r.status_code, body.get("action_in_effect"), body.get("state")))


def _spawn_deciders(db, rail_db, job_id, actions):
    mgr = multiprocessing.Manager()
    results = mgr.list()
    procs = [
        multiprocessing.Process(target=_decision_worker, args=(db, rail_db, job_id, a, results))
        for a in actions
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
    return list(results)


def test_process_race_approve_vs_reject_one_winner_loser_409(tmp_path):
    db, rail_db = str(tmp_path / "ledger.db"), str(tmp_path / "rail.db")
    park_job(lambda: Clerk(Ledger(db), POLICY, FileRail(rail_db)), job_id="job-race")

    results = _spawn_deciders(db, rail_db, "job-race", ["APPROVED", "REJECTED"])
    assert sorted(r[1] for r in results) == [200, 409]  # exactly one winner

    (winner,) = [r for r in results if r[1] == 200]
    assert winner[2] == winner[0]  # winner's stored action is its own
    settlements = FileRail(rail_db).settle_count(Invoice("inv-ask-1", "api.example", Decimal("2.00"), "USDC", memo="GET /premium"))
    assert settlements == (1 if winner[0] == "APPROVED" else 0)
    ledger = Ledger(db)
    stored = ledger.decision(ledger.invoice_row("api.example", "inv-ask-1"))
    ledger.close()
    assert stored[0] == winner[0]  # money followed the stored decision only


def test_process_race_same_approve_settles_once(tmp_path):
    db, rail_db = str(tmp_path / "ledger.db"), str(tmp_path / "rail.db")
    park_job(lambda: Clerk(Ledger(db), POLICY, FileRail(rail_db)), job_id="job-race")

    results = _spawn_deciders(db, rail_db, "job-race", ["APPROVED", "APPROVED"])
    assert [r[1] for r in results] == [200, 200]  # same action never conflicts
    states = {r[3] for r in results}
    assert "DONE" in states and states <= {"DONE", "WAITING_APPROVAL"}

    rail = FileRail(rail_db)
    invoice = Invoice("inv-ask-1", "api.example", Decimal("2.00"), "USDC", memo="GET /premium")
    assert rail.settle_count(invoice) == 1  # the merchant saw exactly one payment

    # A parked loser (lost the payment race) recovers by the same resend path.
    def factory():
        return Clerk(Ledger(db), POLICY, rail)
    client = TestClient(create_app(factory, tokens=TOKENS), raise_server_exceptions=False)
    r = client.post("/jobs/job-race/decision", headers=AUTH, json={"action": "APPROVED"})
    assert r.json()["state"] == "DONE"
    assert rail.settle_count(invoice) == 1


# -- real process crash between decision commit and resume ---------------------

class _CrashBeforeResumeClerk(Clerk):
    def resume(self, job_id):
        os._exit(17)  # decision + evidence are committed; resume never starts


def _crash_decider(db, rail_db):
    def factory():
        return _CrashBeforeResumeClerk(Ledger(db), POLICY, FileRail(rail_db))

    client = TestClient(create_app(factory, tokens=TOKENS), raise_server_exceptions=False)
    client.post("/jobs/job-crash/decision", headers=AUTH, json={"action": "APPROVED"})


def test_process_crash_after_decision_commit_recovers_by_resend(tmp_path):
    db, rail_db = str(tmp_path / "ledger.db"), str(tmp_path / "rail.db")
    park_job(lambda: Clerk(Ledger(db), POLICY, FileRail(rail_db)), job_id="job-crash")

    p = multiprocessing.Process(target=_crash_decider, args=(db, rail_db))
    p.start()
    p.join(timeout=60)
    assert p.exitcode == 17  # died exactly between decision commit and resume

    invoice = Invoice("inv-ask-1", "api.example", Decimal("2.00"), "USDC", memo="GET /premium")
    rail = FileRail(rail_db)
    ledger = Ledger(db)
    assert ledger.decision(invoice)[0] == "APPROVED"  # the decision survived
    assert [e["outcome"] for e in ledger.events("job-crash")] == ["recorded"]  # evidence too
    ledger.close()
    assert rail.settle_count(invoice) == 0  # and no money moved

    # Recovery = a NEW process re-sends the SAME decision over fresh connections.
    def factory():
        return Clerk(Ledger(db), POLICY, rail)
    client = TestClient(create_app(factory, tokens=TOKENS), raise_server_exceptions=False)
    r = client.post("/jobs/job-crash/decision", headers=AUTH, json={"action": "APPROVED"}).json()
    assert (r["decided"], r["state"]) == (False, "DONE")
    assert rail.settle_count(invoice) == 1  # paid exactly once, after recovery


def test_resume_failure_is_evidenced_and_recoverable(env, tmp_path):
    client, factory, rail = env

    failed = []

    class FailResumeOnce(Clerk):
        def resume(self, job_id):
            if not failed:
                failed.append(job_id)
                raise RuntimeError("transient resume failure")
            return super().resume(job_id)

    def flaky_factory():
        return FailResumeOnce(Ledger(tmp_path / "ledger.db"), POLICY, rail)

    flaky_client = TestClient(create_app(flaky_factory, tokens=TOKENS),
                              raise_server_exceptions=False)
    park_job(factory)

    r = flaky_client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "APPROVED"})
    assert r.status_code == 500
    assert "token" not in r.text and "RuntimeError" not in r.text  # no internals leak
    assert rail.settled == []

    clerk = factory()
    try:
        trail = [e["outcome"] for e in clerk.ledger.events("job-ask-1")]
        assert trail == ["recorded", "resume-failed:RuntimeError"]
    finally:
        clerk.ledger.close()

    # Same resend recovery path as a crash.
    r = flaky_client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "APPROVED"}).json()
    assert r["state"] == "DONE"
    assert rail.settled == ["api.example/inv-ask-1"]


# -- there is no resume surface -------------------------------------------------

def test_no_resume_endpoint_exists(env):
    client, factory, _ = env
    park_job(factory)
    assert client.post("/jobs/job-ask-1/resume", headers=AUTH).status_code in (404, 405)
    route_paths = {r.path for r in client.app.routes}
    assert not any("resume" in p for p in route_paths)


# -- API contract: pagination, detail, redaction, no secret in responses --------

def test_asks_pagination_is_bounded(env):
    client, factory, _ = env
    for i in range(3):
        park_job(factory, Invoice(f"inv-pg-{i}", "api.example", Decimal("2.00"), "USDC"),
                 job_id=f"job-pg-{i}")
    assert len(client.get("/asks", headers=AUTH).json()) == 3
    assert len(client.get("/asks?limit=2", headers=AUTH).json()) == 2
    page2 = client.get("/asks?limit=2&offset=2", headers=AUTH).json()
    assert len(page2) == 1
    assert client.get("/asks?limit=0", headers=AUTH).status_code == 422
    assert client.get("/asks?limit=201", headers=AUTH).status_code == 422
    assert client.get("/asks?offset=-1", headers=AUTH).status_code == 422


def test_responses_never_leak_memo_query_receipt_or_credentials(env):
    client, factory, rail = env
    secret_memo = Invoice("inv-sec-1", "api.example", Decimal("2.00"), "USDC",
                          memo="http://m.example/data?access_token=SECRET123")
    park_job(factory, secret_memo, job_id="job-sec-1")

    ask = client.get("/asks", headers=AUTH).json()[0]
    assert ask["memo"] == "http://m.example/data?[redacted]"
    assert ask["digest"] == secret_memo.digest()  # digest still binds the RAW terms

    client.post("/jobs/job-sec-1/decision", headers=AUTH, json={"action": "APPROVED"})
    tx = rail.receipts["api.example/inv-sec-1"]["tx"]

    for response_text in (
        json.dumps(client.get("/asks", headers=AUTH).json()),
        json.dumps(client.get("/approvals/job-sec-1", headers=AUTH).json()),
    ):
        assert "SECRET123" not in response_text        # memo query token
        assert tx not in response_text                 # receipt / provider response
        assert "receipt" not in response_text.lower()
        for token in TOKENS.values():
            assert token not in response_text          # credentials


# -- boundary defense ------------------------------------------------------------

def test_malformed_input_is_4xx_without_state_change(env):
    client, factory, _ = env
    park_job(factory)
    attempts = [
        dict(content=b'{"action": "APPROVED"', headers={**AUTH, "Content-Type": "application/json"}),
        dict(content=b"action=APPROVED", headers={**AUTH, "Content-Type": "text/plain"}),
        dict(json={"action": "APPROVED", "amount": "0.01"}, headers=AUTH),   # unknown field
        dict(json={"action": "APPROVED", "digest": "0" * 64}, headers=AUTH),  # unknown field
        dict(json={"action": "PAY"}, headers=AUTH),                           # invalid action
        dict(json={"action": "APPROVED", "note": "x" * 501}, headers=AUTH),   # note over cap
    ]
    for kwargs in attempts:
        r = client.post("/jobs/job-ask-1/decision", **kwargs)
        assert 400 <= r.status_code < 500
        for token in TOKENS.values():
            assert token not in r.text
    # No decision, no payment, still parked.
    clerk = factory()
    try:
        assert clerk.ledger.decision(BIG) is None
        assert clerk.ledger.job("job-ask-1")["state"] == "WAITING_APPROVAL"
    finally:
        clerk.ledger.close()


def test_oversized_body_is_413(env):
    client, factory, _ = env
    park_job(factory)
    r = client.post("/jobs/job-ask-1/decision", headers={**AUTH, "Content-Type": "application/json"},
                    content=b'{"note": "' + b"x" * (17 * 1024) + b'"}')
    assert r.status_code == 413


def test_unknown_job_is_404(env):
    client, _, _ = env
    assert client.post("/jobs/no-such-job/decision", headers=AUTH,
                       json={"action": "APPROVED"}).status_code == 404
    assert client.get("/approvals/no-such-job", headers=AUTH).status_code == 404


# -- ledger hardening -------------------------------------------------------------

def test_ledger_file_is_owner_only_with_integrity(tmp_path):
    db = tmp_path / "ledger.db"
    ledger = Ledger(db)
    try:
        assert stat.S_IMODE(os.stat(db).st_mode) == 0o600
        assert ledger.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert ledger.integrity_ok()
    finally:
        ledger.close()
