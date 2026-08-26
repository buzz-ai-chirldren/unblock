"""Approval API against the Gate B threat model.

The rail's settlement count is the money oracle, same as the Gate A suite.
Properties under test: fail-closed auth with server-side actor resolution,
decisions keyed by job_id with terms read only from the pinned ledger row,
terminal decisions (idempotent resend / 409 on the opposite action),
decision persisted before resume (crash between the two recovers without a
double payment), no free-form resume, strict schemas, and evidence events.
"""

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
from clerk.rails import MockRail  # noqa: E402

POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("5.00"),
    per_invoice_cap=Decimal("1.00"),
    merchant_allowlist=frozenset({"api.example"}),
)

BIG = Invoice("inv-ask-1", "api.example", Decimal("2.00"), "USDC", memo="GET /premium")
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


def park_big_job(factory, job_id="job-ask-1"):
    clerk = factory()
    try:
        assert clerk.run_job(job_id, BIG, "fetch premium") == "WAITING_APPROVAL"
    finally:
        clerk.ledger.close()


# -- auth is fail-closed, actor is the authenticated principal -----------------

def test_app_refuses_to_start_without_tokens(monkeypatch):
    monkeypatch.delenv("CLERK_APPROVAL_TOKENS", raising=False)
    with pytest.raises(RuntimeError):
        create_app(lambda: None)
    with pytest.raises(RuntimeError):
        create_app(lambda: None, tokens={"akiyuki": ""})  # empty token = unauthenticated


def test_all_routes_require_bearer_token(env):
    client, factory, _ = env
    park_big_job(factory)
    for attempt in ({}, {"Authorization": "Bearer wrong"}):
        assert client.get("/asks", headers=attempt).status_code == 401
        assert client.post("/jobs/job-ask-1/decision", headers=attempt,
                           json={"action": "APPROVED"}).status_code == 401
        assert client.post("/jobs/job-ask-1/resume", headers=attempt).status_code == 401


def test_actor_comes_from_credential_not_body(env):
    client, factory, _ = env
    park_big_job(factory)
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
        assert [e["actor"] for e in clerk.ledger.events("job-ask-1")] == ["auditor"]
    finally:
        clerk.ledger.close()


# -- the full human loop: list -> decide -> job completes ----------------------

def test_list_decide_completes_and_pays_once(env):
    client, factory, rail = env
    park_big_job(factory)

    asks = client.get("/asks", headers=AUTH).json()
    assert len(asks) == 1
    ask = asks[0]
    assert ask["job_id"] == "job-ask-1"
    assert (ask["merchant"], ask["invoice_id"]) == (BIG.merchant, BIG.invoice_id)
    assert ask["amount"] == "2.00" and ask["memo"] == "GET /premium"
    assert ask["digest"] == BIG.digest()  # terms served from the pinned row
    assert ask["decision"] is None

    r = client.post("/jobs/job-ask-1/decision", headers=AUTH,
                    json={"action": "APPROVED", "note": "ok for demo"})
    body = r.json()
    assert (body["decided"], body["action_in_effect"], body["state"]) == (True, "APPROVED", "DONE")
    assert rail.settled == ["api.example/inv-ask-1"]  # exactly one settlement
    assert client.get("/asks", headers=AUTH).json() == []  # queue drained

    clerk = factory()
    try:
        (event,) = clerk.ledger.events("job-ask-1")
        assert event["actor"] == "akiyuki"
        assert event["action"] == "APPROVED" and event["outcome"] == "recorded"
        assert event["invoice_digest"] == BIG.digest()
        assert event["state_before"] == "WAITING_APPROVAL/ASK_PENDING"
        assert event["state_after"] == "DONE/PAID"
        assert event["request_id"] == body["request_id"]
    finally:
        clerk.ledger.close()


def test_reject_ends_job_without_payment(env):
    client, factory, rail = env
    park_big_job(factory)
    r = client.post("/jobs/job-ask-1/decision", headers=AUTH,
                    json={"action": "REJECTED", "note": "not needed"})
    assert r.json()["state"] == "FAILED"
    assert rail.settled == []


# -- terminal decisions: idempotent resend, 409 on the opposite ----------------

def test_resend_is_idempotent_and_flip_is_conflict(env):
    client, factory, rail = env
    park_big_job(factory)
    first = client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "REJECTED"}).json()
    assert first["decided"] is True and first["state"] == "FAILED"

    resend = client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "REJECTED"}).json()
    assert resend["decided"] is False  # idempotent no-op, still 200
    assert resend["action_in_effect"] == "REJECTED"

    flip = client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "APPROVED"})
    assert flip.status_code == 409
    assert rail.settled == []

    clerk = factory()
    try:
        outcomes = [e["outcome"] for e in clerk.ledger.events("job-ask-1")]
        assert outcomes == ["recorded", "idempotent-noop", "conflict"]
    finally:
        clerk.ledger.close()


# -- decision persists before resume: crash between the two recovers -----------

def test_crash_after_decision_persist_recovers_without_double_pay(env, tmp_path):
    client, factory, rail = env

    crashed = []

    class CrashBeforeResume(Clerk):
        def resume(self, job_id):
            if not crashed:
                crashed.append(job_id)
                raise RuntimeError("simulated crash between decision persist and resume")
            return super().resume(job_id)

    def crashy_factory():
        return CrashBeforeResume(Ledger(tmp_path / "ledger.db"), POLICY, rail)

    crashy_client = TestClient(create_app(crashy_factory, tokens=TOKENS),
                               raise_server_exceptions=False)
    park_big_job(factory)

    r = crashy_client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "APPROVED"})
    assert r.status_code == 500
    assert rail.settled == []  # crashed before any payment path

    # "Restart": the ordinary app over the same ledger file. The decision
    # survived, so recovery resume completes the job with exactly one payment.
    asks = client.get("/asks", headers=AUTH).json()
    assert asks[0]["decision"] == "APPROVED"
    r = client.post("/jobs/job-ask-1/resume", headers=AUTH).json()
    assert r["state"] == "DONE"
    assert rail.settled == ["api.example/inv-ask-1"]


# -- resume is not free-form ----------------------------------------------------

def test_resume_only_for_parked_jobs(env):
    client, factory, rail = env
    park_big_job(factory)
    # Undecided parked job: resume is allowed but pays nothing and stays parked.
    assert client.post("/jobs/job-ask-1/resume", headers=AUTH).json()["state"] == "WAITING_APPROVAL"
    assert rail.settled == []
    # Completed job: resume is refused.
    client.post("/jobs/job-ask-1/decision", headers=AUTH, json={"action": "APPROVED"})
    assert client.post("/jobs/job-ask-1/resume", headers=AUTH).status_code == 409
    assert rail.settled == ["api.example/inv-ask-1"]


# -- strict schemas and unknown targets ----------------------------------------

def test_strict_schema_rejects_unknown_fields_and_oversize_note(env):
    client, factory, _ = env
    park_big_job(factory)
    bad_bodies = [
        {"action": "APPROVED", "amount": "0.01"},        # unknown field
        {"action": "APPROVED", "digest": "0" * 64},      # unknown field
        {"action": "PAY"},                               # not a valid action
        {"action": "APPROVED", "note": "x" * 501},       # note over cap
    ]
    for body in bad_bodies:
        assert client.post("/jobs/job-ask-1/decision", headers=AUTH, json=body).status_code == 422


def test_unknown_job_is_404(env):
    client, _, _ = env
    assert client.post("/jobs/no-such-job/decision", headers=AUTH,
                       json={"action": "APPROVED"}).status_code == 404
    assert client.post("/jobs/no-such-job/resume", headers=AUTH).status_code == 404
