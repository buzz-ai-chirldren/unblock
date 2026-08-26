"""Tests for the owner preview surface.

The preview is the only part of this repo that has ever been reachable from
the public internet, so its guards are the ones worth pinning: what is
readable without a token, what happens after the clock runs out, and the
promise that no paid endpoint exists here at all.

Everything runs on the mock rail against a temp directory; nothing in these
tests can reach a network.
"""
from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# demo/ is a script directory, not an installed package: the repo root has to
# be importable before `demo.preview_app` resolves.
REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

TOKEN = "test-token-that-is-long-enough-xxxx"
JOB = "unblock-1c00f07c873d"


@pytest.fixture
def preview(tmp_path, monkeypatch):
    """A fresh preview module per test, with its scratch dir in tmp_path."""
    for name in ("BEDROCK_KEY_FILE", "CLERK_WALLET_FILE", "AWS_ACCESS_KEY_ID",
                 "AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLERK_PREVIEW_TOKEN", TOKEN)
    monkeypatch.setenv("PREVIEW_TTL_HOURS", "12")
    sys.modules.pop("demo.preview_app", None)
    module = importlib.import_module("demo.preview_app")
    module.RUN_DIR = tmp_path / "preview_run"
    module._HITS.clear()
    return module


@pytest.fixture
def client(preview):
    return TestClient(preview.app)


def auth(token: str = TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


# -- startup guard ----------------------------------------------------------

def test_refuses_to_start_holding_money_credentials(monkeypatch):
    monkeypatch.setenv("CLERK_PREVIEW_TOKEN", TOKEN)
    monkeypatch.setenv("CLERK_WALLET_FILE", "/tmp/wallet.json")
    sys.modules.pop("demo.preview_app", None)
    with pytest.raises(RuntimeError, match="credentials"):
        importlib.import_module("demo.preview_app")
    monkeypatch.delenv("CLERK_WALLET_FILE")


def test_refuses_a_short_token(monkeypatch):
    monkeypatch.setenv("CLERK_PREVIEW_TOKEN", "short")
    sys.modules.pop("demo.preview_app", None)
    with pytest.raises(RuntimeError, match="24 chars"):
        importlib.import_module("demo.preview_app")


# -- what is readable without a token ---------------------------------------

@pytest.mark.parametrize("path", [
    "/", "/api/jobs", "/api/pr", "/api/site", "/pilot.mp4",
    "/api/merchant/challenge", "/approval/v1/approvals", "/docs", "/openapi.json",
])
def test_everything_interesting_needs_a_token(client, path):
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("path", ["/api/demo/run", "/api/demo/reset"])
def test_mutating_routes_need_a_token(client, path):
    assert client.post(path).status_code == 401


def test_health_is_public_and_says_it_is_a_mock(client):
    body = client.get("/health").json()
    assert body["ok"] is True
    assert "no real money" in body["rail"]
    assert body["seconds_remaining"] > 0


def test_robots_is_public_and_disallows_everything(client):
    # A crawler that gets 401 never reads the disallow.
    response = client.get("/robots.txt")
    assert response.status_code == 200
    assert "Disallow: /" in response.text


def test_a_wrong_token_is_rejected(client):
    assert client.get("/api/jobs", headers=auth("nope-nope-nope-nope-nope-nope")).status_code == 401


# -- browser entry ----------------------------------------------------------

def test_bootstrap_link_works_exactly_once(client, preview):
    first = client.get(f"/?t={TOKEN}", follow_redirects=False)
    assert first.status_code == 303 and first.headers["location"] == "/"
    assert preview._BOOTSTRAP_SPENT is True

    second = client.get(f"/?t={TOKEN}", follow_redirects=False)
    assert second.headers["location"] == "/login?reason=bootstrap-spent"


def test_the_session_cookie_is_httponly_and_secure(client):
    header = client.get(f"/?t={TOKEN}", follow_redirects=False).headers["set-cookie"]
    assert "HttpOnly" in header and "Secure" in header


def test_login_takes_the_token_in_the_body_not_the_url(client):
    response = client.post("/login", data={"token": TOKEN}, follow_redirects=False)
    assert response.status_code == 303
    assert "Secure" in response.headers["set-cookie"]


def test_login_page_is_reachable_without_a_token(client):
    assert client.get("/login").status_code == 200


def test_a_bad_login_sets_no_cookie(client):
    response = client.post("/login", data={"token": "wrong"}, follow_redirects=False)
    assert "set-cookie" not in response.headers


# -- expiry -----------------------------------------------------------------

def test_an_expired_preview_answers_410(client, preview):
    preview.EXPIRES_AT = time.time() - 1
    assert client.get("/api/jobs", headers=auth()).status_code == 410
    assert client.post("/api/demo/run", headers=auth()).status_code == 410


def test_health_still_answers_after_expiry(client, preview):
    # So an operator can see *why* everything else is 410.
    preview.EXPIRES_AT = time.time() - 1
    assert client.get("/health").status_code == 200


# -- rate limit -------------------------------------------------------------

def test_reads_are_rate_limited(client, preview):
    limit, _ = preview.READ_LIMIT
    for _ in range(limit):
        assert client.get("/api/jobs", headers=auth()).status_code == 200
    assert client.get("/api/jobs", headers=auth()).status_code == 429


def test_mutations_have_a_tighter_limit(client, preview):
    assert preview.WRITE_LIMIT[0] < preview.READ_LIMIT[0]
    for _ in range(preview.WRITE_LIMIT[0]):
        assert client.post("/api/demo/reset", headers=auth()).status_code == 200
    assert client.post("/api/demo/reset", headers=auth()).status_code == 429


# -- the merchant is not for sale here --------------------------------------

@pytest.mark.parametrize("path", ["/merchant/intel", "/intel", "/merchant"])
def test_no_paid_endpoint_is_reachable(client, path):
    # Mounting the merchant made the x402 middleware stop matching and served
    # the paid record for free. It stays unmounted; only the challenge shows.
    assert client.get(path, headers=auth()).status_code == 404


def test_the_challenge_shows_terms_but_never_the_paid_record(client):
    body = client.get("/api/merchant/challenge", headers=auth()).json()
    assert body["status"] == 402
    assert body["payment_required"]["accepts"][0]["amount"] == "50000"
    assert "suggested_replacement" not in str(body)


def test_an_unknown_link_is_refused_before_any_challenge(client):
    body = client.get("/api/merchant/challenge",
                      params={"broken_url": "nope.md"}, headers=auth()).json()
    assert body["status"] == 400
    assert body["payment_required"] is None


# -- the three scenarios ----------------------------------------------------

def test_allow_pays_on_the_mock_rail(client):
    client.post("/api/demo/reset", headers=auth())
    body = client.post("/api/demo/run", params={"scenario": "allow"}, headers=auth()).json()
    (verdict,) = body["verdicts"]
    assert verdict["status"] == "done-paid"
    assert verdict["receipt"]["rail"] == "filemock"
    assert body["remaining_broken_links"] == 0


@pytest.mark.parametrize("scenario,reason", [
    ("ask-over-cap", "over-invoice-cap"),
    ("ask-unknown-merchant", "merchant-not-allowlisted"),
])
def test_out_of_policy_purchases_park_for_a_human(client, scenario, reason):
    client.post("/api/demo/reset", headers=auth())
    body = client.post("/api/demo/run", params={"scenario": scenario}, headers=auth()).json()
    assert [v["status"] for v in body["verdicts"]] == ["waiting-approval"]
    assert body["remaining_broken_links"] == 1
    assert body["next_step"]

    (parked,) = client.get("/approval/v1/approvals", headers=auth()).json()
    assert parked["reason_code"] == reason


def test_an_unknown_scenario_is_refused(client):
    assert client.post("/api/demo/run", params={"scenario": "nope"},
                       headers=auth()).status_code == 400


# -- the human decision -----------------------------------------------------

def _park(client) -> None:
    client.post("/api/demo/reset", headers=auth())
    client.post("/api/demo/run", params={"scenario": "ask-over-cap"}, headers=auth())


def test_reject_finishes_the_job_without_paying(client, preview):
    _park(client)
    client.post(f"/approval/v1/approvals/{JOB}/decision",
                json={"action": "REJECT"}, headers=auth())
    body = client.post("/api/demo/run", params={"scenario": "ask-over-cap"},
                       headers=auth()).json()
    (verdict,) = body["verdicts"]
    assert verdict["status"] == "done-free"
    assert verdict["receipt"] is None
    assert body["remaining_broken_links"] == 0
    assert not (preview.RUN_DIR / "rail.db").exists() or _settlements(preview) == 0


def _settlements(preview) -> int:
    import sqlite3
    return sqlite3.connect(preview.RUN_DIR / "rail.db").execute(
        "select count(*) from settlements").fetchone()[0]


def test_approve_pays_the_pinned_terms(client):
    _park(client)
    decision = client.post(f"/approval/v1/approvals/{JOB}/decision",
                           json={"action": "APPROVE"}, headers=auth()).json()
    assert decision["action_in_effect"] == "APPROVED"
    body = client.post("/api/demo/run", params={"scenario": "ask-over-cap"},
                       headers=auth()).json()
    (verdict,) = body["verdicts"]
    assert verdict["status"] == "done-paid"
    assert verdict["receipt"]["amount"] == "0.50"


def test_a_conflicting_second_decision_is_refused(client):
    _park(client)
    client.post(f"/approval/v1/approvals/{JOB}/decision",
                json={"action": "REJECT"}, headers=auth())
    conflict = client.post(f"/approval/v1/approvals/{JOB}/decision",
                           json={"action": "APPROVE"}, headers=auth())
    assert conflict.status_code == 409


# -- reset ------------------------------------------------------------------

def test_reset_clears_jobs_and_prs(client):
    client.post("/api/demo/reset", headers=auth())
    client.post("/api/demo/run", params={"scenario": "allow"}, headers=auth())
    assert client.get("/api/jobs", headers=auth()).json()
    assert client.get("/api/pr", headers=auth()).json()

    client.post("/api/demo/reset", headers=auth())
    assert client.get("/api/jobs", headers=auth()).json() == []
    assert client.get("/api/pr", headers=auth()).json() == []


def test_reset_restores_the_broken_site(client):
    client.post("/api/demo/reset", headers=auth())
    client.post("/api/demo/run", params={"scenario": "allow"}, headers=auth())
    client.post("/api/demo/reset", headers=auth())
    body = client.post("/api/demo/run", params={"scenario": "allow"}, headers=auth()).json()
    assert body["incidents_found"] == 1


def test_reading_the_ledger_before_any_run_is_fine(client):
    # A human's first move is often to look before touching anything.
    assert client.get("/api/jobs", headers=auth()).json() == []
    assert client.get("/api/pr", headers=auth()).json() == []
