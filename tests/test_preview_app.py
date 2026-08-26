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
    monkeypatch.setenv("PREVIEW_RUN_DIR", str(tmp_path / "preview_run"))
    sys.modules.pop("demo.preview_app", None)
    module = importlib.import_module("demo.preview_app")
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


# -- runtime state never touches the repository -----------------------------

def test_the_default_run_dir_is_outside_the_repo(monkeypatch):
    monkeypatch.setenv("CLERK_PREVIEW_TOKEN", TOKEN)
    monkeypatch.delenv("PREVIEW_RUN_DIR", raising=False)
    sys.modules.pop("demo.preview_app", None)
    module = importlib.import_module("demo.preview_app")
    assert REPO not in module.RUN_DIR.parents and module.RUN_DIR != REPO


def test_a_run_dir_inside_the_repo_is_refused(monkeypatch):
    monkeypatch.setenv("CLERK_PREVIEW_TOKEN", TOKEN)
    monkeypatch.setenv("PREVIEW_RUN_DIR", str(REPO / "demo" / "somewhere"))
    sys.modules.pop("demo.preview_app", None)
    with pytest.raises(RuntimeError, match="outside the repository"):
        importlib.import_module("demo.preview_app")


def test_driving_the_whole_demo_does_not_touch_the_repository(client):
    """The failure this pins: runtime state under the repo meant a run rewrote
    its own fixture and a reset deleted tracked files.

    It compares `git status --short` before and after rather than asserting the
    tree is clean, so it holds while the branch is being worked on too -- and
    an unchanged status is the property that actually matters.
    """
    import subprocess

    def status() -> str:
        result = subprocess.run(
            ["git", "status", "--short"], cwd=REPO,
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            pytest.skip("not a git checkout")
        return result.stdout

    before = status()

    for scenario in ("allow", "ask-over-cap", "ask-unknown-merchant"):
        client.post("/api/demo/reset", headers=auth())
        client.post("/api/demo/run", params={"scenario": scenario}, headers=auth())
        client.post(f"/approval/v1/approvals/{JOB}/decision",
                    json={"action": "REJECT"}, headers=auth())
        client.post("/api/demo/run", params={"scenario": scenario}, headers=auth())
        assert status() == before, f"{scenario} changed the repository"

    client.post("/api/demo/reset", headers=auth())
    assert status() == before, "reset changed the repository"


# -- the landing page has to explain itself ---------------------------------

def test_the_entry_point_carries_no_internal_jargon(client):
    """The owner could not present the old screen: it opened with RUN THE JOB
    and internal verb names. Those belong in the developer drawer, not the
    first thing a person reads."""
    client.get(f"/?t={TOKEN}", follow_redirects=False)
    page = client.get("/", headers=auth()).text
    for jargon in ("RUN THE JOB", "ALLOW", "DENY", "WAITING_APPROVAL",
                   "reason_code", "idempotency", "FileRail"):
        assert jargon not in page, f"{jargon!r} is visible on the landing page"


def test_the_page_opens_with_the_risk_not_the_feature(client):
    """Order fixed with Codex: fear, then the safeguard, then proof, then the
    future. A visitor who does not know x402 has to recognise the problem in
    the first line."""
    page = client.get("/", headers=auth()).text
    assert "AIにお金を使わせたとき、誰が止めるんですか？" in page
    assert "You gave an AI a wallet. Who stops the spending?" in page
    assert "ローカルな防火壁" in page and "local spending firewall" in page


def test_the_future_section_does_not_overclaim(client):
    """The rails are swappable and other irreversible actions are a plausible
    extension, but this code has only ever proved the payment path. The page
    has to say so, or the demo quietly promises something it cannot show."""
    page = client.get("/", headers=auth()).text
    assert "x402" in page and "Tempo MPP" in page
    assert "いま実証できているのは「支払い」の経路です" in page
    assert "what this code proves is the payment path" in page
    for overclaim in ("deploy", "データベース", "メール送信"):
        assert overclaim not in page, f"the page claims {overclaim!r} is covered"


def test_the_story_is_told_in_both_languages(client):
    page = client.get("/", headers=auth()).text
    assert "リンク切れを直してみる" in page      # the plain-language primary action
    assert "Fix the broken link" in page          # the same action for filming
    for anchor in ("const JA = {", "const EN = {", "toggleLang"):
        assert anchor in page


def test_the_page_still_shows_it_is_a_mock(client):
    page = client.get("/", headers=auth()).text
    assert "実際のお金は動きません" in page and "no real money moves" in page


# -- the browser session reaches the approval API ---------------------------

def _cookie_client(preview):
    """A client that has only the session cookie -- no Authorization header,
    which is exactly what a browser has.

    base_url is https because the cookie is Secure: over http the client would
    silently decline to send it and the test would prove nothing.
    """
    client = TestClient(preview.app, base_url="https://testserver")
    client.get(f"/?t={TOKEN}", follow_redirects=False)
    assert client.cookies.get("preview_token"), "no session cookie was set"
    return client


def test_a_cookie_session_can_read_the_approval_api(preview):
    """The mounted v1 API checks the bearer header itself. A browser cannot
    supply one -- the token is httpOnly on purpose -- so without help its
    approve/reject is answered 401 while every curl example works."""
    client = _cookie_client(preview)
    assert client.get("/approval/v1/approvals").status_code == 200


def test_a_cookie_session_can_decide(preview):
    client = _cookie_client(preview)
    client.post("/api/demo/reset")
    client.post("/api/demo/run", params={"scenario": "ask-over-cap"})

    decision = client.post(f"/approval/v1/approvals/{JOB}/decision",
                           json={"action": "REJECT"})
    assert decision.status_code == 200, decision.text
    assert decision.json()["action_in_effect"] == "REJECTED"

    after = client.post("/api/demo/run", params={"scenario": "ask-over-cap"}).json()
    assert after["verdicts"][0]["status"] == "done-free"
    assert client.get("/api/pr").json(), "the story's evidence panel would be empty"


def test_an_unauthenticated_request_is_not_given_a_header(preview):
    # The injection happens only after the gate has already authenticated.
    client = TestClient(preview.app, base_url="https://testserver")
    assert client.get("/approval/v1/approvals").status_code == 401


def test_a_wrong_bearer_is_not_upgraded(preview):
    client = TestClient(preview.app, base_url="https://testserver")
    assert client.get("/approval/v1/approvals",
                      headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_the_session_cookie_is_declined_over_plain_http(preview):
    """Secure is doing its job: the same cookie buys nothing on http."""
    insecure = TestClient(preview.app)
    insecure.cookies.set("preview_token", TOKEN, domain="testserver")
    assert insecure.get("/api/jobs").status_code == 401


def test_only_the_approval_subapp_receives_the_injected_bearer(preview):
    """Least privilege, tested as the risk was described: something else gets
    mounted later and is silently handed the owner token."""
    seen: dict[str, str] = {}

    async def recorder(scope, receive, send):
        headers = {k.decode(): v.decode() for k, v in scope["headers"]}
        seen["auth"] = headers.get("authorization", "")
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    preview.app.mount("/other", recorder)

    client = _cookie_client(preview)
    assert client.get("/other/anything").status_code == 204
    assert seen["auth"] == "", "a newly mounted sub-app was handed the owner token"

    # The one it is meant for still works.
    assert client.get("/approval/v1/approvals").status_code == 200


def test_an_explicit_bearer_is_never_replaced(preview):
    """Injection fills a gap; it does not override what the caller sent."""
    client = TestClient(preview.app, base_url="https://testserver")
    assert client.get("/approval/v1/approvals",
                      headers={"Authorization": "Bearer wrong"}).status_code == 401


# -- the wire panel ---------------------------------------------------------

def test_the_raw_data_panel_is_alongside_the_story_not_hidden(client):
    """The owner asked to watch the data move step by step. Burying it in a
    collapsed drawer meant reading it out of order, after the fact."""
    page = client.get("/", headers=auth()).text
    assert '<aside class="wire">' in page
    assert 'id="wirelog"' in page
    assert "実際に流れているデータ" in page and "what actually moved" in page
    # every request the page makes is logged, so the panel cannot drift from
    # what really happened
    assert "async function call(" in page and "function logWire(" in page
    assert page.count("await fetch(") <= 2, "a request bypasses the wire logger"


def test_the_challenge_is_labelled_as_an_invoice_not_a_payment(client):
    """The 402 shows payTo 0x…dEaD and a testserver URL. Without a word of
    explanation that reads as a broken demo rather than a deliberate one."""
    page = client.get("/", headers=auth()).text
    assert "X-PAYMENT" in page
    assert "請求書であって、支払いではありません" in page
    assert "an invoice, not a payment" in page
    assert "burn address" in page


def test_rejection_is_explained_as_a_decision_not_a_failure(client):
    page = client.get("/", headers=auth()).text
    assert "仕事の失敗ではありません" in page
    assert "not that the job failed" in page


def test_the_panel_leads_with_readable_fields_then_the_raw_json(client):
    page = client.get("/", headers=auth()).text
    assert "function summarise(" in page
    assert '<details><summary>' in page and 'JSON.stringify(body, null, 1)' in page
    for label in ("k_amount", "k_network", "k_asset", "k_payto", "k_settle"):
        assert f"{label}:" in page


def test_mock_and_live_settlement_are_never_shown_as_the_same_thing(client):
    """A demo that lets a mock run read as a settled payment is worse than one
    with no payment at all."""
    page = client.get("/", headers=auth()).text
    assert "NOT BROADCAST" in page
    assert "CONFIRMED" in page
    assert "0x64a0a2d15d9dd4e33c419c0af1289acf30b0eea074630ab177e9760bff430834" in page
    assert "sepolia.basescan.org" in page
    # the live tx is labelled as a different run, not this one
    assert "この実行とは別" in page and "a different run" in page


def test_the_in_process_merchant_is_not_passed_off_as_a_public_url(client):
    page = client.get("/", headers=auth()).text
    assert "公開URLではありません" in page and "not a public URL" in page
    assert "burn address" in page


def test_the_panel_is_reachable_on_a_narrow_screen(client):
    page = client.get("/", headers=auth()).text
    assert 'id="wiretoggle"' in page
    assert "@media (max-width:1180px)" in page
    assert ".wire.open" in page
