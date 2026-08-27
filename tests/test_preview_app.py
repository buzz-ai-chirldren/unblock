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
import os
import re
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
# Derived, not pinned: the job id comes from the incident, so a fixture change
# would otherwise leave every decision test posting to a job that never existed.
JOB = "unblock-7937bef067a1"


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
    assert "この未評価の部品を調べる" in page      # the plain-language primary action
    assert "Check this unreviewed package" in page   # the same action for filming
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


def test_the_challenge_price_matches_the_price_the_story_narrates(client):
    """Side by side, the story said $0.50 while the merchant's own 402 said
    $0.05. A panel that contradicts the story it sits next to is worse than
    no panel."""
    cheap = client.get("/api/merchant/challenge", params={"price": "0.05"},
                       headers=auth()).json()
    dear = client.get("/api/merchant/challenge", params={"price": "0.50"},
                      headers=auth()).json()
    assert cheap["payment_required"]["accepts"][0]["amount"] == "50000"
    assert dear["payment_required"]["accepts"][0]["amount"] == "500000"


def test_an_unpriced_merchant_is_refused_rather_than_guessed(client):
    assert client.get("/api/merchant/challenge", params={"price": "9.99"},
                      headers=auth()).status_code == 400


def test_the_story_requests_the_challenge_at_its_own_price(client):
    page = client.get("/", headers=auth()).text
    assert "/api/merchant/challenge?price=${price}" in page


def test_the_story_column_marks_its_own_payment_as_mock(client):
    """The right-hand panel badged NOT BROADCAST while the story column showed
    a receipt id next to a dollar amount with nothing to say it was a mock.
    The story column is the one that gets filmed and cropped."""
    page = client.get("/", headers=auth()).text
    story_receipt = page[page.index("L.s4t_pay, L.s4p_pay"):]
    assert "badge mock" in story_receipt[:600]


# -- the story arrives one step at a time -----------------------------------

def test_the_steps_are_paced_rather_than_dumped(client):
    """One click used to print all five steps at once: a result list, not a
    sequence. The owner could not narrate it."""
    page = client.get("/", headers=auth()).text
    assert "const pace = (ms)" in page
    assert "await pace(BEAT)" in page
    assert "async function reveal(" in page


def test_the_pause_precedes_the_request_so_both_columns_move_together(client):
    page = client.get("/", headers=auth()).text
    story = page[page.index("async function story(scenario)"):page.index("async function decide")]
    # each phase waits, then calls, then draws - never draws ahead of the work
    assert story.index("await pace(BEAT)") < story.index('await call("/api/site")')
    assert story.count("await pace(") >= 4


def test_reduced_motion_keeps_the_order_and_drops_the_movement(client):
    page = client.get("/", headers=auth()).text
    assert "prefers-reduced-motion" in page
    assert "Math.min(ms, 120)" in page, "reduced motion must still be sequential"
    assert "animation:none" in page


def test_the_expensive_path_generates_nothing_past_the_human(client):
    page = client.get("/", headers=auth()).text
    story = page[page.index("async function story(scenario)"):page.index("async function decide")]
    parked = story[story.index("if (parked) {"):]
    assert "return;" in parked, "the story must stop at the decision"
    assert "L.s5t" not in parked, "step 5 is generated before anyone chose"


def test_the_verdict_line_comes_from_the_policy_not_a_restatement(client):
    page = client.get("/", headers=auth()).text
    assert 'const parked = verdict.status === "waiting-approval";' in page
    # the line is appended from that value, not recomputed from the price
    assert 'parked ? L.v_ask : L.v_pay' in page
    assert "overCap ? L.v_ask" not in page, "the verdict is being restated locally"


def test_the_run_buttons_are_disabled_while_a_story_runs(client):
    page = client.get("/", headers=auth()).text
    assert 'for (const id of ["go","go2"]) document.getElementById(id).disabled = true;' in page


# -- the page's own JavaScript has to parse ---------------------------------

def _inline_script(html: str, marker: str) -> str:
    start = html.index(marker) + len(marker)
    return html[start:html.index("</script>", start)]


def test_the_page_javascript_parses(preview, tmp_path):
    """A missing brace shipped once: 126 assertions passed because every one of
    them reads the HTML as a string, and the browser was the only thing that
    ever tried to run it. The page renders blank labels and no button works.
    """
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available")

    script = tmp_path / "ui.js"
    script.write_text(_inline_script(preview.UI_HTML, "<script>"), encoding="utf-8")
    result = subprocess.run([node, "--check", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_the_panel_does_not_show_an_outcome_before_the_story_tells_it(client):
    """One response feeds the verdict, the payment and the result. Logging it
    the instant it arrived put done-paid on the right while the left was still
    two steps behind - visible in a mid-story frame, which is a video frame."""
    page = client.get("/", headers=auth()).text
    assert "function flushWire(" in page
    # the run call is held back
    assert '{method:"POST"}, true)' in page
    story = page[page.index("async function story(scenario)"):page.index("async function decide")]
    assert story.index("flushWire();") > story.index('await pace(BEAT);\n  card.querySelector')

    # the rejected path carries done-free in that same response, so step 5's
    # own requests are held too and everything lands as step 5 is drawn
    paid = page[page.index("async function paid("):]
    assert 'await call("/api/site", {}, true)' in paid
    assert 'await call("/api/pr", {}, true)' in paid
    # the left element is drawn first and the flush follows in the same tick,
    # so no frame can catch the panel ahead of the story
    assert paid.index('step(5, "good"') < paid.index("flushWire();   // run (if still held)")


def test_a_held_entry_keeps_the_step_it_was_made_at(client):
    page = client.get("/", headers=auth()).text
    assert "function logWire(verb, path, status, body, atStep = STEP)" in page
    assert '${atStep || "·"}' in page


def test_held_entries_drain_in_arrival_order(client):
    """Holding an entry back must not reorder the record."""
    page = client.get("/", headers=auth()).text
    assert "let HELD = [];" in page
    assert "HELD.push(entry)" in page
    assert "for (const entry of queued) logWire(...entry);" in page


def test_a_new_story_inherits_nothing_that_was_held(client):
    page = client.get("/", headers=auth()).text
    story = page[page.index("async function story(scenario)"):page.index("async function decide")]
    assert "HELD = [];" in story
    assert story.index("HELD = [];") < story.index('await call("/api/demo/reset"')


# -- the error path, executed rather than read ------------------------------

CHROME = (
    Path("/srv/workspaces/claude/REPOS/OpenMontage/remotion-composer/node_modules")
    / ".remotion/chrome-headless-shell/linux64/chrome-headless-shell-linux64/chrome-headless-shell"
)
WS_MODULE = (
    Path("/srv/workspaces/claude/REPOS/OpenMontage/remotion-composer/node_modules/ws")
)


@pytest.fixture
def served(tmp_path):
    """The preview on a real port. The error path cannot be checked by reading
    the page: it only exists while the script is running."""
    import shutil
    import socket
    import subprocess
    import time
    import urllib.request

    if not (shutil.which("node") and CHROME.exists() and WS_MODULE.exists()):
        pytest.skip("node, chromium or ws is unavailable")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    env = {
        **os.environ,
        "CLERK_PREVIEW_TOKEN": TOKEN,
        "PREVIEW_RUN_DIR": str(tmp_path / "run"),
        "PREVIEW_TTL_HOURS": "1",
    }
    for name in ("BEDROCK_KEY_FILE", "CLERK_WALLET_FILE", "AWS_ACCESS_KEY_ID"):
        env.pop(name, None)

    server = subprocess.Popen(
        ["uv", "run", "uvicorn", "demo.preview_app:app", "--host", "127.0.0.1",
         "--port", str(port)],
        cwd=REPO, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(120):
            try:
                urllib.request.urlopen(f"{base}/health", timeout=1).read()
                break
            except Exception:
                time.sleep(0.5)
        else:
            pytest.skip("preview server did not start")
        yield base
    finally:
        server.terminate()
        server.wait(timeout=10)


def test_an_error_mid_run_discards_what_was_held(served, tmp_path):
    """A held response surviving an error would flush somebody else's outcome
    into the next story's panel. The whole point of holding is that the panel
    never shows something the story has not reached."""
    import json
    import subprocess

    result = subprocess.run(
        ["node", str(REPO / "tests/browser/error_cleanup.js"), served, TOKEN],
        capture_output=True, text=True, timeout=180,
        env={**os.environ, "CHROME_PATH": str(CHROME), "WS_MODULE": str(WS_MODULE),
             "CDP_PORT": "9611"},
    )
    assert result.returncode == 0, result.stderr
    state = json.loads(result.stdout.strip().splitlines()[-1])

    assert state["held"] == 0, "a response stayed held after the run failed"
    # step 5 defers /api/site; the failure lands before it can be shown, so the
    # panel must still carry only the step 1 fetch of the same path
    assert sum("/api/site" in p for p in state["wirePaths"]) == 1, \
        f"a held response leaked into the panel: {state['wirePaths']}"
    assert state["errorShown"], "the failure was not surfaced to the operator"
    assert state["buttonsEnabled"], "the run buttons stayed disabled after a failure"


@pytest.mark.parametrize("button,reject", [("go", False), ("go2", True)])
def test_the_panel_never_runs_ahead_of_the_story(served, button, reject):
    """UI Gate item 4, run rather than eyeballed.

    The fault this catches was fixed once on the paid path and left standing on
    the rejected one, because the fix was written where the symptom had been
    seen instead of where the responses are read. A frame-by-frame invariant
    does not care which branch it is looking at.
    """
    import json
    import subprocess

    command = ["node", str(REPO / "tests/browser/lead_invariant.js"), served, TOKEN, button]
    if reject:
        command.append("reject")

    result = subprocess.run(
        command, capture_output=True, text=True, timeout=240,
        env={**os.environ, "CHROME_PATH": str(CHROME), "WS_MODULE": str(WS_MODULE),
             "CDP_PORT": "9612"},
    )
    assert result.returncode != 2, result.stderr
    state = json.loads(result.stdout.strip().splitlines()[-1])

    assert not state["ahead"], (
        f"the panel ran ahead of the story: {state['ahead'][:3]} "
        f"(transitions {state['transitions']})"
    )
    assert state["reachedEnd"], f"the story did not finish: {state['transitions']}"


# -- paying has to buy something -------------------------------------------

def test_the_paid_record_is_the_analysis_the_story_describes(client):
    """The screen says the report names what the package was doing. The record
    the pipeline actually validated has to carry that, or the story is a
    caption over unrelated data."""
    import json as _json

    record = _json.loads((REPO / "fixtures/preview_intel.json").read_text())
    entry = record["vendor/quickparse-0.4.1.md"]
    assert entry["final_url"], "the observed destination is what was bought"
    assert entry["suggested_replacement"] == "vendor/quickparse-0.4.3.md"


def test_the_paid_record_still_passes_strict_validation(client):
    """It carries the threat meaning inside the five fields the agent accepts.
    Adding verdict/behaviours would be rejected as invalid intel: the pipeline
    demands exactly this field set so a merchant cannot smuggle extras in."""
    import json as _json
    import sys as _sys

    _sys.path.insert(0, str(REPO / "src"))
    from unblock.pipeline import INTEL_FIELDS, Unblock

    entry = _json.loads((REPO / "fixtures/preview_intel.json").read_text())[
        "vendor/quickparse-0.4.1.md"]
    assert set(entry) == set(INTEL_FIELDS)
    assert Unblock._replacement_from(
        {"resource": _json.dumps(entry)}, "vendor/quickparse-0.4.1.md"
    ) == "vendor/quickparse-0.4.3.md"


def test_refusing_to_pay_does_not_land_where_paying_lands(client):
    """If both routes end at the same file the $0.05 buys nothing, and the
    whole point of the human decision disappears."""
    client.post("/api/demo/reset", headers=auth())
    paid = client.post("/api/demo/run", params={"scenario": "allow"},
                       headers=auth()).json()
    paid_site = {f["path"]: f["body"] for f in client.get("/api/site", headers=auth()).json()}

    client.post("/api/demo/reset", headers=auth())
    client.post("/api/demo/run", params={"scenario": "ask-over-cap"}, headers=auth())
    client.post(f"/approval/v1/approvals/{JOB}/decision",
                json={"action": "REJECT"}, headers=auth())
    free = client.post("/api/demo/run", params={"scenario": "ask-over-cap"},
                       headers=auth()).json()
    free_site = {f["path"]: f["body"] for f in client.get("/api/site", headers=auth()).json()}

    assert paid["verdicts"][0]["status"] == "done-paid"
    assert free["verdicts"][0]["status"] == "done-free"
    assert "quickparse-0.4.3.md" in paid_site["release.md"], "paying keeps the feature"
    assert "quarantined.md" in free_site["release.md"], "refusing switches it off"
    assert paid_site["release.md"] != free_site["release.md"]


def test_the_preview_challenge_names_what_it_sells(client):
    body = client.get("/api/merchant/challenge", headers=auth()).json()
    assert body["payment_required"]["resource"]["description"] == (
        "Threat intelligence report for an unreviewed dependency"
    )


def test_the_gate_c_merchant_keeps_its_own_description():
    """The preview renames what it sells; the shipped demo does not move."""
    source = (REPO / "demo/merchant.py").read_text()
    assert '"Link Intelligence record behind an x402 paywall (Gate C demo)"' in source
