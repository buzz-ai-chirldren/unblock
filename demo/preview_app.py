"""Owner preview: the real UNBLOCK code behind one URL, on the mock rail.

This exists so a human can drive the demo from a browser and a terminal before
we film it. It adds NO business logic: the pipeline, the clerk, the policy and
the approval API are imported and run exactly as they ship. What is new here is
a thin operator surface -- run, reset, list, inspect, decide -- plus the guards
that make a temporary public URL safe:

  * mock rail only. Nothing here can reach Bedrock, a wallet, x402, or GitHub.
    `_assert_offline()` fails startup if the process was handed any of those.
  * bearer token on every route except /health and /robots.txt. Terminals send
    Authorization: Bearer, which never reaches an access log. Browsers post the
    token to /login. A ?t=<token> bootstrap link still works, but exactly ONCE:
    a token that has been in a URL is a token that is in somebody's log, so the
    URL path is closed after its first redemption and later attempts land on
    /login instead.
  * a hard expiry. After it, every route answers 410 and the server stops.
  * a scratch directory OUTSIDE the repository, deleted and rebuilt by
    /api/demo/reset. Runtime state under the repo would mean a demo run
    rewriting its own fixture and a reset deleting tracked files.
  * a per-IP rate limit, tighter on the mutating routes.

Run:
  CLERK_PREVIEW_TOKEN=<token> uv run uvicorn demo.preview_app:app --port 8410
Env:
  CLERK_PREVIEW_TOKEN   required, the owner's bearer token
  PREVIEW_TTL_HOURS     default 12
  PREVIEW_RUN_DIR       scratch dir, default <tmp>/unblock-preview-run.
                        Must be outside the repository.
"""

from __future__ import annotations

import hmac
import json
import os
import shutil
import sys
import tempfile
import time
from collections import defaultdict, deque
from decimal import Decimal
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse,
)

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from clerk.approval_api import create_app  # noqa: E402
from clerk.jobs import Clerk  # noqa: E402
from clerk.ledger import Ledger  # noqa: E402
from clerk.policy import Policy  # noqa: E402
from clerk.rails import FileRail  # noqa: E402
from unblock import Incident, IntelOffer, Unblock, detect  # noqa: E402

# --- guards ----------------------------------------------------------------

FORBIDDEN_ENV = (
    "BEDROCK_KEY_FILE", "CLERK_WALLET_FILE", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN", "GH_TOKEN",
)


def _assert_offline() -> None:
    """Refuse to start if this process could reach anything that costs money.

    A preview that *might* be holding a wallet key is not a preview, and the
    cheapest place to find out is before the port is open.
    """
    present = [name for name in FORBIDDEN_ENV if os.environ.get(name)]
    if present:
        raise RuntimeError(
            "preview refuses to start with money/cloud credentials in the "
            f"environment: {', '.join(present)}"
        )


_assert_offline()

TOKEN = os.environ.get("CLERK_PREVIEW_TOKEN") or ""
if len(TOKEN) < 24:
    raise RuntimeError("CLERK_PREVIEW_TOKEN must be set and at least 24 chars")

# Flipped by the first successful ?t= redemption. In-process only: a restart
# re-opens the bootstrap link, which is the behaviour we want when a preview is
# re-issued and the owner needs to get back in.
_BOOTSTRAP_SPENT = False

TTL_HOURS = float(os.environ.get("PREVIEW_TTL_HOURS", "12"))
STARTED_AT = time.time()
EXPIRES_AT = STARTED_AT + TTL_HOURS * 3600

# Runtime state lives outside the repository, always. The fixture site under
# fixtures/ is the immutable source; a run copies it here and edits the copy.
# Keeping the two in one place meant a demo run rewrote its own fixture and a
# reset deleted tracked files -- found in review, not in tests, because the
# tests point RUN_DIR at a tmp_path and never saw the production default.
RUN_DIR = Path(
    os.environ.get("PREVIEW_RUN_DIR")
    or Path(tempfile.gettempdir()) / "unblock-preview-run"
).resolve()
if RUN_DIR == REPO or REPO in RUN_DIR.parents:
    raise RuntimeError(
        f"PREVIEW_RUN_DIR must be outside the repository, got {RUN_DIR}"
    )

# Same policy the demo ships with: $0.10 per invoice, $1.00 a week, one
# allowlisted merchant. Anything outside it parks for a human.
OFFER = IntelOffer("intel.example", Decimal("0.05"), url="http://intel.example/intel")
BIG_OFFER = IntelOffer("intel.example", Decimal("0.50"), url="http://intel.example/intel")
UNKNOWN_OFFER = IntelOffer("stranger.example", Decimal("0.05"), url="http://stranger.example/intel")
POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("1.00"),
    per_invoice_cap=Decimal("0.10"),
    merchant_allowlist=frozenset({OFFER.merchant}),
)
INTEL_RECORD = json.dumps(
    json.loads((REPO / "fixtures" / "intel_db.json").read_text())["guides/install.md"]
)

# The free fallback the pipeline uses when a human REJECTS the purchase. Same
# pair demo/record_reject.py uses, so a rejected job finishes without paying
# rather than dying -- which is the whole point of REJECT.
FREE_SOURCES = {"guides/install.md": "docs/setup.md"}

SCENARIOS = {
    # label -> (offer, what the human should expect to see)
    "allow": (OFFER, "under the cap: the clerk pays on the mock rail, no human needed"),
    "ask-over-cap": (BIG_OFFER, "$0.50 exceeds the $0.10 cap: parks for approval"),
    "ask-unknown-merchant": (UNKNOWN_OFFER, "merchant not allowlisted: parks for approval"),
}


def _site() -> Path:
    site = RUN_DIR / "site"
    if not site.exists():
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copytree(REPO / "fixtures" / "site", site)
    return site


def _rail() -> FileRail:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    return FileRail(RUN_DIR / "rail.db", paid_body=INTEL_RECORD)


def _clerk_factory():
    # Reading the ledger before anything has been run is a normal first move
    # for a human poking at the preview; sqlite will not create a database in
    # a directory that does not exist yet.
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    return Clerk(Ledger(RUN_DIR / "ledger.db"), POLICY, _rail())


def _pipeline(offer: IntelOffer) -> Unblock:
    policy = POLICY
    return Unblock(
        site_dir=_site(),
        allowed_file="index.md",
        clerk_factory=lambda: Clerk(Ledger(RUN_DIR / "ledger.db"), policy, _rail()),
        offer=offer,
        pr_dir=RUN_DIR / "prs",
        free_sources=FREE_SOURCES,
    )


# --- rate limit ------------------------------------------------------------

_HITS: dict[str, deque[float]] = defaultdict(deque)
READ_LIMIT = (60, 60.0)      # 60 requests per minute
WRITE_LIMIT = (10, 60.0)     # 10 mutating requests per minute


def _rate_limit(request: Request, limit: tuple[int, float]) -> None:
    count, window = limit
    key = f"{request.client.host if request.client else '?'}:{count}"
    now = time.time()
    hits = _HITS[key]
    while hits and now - hits[0] > window:
        hits.popleft()
    if len(hits) >= count:
        raise HTTPException(status_code=429, detail="slow down")
    hits.append(now)


# --- app -------------------------------------------------------------------

app = FastAPI(title="UNBLOCK owner preview")

# The real approval API, unmodified, under its own prefix. Its own bearer
# token is the same one, so the terminal only ever carries one secret.
approval = create_app(_clerk_factory, tokens={"owner": TOKEN})
app.mount("/approval", approval)

# The real x402 merchant, so the 402 challenge shown here is the genuine
# article rather than a mock-up. It holds no keys -- only a receiving address,
# here the burn address, because nothing in this preview ever pays it.
#
# It is deliberately NOT mounted. Mounting rewrites the request path, the x402
# payment middleware is configured for "/intel" and stops matching, and the
# paywalled record is then served for free -- measured, not assumed. So the
# merchant is exercised in-process against its own root path and only its
# CHALLENGE is exposed. There is no reachable paid endpoint on this preview.
os.environ.setdefault("MERCHANT_ADDRESS", "0x000000000000000000000000000000000000dEaD")
try:
    from fastapi.testclient import TestClient  # noqa: E402

    from demo.merchant import app as _merchant_app  # noqa: E402

    _merchant = TestClient(_merchant_app, raise_server_exceptions=False)
    MERCHANT_AVAILABLE = True
except Exception:  # pragma: no cover - the preview is still useful without it
    MERCHANT_AVAILABLE = False


def _authorised(request: Request) -> bool:
    supplied = request.headers.get("Authorization", "")
    if hmac.compare_digest(supplied.encode(), f"Bearer {TOKEN}".encode()):
        return True
    cookie = request.cookies.get("preview_token", "")
    return hmac.compare_digest(cookie.encode(), TOKEN.encode())


PUBLIC_PATHS = frozenset({"/health", "/robots.txt", "/login"})


def _session_cookie(response):
    """Set the browser session cookie. `secure` because the only way in is the
    HTTPS tunnel; a preview cookie that would travel in clear is a preview
    cookie waiting to be read."""
    response.set_cookie(
        "preview_token", TOKEN, httponly=True, secure=True,
        samesite="lax", max_age=int(TTL_HOURS * 3600),
    )
    return response


@app.middleware("http")
async def gate(request: Request, call_next):
    global _BOOTSTRAP_SPENT
    path = request.url.path

    if path == "/robots.txt":
        # Deliberately before the auth check: a crawler that gets 401 never
        # reads the disallow, which is the opposite of what it is for.
        return PlainTextResponse("User-agent: *\nDisallow: /\n")
    if path == "/health":
        return await call_next(request)

    if time.time() > EXPIRES_AT:
        return JSONResponse({"detail": "preview expired"}, status_code=410)

    # One-shot browser bootstrap. Valid once; after that the link is dead even
    # with the right token, and the browser is sent to the form instead.
    token_param = request.query_params.get("t")
    if path == "/" and token_param:
        good = hmac.compare_digest(token_param.encode(), TOKEN.encode())
        if good and not _BOOTSTRAP_SPENT:
            _BOOTSTRAP_SPENT = True
            return _session_cookie(RedirectResponse("/", status_code=303))
        return RedirectResponse("/login?reason=bootstrap-spent", status_code=303)

    if path in PUBLIC_PATHS:
        return await call_next(request)

    if not _authorised(request):
        return JSONResponse({"detail": "invalid or missing bearer token"}, status_code=401)

    try:
        _rate_limit(request, WRITE_LIMIT if request.method != "GET" else READ_LIMIT)
    except HTTPException as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return await call_next(request)


@app.get("/health")
def health() -> dict:
    return {
        "ok": True,
        "rail": "mock (FileRail) - no real money can move from this process",
        "commit": os.environ.get("PREVIEW_COMMIT", "unknown"),
        "expires_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(EXPIRES_AT)),
        "seconds_remaining": max(0, int(EXPIRES_AT - time.time())),
        "merchant_challenge_available": MERCHANT_AVAILABLE,
    }


@app.post("/api/demo/reset")
def reset() -> dict:
    """Delete the scratch site, ledger and PRs, then recreate the site."""
    if RUN_DIR.exists():
        shutil.rmtree(RUN_DIR)
    _site()
    return {"reset": True, "run_dir": str(RUN_DIR)}


@app.post("/api/demo/run")
def run(scenario: str = "allow") -> dict:
    """Run the deterministic pipeline over every detected incident.

    No model is involved. In the filmed demo a Strands agent sequences these
    same two steps; here the operator is the sequencer, which is precisely what
    makes the payment behaviour easy to see.
    """
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"unknown scenario {scenario!r}")
    offer, expectation = SCENARIOS[scenario]
    pipeline = _pipeline(offer)
    incidents = detect(_site())
    verdicts = [{"incident_id": i.incident_id, "file": i.file, "broken_link": i.link,
                 **pipeline.run(i)} for i in incidents]
    parked = [v for v in verdicts if v["status"] == "waiting-approval"]
    return {
        "scenario": scenario,
        "expectation": expectation,
        "incidents_found": len(incidents),
        "verdicts": verdicts,
        "remaining_broken_links": len(detect(_site())),
        "rail": "mock",
        "next_step": (
            "decide on the parked job, then run again: the decision only records "
            "what may happen, the pipeline is what carries it out"
            if parked else None
        ),
    }


@app.get("/api/merchant/challenge")
def merchant_challenge(broken_url: str = "guides/install.md") -> dict:
    """What the real merchant answers before any payment is made.

    Returns the status, the body, and the decoded x402 terms. The paid record
    itself is never returned by this route: an unpaid request cannot get it,
    which is the property worth showing.
    """
    if not MERCHANT_AVAILABLE:
        raise HTTPException(status_code=503, detail="merchant not available")
    response = _merchant.get("/intel", params={"broken_url": broken_url})
    header = response.headers.get("payment-required")
    terms = None
    if header:
        import base64

        try:
            terms = json.loads(base64.b64decode(header))
        except Exception:
            terms = {"undecodable": header[:80]}
    return {
        "status": response.status_code,
        "body": response.text[:500],
        "payment_required": terms,
        "note": (
            "400 before any challenge means an unknown link costs the caller nothing"
            if response.status_code == 400
            else "402 with pinned terms: amount, asset, network, payTo"
        ),
    }


@app.get("/api/jobs")
def jobs() -> list[dict]:
    """Every job in the preview ledger, newest first."""
    clerk = _clerk_factory()
    try:
        rows = clerk.ledger.conn.execute(
            "SELECT job_id, state, merchant, invoice_id FROM jobs ORDER BY rowid DESC"
        ).fetchall()
        return [
            {"job_id": r[0], "state": r[1], "merchant": r[2], "invoice_id": r[3]}
            for r in rows
        ]
    finally:
        clerk.ledger.close()


@app.get("/api/pr")
def prs() -> list[dict]:
    directory = RUN_DIR / "prs"
    if not directory.exists():
        return []
    return [{"name": p.name, "body": p.read_text()} for p in sorted(directory.glob("*.md"))]


@app.get("/api/site")
def site_files() -> list[dict]:
    site = _site()
    return [
        {"path": str(p.relative_to(site)), "body": p.read_text()}
        for p in sorted(site.rglob("*.md"))
    ]


@app.get("/", response_class=HTMLResponse)
def ui() -> str:
    return UI_HTML


PILOT = Path(__file__).resolve().parent / "preview_assets" / "unblock-pilot.mp4"


@app.get("/pilot.mp4")
def pilot():
    """The 45s pilot cut, served here because the relay refuses the file and a
    second place to look is a second thing to lose."""
    if not PILOT.exists():
        raise HTTPException(status_code=404, detail="no pilot render bundled")
    return FileResponse(PILOT, media_type="video/mp4")


@app.get("/login", response_class=HTMLResponse)
def login_form(reason: str = "") -> str:
    note = {
        "bootstrap-spent": "That one-time link has already been used. Paste the token instead.",
    }.get(reason, "")
    return LOGIN_HTML.replace("{{note}}", note)


@app.post("/login")
async def login(request: Request):
    """Token in the request body, never in the URL, so it stays out of logs."""
    form = await request.form()
    supplied = str(form.get("token", ""))
    if not hmac.compare_digest(supplied.encode(), TOKEN.encode()):
        return RedirectResponse("/login?reason=bad-token", status_code=303)
    return _session_cookie(RedirectResponse("/", status_code=303))


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots() -> str:
    return "User-agent: *\nDisallow: /\n"


LOGIN_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>UNBLOCK preview — sign in</title>
<style>
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;
      color:#e6edf3;font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace}
 form{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:26px;width:min(92vw,400px)}
 h1{font-size:15px;margin:0 0 6px} p{color:#8b949e;margin:0 0 16px}
 .note{color:#d29922}
 input{width:100%;padding:9px;border-radius:5px;border:1px solid #30363d;
       background:#0d1117;color:inherit;font:inherit;margin-bottom:12px}
 button{width:100%;padding:9px;border-radius:5px;border:1px solid #2ea043;
        background:#238636;color:#fff;font:inherit;cursor:pointer}
</style></head><body>
<form method="post" action="/login">
  <h1>UNBLOCK — owner preview</h1>
  <p>Mock rail. No real money. <span class="note">{{note}}</span></p>
  <input type="password" name="token" placeholder="preview token" autofocus autocomplete="off">
  <button type="submit">enter</button>
</form></body></html>
"""


UI_HTML = r"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>UNBLOCK</title>
<style>
  :root { color-scheme: dark; --bg:#0d1117; --panel:#161b22; --line:#30363d;
          --fg:#e6edf3; --dim:#8b949e; --ok:#3fb950; --warn:#d29922; --bad:#f85149;
          --accent:#58a6ff; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:15px/1.7 -apple-system,BlinkMacSystemFont,"Hiragino Sans","Noto Sans JP",sans-serif; }
  code, pre, .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  header { padding:12px 20px; border-bottom:1px solid var(--line); display:flex;
           gap:12px; align-items:center; flex-wrap:wrap; font-size:13px; }
  header b { font-size:14px; letter-spacing:.02em; }
  .tag { background:var(--warn); color:#000; padding:2px 8px; border-radius:3px;
         font-weight:700; font-size:11px; }
  .spacer { flex:1 }
  .dim { color:var(--dim); }
  main { padding:28px 20px 60px; max-width:820px; margin:0 auto; }
  h1 { font-size:26px; line-height:1.45; margin:0 0 14px; }
  .lede { font-size:16px; color:var(--dim); margin:0 0 26px; }
  button { background:#21262d; color:var(--fg); border:1px solid var(--line);
           border-radius:6px; padding:9px 14px; cursor:pointer; font:inherit; }
  button:hover:not(:disabled) { border-color:#6e7681; }
  button:disabled { opacity:.45; cursor:default; }
  button.primary { background:#238636; border-color:#2ea043; font-weight:600;
                   padding:12px 20px; font-size:16px; }
  button.link { background:none; border:none; color:var(--accent); padding:0;
                text-decoration:underline; font-size:14px; }
  button.approve { background:#238636; border-color:#2ea043; }
  button.reject { background:#4a1f1f; border-color:#6e2b2b; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  .steps { margin:30px 0 0; display:grid; gap:12px; }
  .step { background:var(--panel); border:1px solid var(--line); border-radius:8px;
          padding:16px 18px; display:grid; grid-template-columns:30px 1fr; gap:14px;
          opacity:0; transform:translateY(6px); animation:in .35s ease forwards; }
  @keyframes in { to { opacity:1; transform:none } }
  .num { width:26px; height:26px; border-radius:50%; background:#21262d;
         border:1px solid var(--line); display:grid; place-items:center;
         font-size:13px; color:var(--dim); }
  .step.good .num { background:#12321c; border-color:#2ea043; color:var(--ok); }
  .step.ask  .num { background:#3a2d09; border-color:#9e7615; color:var(--warn); }
  .step h3 { margin:0 0 4px; font-size:16px; }
  .step p { margin:0; color:var(--dim); font-size:14px; }
  .fact { margin-top:10px; background:#0d1117; border:1px solid var(--line);
          border-radius:6px; padding:10px 12px; font-size:13px; }
  .fact .mono { color:var(--fg); word-break:break-all; }
  .rules { display:grid; gap:6px; margin-top:10px; font-size:13px; }
  .rule { display:flex; gap:9px; align-items:baseline; }
  .yes { color:var(--ok); } .no { color:var(--warn); }
  .verdict { margin-top:12px; padding:10px 12px; border-radius:6px; font-weight:600;
             font-size:14px; }
  .verdict.pay { background:#12321c; border:1px solid #2ea043; }
  .verdict.ask { background:#3a2d09; border:1px solid #9e7615; }
  .diff { margin-top:10px; border:1px solid var(--line); border-radius:6px;
          overflow:hidden; font-size:13px; }
  .diff div { padding:5px 11px; }
  .diff .del { background:#3a1414; color:#ffa198; }
  .diff .add { background:#12321c; color:#7ee787; }
  .summary { margin-top:12px; display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
             gap:10px; }
  .cell { background:#0d1117; border:1px solid var(--line); border-radius:6px; padding:11px 13px; }
  .cell .k { font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:.07em; }
  .cell .v { font-size:17px; font-weight:600; margin-top:3px; }
  details { margin-top:34px; border-top:1px solid var(--line); padding-top:14px; }
  summary { cursor:pointer; color:var(--dim); font-size:13px; }
  pre { background:#0d1117; border:1px solid var(--line); border-radius:6px;
        padding:11px; overflow:auto; margin:10px 0 0; max-height:300px;
        white-space:pre-wrap; word-break:break-word; font-size:12px; }
  table { border-collapse:collapse; width:100%; margin-top:10px; font-size:13px; }
  th,td { text-align:left; padding:6px 9px; border-bottom:1px solid var(--line); }
  th { color:var(--dim); font-weight:600; }
  video { width:100%; border:1px solid var(--line); border-radius:6px; margin-top:10px; }
  @media (max-width:640px){ main{padding:20px 14px 50px} h1{font-size:21px} }
</style></head><body>
<header>
  <b>UNBLOCK</b>
  <span class="tag" data-i="badge"></span>
  <span class="spacer"></span>
  <button class="link" id="lang" onclick="toggleLang()"></button>
  <span class="dim" id="meta"></span>
</header>
<main>
  <h1 data-i="title"></h1>
  <p class="lede" data-i="lede"></p>
  <div class="row">
    <button class="primary" id="go" onclick="story('allow')" data-i="cta"></button>
    <button id="go2" onclick="story('ask-over-cap')" data-i="cta2"></button>
    <button id="again" onclick="location.reload()" data-i="again" style="display:none"></button>
  </div>
  <div class="steps" id="steps"></div>

  <details>
    <summary data-i="dev"></summary>
    <div class="row" style="margin-top:12px">
      <button onclick="raw('/api/jobs')" data-i="d_jobs"></button>
      <button onclick="raw('/api/pr')" data-i="d_pr"></button>
      <button onclick="raw('/api/merchant/challenge')" data-i="d_402"></button>
      <button onclick="raw('/api/merchant/challenge?broken_url=nope.md')" data-i="d_400"></button>
      <button onclick="resetAll()" data-i="d_reset"></button>
    </div>
    <pre id="rawout">—</pre>
    <p class="dim" style="font-size:13px" data-i="d_note"></p>
    <video src="/pilot.mp4" controls preload="none"></video>
  </details>
</main>
<script>
const JA = {
  badge:"デモ用・実際のお金は動きません", lang:"English",
  title:"AIが「有料の壁」で止まらないようにする仕組みです。",
  lede:"サイトのリンク切れを直すのに、答えが有料ページの向こうにありました。ふつうのAIはここで止まって人間を待ちます。UNBLOCKは、決められたおこづかいの範囲なら自分で買って、仕事を最後まで終わらせます。高すぎるときだけ人間に聞きます。",
  cta:"リンク切れを直してみる", cta2:"高い情報だったら？", again:"もう一度はじめから",
  s1t:"AIが壊れたリンクを見つけた", s1p:"サイトの中を機械的に調べただけ。ここまではお金の話は出てきません。",
  s2t:"直し方が有料ページの向こうにある", s2p:"正しいリンク先を知っているサイトが「先にお金を払って」と答えました。ふつうのAIはここで止まります。",
  s3t:"おこづかい係が判断する", s3p:"AI本人は財布を持っていません。決めるのは、書き換えられないルールです。",
  s4t_pay:"ルールの範囲内なので、自分で払った", s4p_pay:"人を待たずに支払い完了。誰にいくら払ったかは記録に残ります。",
  s4t_ask:"高すぎるので、人間に聞いた", s4p_ask:"AIは勝手に払いません。あなたが決めるまで、この仕事は止まったまま安全に待ちます。",
  s5t:"直して、確認して、証拠を残した", s5p:"リンクを直し、本当に直ったか確かめ、「何に・なぜ・いくら払ったか」を残しました。",
  s5t_free:"お金を使わずに直した", s5p_free:"あなたが「払わない」と決めたので、無料の代わりの情報で直しました。支払いはゼロ件です。",
  r_cap:"1回の上限", r_week:"1週間の上限", r_shop:"知っているお店か",
  v_pay:"→ 自動で払ってよい", v_ask:"→ 人間に聞く",
  k_paid:"支払った額", k_left:"残った不具合", k_pr:"証拠", k_price:"値段", k_shop:"お店",
  approve:"払っていい", reject:"払わない", decide:"あなたが決めてください",
  before:"直す前", after:"直した後", nopay:"支払いなし",
  dev:"開発者向けの生データ", d_jobs:"ジョブ一覧", d_pr:"PR成果物", d_402:"402チャレンジ",
  d_400:"知らないリンク（400）", d_reset:"リセット",
  d_note:"402は本物のx402マーチャントが返した内容です。知らないリンクは課金の前に400で断られるので、間違った質問はタダです。",
  running:"実行中…",
};
const EN = {
  badge:"DEMO — no real money moves", lang:"日本語",
  title:"An AI that does not stop at a paywall.",
  lede:"Fixing a broken link needed an answer that sits behind a paid page. A normal agent stops there and waits for a human. UNBLOCK buys it within a fixed allowance and finishes the job — and asks a person only when the price is out of bounds.",
  cta:"Fix the broken link", cta2:"What if it were expensive?", again:"Start over",
  s1t:"The agent found a broken link", s1p:"A plain mechanical scan of the site. No money involved yet.",
  s2t:"The fix is behind a paywall", s2p:"The site that knows the correct target answered: pay first. A normal agent stops here.",
  s3t:"The allowance clerk decides", s3p:"The model holds no wallet. The decision is made by rules it cannot rewrite.",
  s4t_pay:"Within the rules, so it paid", s4p_pay:"No human needed. Who was paid and how much is on the record.",
  s4t_ask:"Too expensive, so it asked", s4p_ask:"The agent will not pay on its own. The job waits, safely, until you decide.",
  s5t:"Fixed, verified, evidenced", s5p:"It repaired the link, checked the repair really held, and recorded what was bought, why, and for how much.",
  s5t_free:"Fixed without spending anything", s5p_free:"You said no, so it finished from a free source instead. Zero settlements.",
  r_cap:"Per-purchase cap", r_week:"Weekly allowance", r_shop:"Known merchant",
  v_pay:"→ pay automatically", v_ask:"→ ask a human",
  k_paid:"Paid", k_left:"Remaining faults", k_pr:"Evidence", k_price:"Price", k_shop:"Merchant",
  approve:"Approve", reject:"Reject", decide:"Your call",
  before:"before", after:"after", nopay:"nothing paid",
  dev:"Raw data for developers", d_jobs:"jobs", d_pr:"PR artifact", d_402:"402 challenge",
  d_400:"unknown link (400)", d_reset:"reset",
  d_note:"The 402 is what the real x402 merchant returned. An unknown link is refused with 400 before any charge, so a wrong question costs nothing.",
  running:"running…",
};
let L = localStorage.getItem("lang") === "en" ? EN : JA;
const j = (r) => r.json();
const el = (h) => { const d = document.createElement("div"); d.innerHTML = h.trim(); return d.firstChild; };
const esc = (t) => String(t).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));

function paint(){
  document.documentElement.lang = L === JA ? "ja" : "en";
  document.getElementById("lang").textContent = L.lang;
  for (const node of document.querySelectorAll("[data-i]"))
    node.textContent = L[node.dataset.i] ?? "";
}
function toggleLang(){
  L = (L === JA) ? EN : JA;
  localStorage.setItem("lang", L === EN ? "en" : "ja");
  paint();
  document.getElementById("steps").innerHTML = "";
  document.getElementById("again").style.display = "none";
  for (const id of ["go","go2"]) document.getElementById(id).disabled = false;
}
async function meta(){
  const h = await fetch("/health").then(j);
  document.getElementById("meta").textContent = `${h.commit.slice(0,7)} · ${h.expires_at_utc}`;
}

const steps = () => document.getElementById("steps");
function add(html){ const n = el(html); steps().appendChild(n); n.scrollIntoView({behavior:"smooth", block:"end"}); return n; }
const step = (n, cls, title, body, extra="") => add(
  `<div class="step ${cls}"><div class="num">${n}</div><div>
     <h3>${esc(title)}</h3><p>${esc(body)}</p>${extra}</div></div>`);

let PENDING = null;

async function story(scenario){
  for (const id of ["go","go2"]) document.getElementById(id).disabled = true;
  steps().innerHTML = "";
  await fetch("/api/demo/reset", {method:"POST"});

  const before = await fetch("/api/site").then(j);
  const index = before.find(f => f.path === "index.md");
  const broken = (index.body.match(/\]\(([^)]*install[^)]*)\)/) || [null,"guides/install.md"])[1];
  step(1, "", L.s1t, L.s1p,
    `<div class="fact">index.md → <span class="mono">${esc(broken)}</span> ✕</div>`);

  const ch = await fetch("/api/merchant/challenge").then(j);
  const opt = ch.payment_required?.accepts?.[0];
  const price = scenario === "allow" ? "0.05" : "0.50";
  step(2, "", L.s2t, L.s2p,
    `<div class="fact">HTTP <span class="mono">402 Payment Required</span> ·
      ${L.k_price}: <span class="mono">$${price} USDC</span> ·
      ${L.k_shop}: <span class="mono">${esc(scenario === "ask-unknown-merchant" ? "stranger.example" : "intel.example")}</span></div>`);

  const overCap = Number(price) > 0.10;
  step(3, overCap ? "ask" : "good", L.s3t, L.s3p, `
    <div class="rules">
      <div class="rule"><span class="${overCap ? "no" : "yes"}">${overCap ? "✕" : "✓"}</span>
        <span>${L.r_cap}: $0.10 &nbsp;<span class="dim">(→ $${price})</span></span></div>
      <div class="rule"><span class="yes">✓</span><span>${L.r_week}: $1.00</span></div>
      <div class="rule"><span class="yes">✓</span><span>${L.r_shop}: intel.example</span></div>
    </div>
    <div class="verdict ${overCap ? "ask" : "pay"}">${overCap ? L.v_ask : L.v_pay}</div>`);

  const run = await fetch(`/api/demo/run?scenario=${scenario}`, {method:"POST"}).then(j);
  const verdict = run.verdicts[0];

  if (verdict.status === "waiting-approval") {
    PENDING = {job: verdict.job_id, scenario, before: index.body, price};
    step(4, "ask", L.s4t_ask, L.s4p_ask, `
      <div class="fact"><b>${L.decide}</b> — $${price} USDC → intel.example</div>
      <div class="row" style="margin-top:12px">
        <button class="approve" onclick="decide('APPROVE')">${L.approve}</button>
        <button class="reject" onclick="decide('REJECT')">${L.reject}</button>
      </div>`);
    return;
  }
  paid(verdict, index.body, price);
}

async function decide(action){
  const {job, scenario, before, price} = PENDING;
  for (const b of document.querySelectorAll(".approve,.reject")) b.disabled = true;
  await fetch(`/approval/v1/approvals/${job}/decision`, {
    method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({action})});
  const run = await fetch(`/api/demo/run?scenario=${scenario}`, {method:"POST"}).then(j);
  paid(run.verdicts[0], before, action === "APPROVE" ? price : null);
}

async function paid(verdict, beforeBody, price){
  const free = verdict.status === "done-free";
  if (!free && price)
    step(4, "good", L.s4t_pay, L.s4p_pay,
      `<div class="fact"><span class="mono">${esc(verdict.receipt?.tx || "")}</span> ·
        $${verdict.receipt?.amount || price} ${esc(verdict.receipt?.currency || "USDC")}</div>`);

  const after = await fetch("/api/site").then(j);
  const afterIndex = after.find(f => f.path === "index.md").body;
  const [bLine, aLine] = [beforeBody, afterIndex].map(
    body => (body.split("\n").find(l => l.includes("](")) || "").trim());
  const prs = await fetch("/api/pr").then(j);

  step(5, "good", free ? L.s5t_free : L.s5t, free ? L.s5p_free : L.s5p, `
    <div class="diff">
      <div class="del">− ${esc(bLine)} <span class="dim">${L.before}</span></div>
      <div class="add">+ ${esc(aLine)} <span class="dim">${L.after}</span></div>
    </div>
    <div class="summary">
      <div class="cell"><div class="k">${L.k_paid}</div><div class="v">${
        free || !price ? L.nopay : "$" + (verdict.receipt?.amount || price)}</div></div>
      <div class="cell"><div class="k">${L.k_left}</div><div class="v">0</div></div>
      <div class="cell"><div class="k">${L.k_pr}</div><div class="v mono" style="font-size:13px">${
        esc(prs[0]?.name || "—")}</div></div>
    </div>`);
  document.getElementById("again").style.display = "inline-block";
}

const raw = async (path) =>
  document.getElementById("rawout").textContent =
    JSON.stringify(await fetch(path).then(j), null, 2);
const resetAll = async () =>
  document.getElementById("rawout").textContent =
    JSON.stringify(await fetch("/api/demo/reset", {method:"POST"}).then(j), null, 2);

paint(); meta();
</script></body></html>
"""
