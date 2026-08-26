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
  * a rate limit shared by the whole preview, tighter on the mutating routes.

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
# One budget for the whole preview, not per visitor: behind the tunnel every
# request arrives from 127.0.0.1, so the key collapses to a single bucket.
# That is the stricter reading and it cannot be spoofed by a header, but it
# means the ceiling has to clear a human demo comfortably -- one story is four
# writes, and being throttled mid-demo would be worse than the abuse it stops.
READ_LIMIT = (120, 60.0)     # 120 reads per minute
WRITE_LIMIT = (30, 60.0)     # 30 mutating requests per minute


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

# One merchant per scenario price. The story tells the reader what the intel
# costs; the panel beside it shows the merchant's own 402. If those two numbers
# disagree, the panel stops being evidence and starts being decoration -- which
# is exactly what happened when the challenge was hard-wired to $0.05 while the
# expensive path narrated $0.50.
_MERCHANTS: dict[str, object] = {}
try:
    import importlib

    from fastapi.testclient import TestClient  # noqa: E402

    for _price in ("0.05", "0.50"):
        os.environ["MERCHANT_PRICE"] = f"${_price}"
        _module = importlib.reload(importlib.import_module("demo.merchant"))
        _MERCHANTS[_price] = TestClient(_module.app, raise_server_exceptions=False)
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

    # The mounted approval API does its own bearer check, by design -- it is the
    # shipped v1 contract and must keep behaving that way for API callers. A
    # browser authenticated by the session cookie has no header to offer and no
    # way to read the httpOnly token, so its APPROVE/REJECT was answered 401.
    # Having already authenticated the request here, present it downstream in
    # the form that sub-app expects -- and ONLY to that sub-app. Injecting on
    # every path would hand the owner token to whatever gets mounted next.
    if path.startswith("/approval/") and not request.headers.get("Authorization"):
        request.scope["headers"] = [
            (k, v) for k, v in request.scope["headers"] if k.lower() != b"authorization"
        ] + [(b"authorization", f"Bearer {TOKEN}".encode())]

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
def merchant_challenge(broken_url: str = "guides/install.md", price: str = "0.05") -> dict:
    """What the real merchant answers before any payment is made.

    Returns the status, the body, and the decoded x402 terms. The paid record
    itself is never returned by this route: an unpaid request cannot get it,
    which is the property worth showing.
    """
    if not MERCHANT_AVAILABLE:
        raise HTTPException(status_code=503, detail="merchant not available")
    merchant = _MERCHANTS.get(price)
    if merchant is None:
        raise HTTPException(status_code=400, detail=f"no merchant priced at {price!r}")
    response = merchant.get("/intel", params={"broken_url": broken_url})
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
  main { padding:24px 20px 60px; max-width:1440px; margin:0 auto; display:grid;
         grid-template-columns:minmax(0,1fr) 420px; gap:26px; align-items:start; }
  @media (max-width:1180px){ main { grid-template-columns:minmax(0,1fr); } }
  .story { min-width:0; }
  .wire { position:sticky; top:14px; max-height:calc(100vh - 28px); overflow:auto;
          background:var(--panel); border:1px solid var(--line); border-radius:8px; }
  @media (max-width:1180px){ .wire { position:static; max-height:none; } }
  .wire > h2 { font-size:12px; margin:0; padding:11px 14px; color:var(--dim);
               text-transform:uppercase; letter-spacing:.08em;
               border-bottom:1px solid var(--line); position:sticky; top:0;
               background:var(--panel); }
  .wire .hint { padding:14px; color:var(--dim); font-size:13px; margin:0; }
  .w-entry { border-bottom:1px solid var(--line); padding:11px 14px; }
  .w-entry:last-child { border-bottom:none; }
  .w-top { display:flex; gap:7px; align-items:center; flex-wrap:wrap; font-size:12px;
           font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .w-step { width:19px; height:19px; border-radius:50%; background:#21262d;
            border:1px solid var(--line); display:grid; place-items:center;
            font-size:11px; color:var(--dim); flex:none; }
  .w-verb { color:var(--accent); }
  .w-path { color:var(--fg); word-break:break-all; flex:1; }
  .w-code { padding:0 6px; border-radius:3px; font-weight:600; }
  .w-code.ok { background:#12321c; color:var(--ok); }
  .w-code.no { background:#3a1414; color:var(--bad); }
  .w-entry pre { margin:8px 0 0; max-height:230px; font-size:11.5px; }
  .w-note { margin:8px 0 0; font-size:12px; color:var(--warn); line-height:1.55; }
  .w-kv { margin:9px 0 0; display:grid; grid-template-columns:auto 1fr; gap:3px 10px;
          font-size:12px; }
  .w-kv dt { color:var(--dim); white-space:nowrap; }
  .w-kv dd { margin:0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
             word-break:break-all; }
  .w-entry details { margin:9px 0 0; border:none; padding:0; }
  .w-entry summary { font-size:12px; }
  .badge { display:inline-block; padding:1px 7px; border-radius:3px; font-size:11px;
           font-weight:700; letter-spacing:.03em; }
  .badge.mock { background:#3a2d09; color:var(--warn); border:1px solid #9e7615; }
  .badge.live { background:#12321c; color:var(--ok); border:1px solid #2ea043; }
  .w-entry.current { background:#11161d; box-shadow:inset 3px 0 0 var(--accent); }
  .evidence { border-top:1px solid var(--line); padding:13px 14px; }
  .evidence h3 { margin:0 0 7px; font-size:12px; color:var(--dim);
                 text-transform:uppercase; letter-spacing:.08em; }
  .evidence a { color:var(--accent); }
  #wiretoggle { display:none; }
  @media (max-width:1180px){
    /* A full-width bar rather than a floating button: a FAB sits on top of
       whatever happens to be under it, and here that was the reject button. */
    #wiretoggle { display:block; position:fixed; left:0; right:0; bottom:0; z-index:21;
                  border-radius:0; border-left:none; border-right:none; border-bottom:none;
                  padding:11px; font-weight:600; }
    main { padding-bottom:64px; }
    .wire { position:fixed; left:0; right:0; bottom:44px; z-index:20; max-height:72vh;
            border-radius:12px 12px 0 0; transform:translateY(calc(101% + 44px));
            transition:transform .22s ease; }
    .wire.open { transform:none; }
  }
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
  .step, .rule, .verdict, .w-entry {
          opacity:0; transform:translateY(6px); animation:in .3s ease forwards; }
  .step { background:var(--panel); border:1px solid var(--line); border-radius:8px;
          padding:16px 18px; display:grid; grid-template-columns:30px 1fr; gap:14px; }
  @keyframes in { to { opacity:1; transform:none } }
  @media (prefers-reduced-motion: reduce) {
    /* Order and pacing still carry the meaning; only the movement goes. */
    .step, .rule, .verdict, .w-entry { animation:none; opacity:1; transform:none; }
    .wire { transition:none; }
  }
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
  .defn { margin:-16px 0 24px; font-size:15px; color:var(--fg);
          border-left:3px solid var(--accent); padding-left:12px; }
  .future { margin-top:36px; background:var(--panel); border:1px solid var(--line);
            border-radius:8px; padding:18px 20px; }
  .future h2 { font-size:15px; margin:0 0 14px; }
  .future .cols { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:18px; }
  .future .k { font-size:11px; color:var(--dim); text-transform:uppercase;
               letter-spacing:.08em; margin-bottom:5px; }
  .future p { margin:0; font-size:14px; color:var(--dim); }
  .future .bound { margin-top:16px; padding-top:12px; border-top:1px solid var(--line);
                   font-size:13px; color:var(--dim); }
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
 <div class="story">
  <h1 data-i="title"></h1>
  <p class="lede" data-i="lede"></p>
  <p class="defn" data-i="defn"></p>
  <div class="row">
    <button class="primary" id="go" onclick="story('allow')" data-i="cta"></button>
    <button id="go2" onclick="story('ask-over-cap')" data-i="cta2"></button>
    <button id="again" onclick="location.reload()" data-i="again" style="display:none"></button>
  </div>
  <div class="steps" id="steps"></div>

  <section class="future">
    <h2 data-i="f_head"></h2>
    <div class="cols">
      <div><div class="k" data-i="f_now_k"></div><p data-i="f_now"></p></div>
      <div><div class="k" data-i="f_next_k"></div><p data-i="f_next"></p></div>
    </div>
    <p class="bound" data-i="f_bound"></p>
  </section>

  <details>
    <summary data-i="dev"></summary>
    <div class="row" style="margin-top:12px">
      <button onclick="call('/api/jobs')" data-i="d_jobs"></button>
      <button onclick="call('/api/pr')" data-i="d_pr"></button>
      <button onclick="call('/api/merchant/challenge')" data-i="d_402"></button>
      <button onclick="call('/api/merchant/challenge?broken_url=nope.md')" data-i="d_400"></button>
      <button onclick="call('/api/demo/reset', {method:'POST'})" data-i="d_reset"></button>
    </div>
    <p class="dim" style="font-size:13px" data-i="d_note"></p>
    <video src="/pilot.mp4" controls preload="none"></video>
  </details>
 </div>

 <aside class="wire">
   <h2 data-i="w_head"></h2>
   <p class="hint" id="wirehint" data-i="w_empty"></p>
   <div id="wirelog"></div>
   <div class="evidence">
     <h3 data-i="e_head"></h3>
     <dl class="w-kv">
       <dt data-i="e_rail_k"></dt><dd>x402 · Base Sepolia</dd>
       <dt data-i="e_settle_k"></dt><dd><span class="badge live">CONFIRMED</span></dd>
       <dt data-i="e_tx_k"></dt>
       <dd><a href="https://sepolia.basescan.org/tx/0x64a0a2d15d9dd4e33c419c0af1289acf30b0eea074630ab177e9760bff430834"
              target="_blank" rel="noreferrer">0x64a0a2d1…bff430834</a></dd>
     </dl>
     <p class="w-note" style="color:var(--dim)" data-i="e_note"></p>
   </div>
 </aside>
 <button id="wiretoggle" onclick="toggleWire()" data-i="w_toggle"></button>
</main>
<script>
const JA = {
  badge:"デモ用・実際のお金は動きません", lang:"English",
  title:"AIにお金を使わせたとき、誰が止めるんですか？",
  lede:"AIにwalletや課金APIを渡すと、仕事は速くなります。でも、止める人がいません。UNBLOCKは支払いの権限をAI本人から外し、金額・週の予算・相手・承認された内容を、AIが書き換えられないコードで確認します。範囲内なら自分で払って仕事を終わらせ、外れたときだけ人間に聞きます。",
  defn:"UNBLOCKは、AIのお金の使い方を守るローカルな防火壁です。",
  f_head:"どこで効くのか",
  f_now_k:"今日", f_now:"AIにagent walletやAPIの課金キー、クラウドの予算を渡した時点で、もう必要です。速く働かせるほど、止める仕組みが要ります。",
  f_next_k:"これから", f_next:"x402やTempo MPPのように、機械が機械から直接買う経路が増えるほど効いてきます。支払える agent には、必ず制御層が要ります。",
  f_bound:"正直に言うと、いま実証できているのは「支払い」の経路です。同じ考え方は他の取り消せない操作にも広げられますが、そこはまだ実装も検証もしていません。",
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
  w_head:"実際に流れているデータ",
  w_empty:"ボタンを押すと、各ステップで送受信された中身がここに順番に出ます。",
  w_402:"これは請求書であって、支払いではありません。x402では、この条件を見たクライアントが X-PAYMENT 署名を付けて再送し、そこで facilitator が on-chain の settle を行います。このpreviewはmock railなのでそこまで進みません。payTo が 0x…dEaD（burn address）、URLが testserver なのは、プロセス内で条件だけを取り出しているからで、ここからは1円も動かせません。",
  w_decide:"人間の決定はここで記録されます。state:FAILED は「支払いを許可しなかった」という意味で、仕事の失敗ではありません。次のrunが無料の代替で完了させます。",
  w_toggle:"データを見る", w_close:"閉じる",
  err_t:"途中で失敗しました", err_p:"保留していたデータは破棄しました。もう一度はじめから試してください。",
  k_amount:"金額", k_network:"ネットワーク", k_asset:"通貨", k_payto:"支払先",
  k_merchant:"相手", k_settle:"決済", k_rail:"経路", k_verdict:"判定",
  k_job:"ジョブ", k_action:"決定", k_state:"状態", k_files:"ファイル", k_count:"件数",
  v_notbroadcast:"NOT BROADCAST", v_inproc:"in-process merchant（公開URLではありません）",
  v_burn:"burn address（ここへは1円も動きません）",
  raw:"生JSON",
  e_head:"過去のlive実証（この実行とは別）",
  e_rail_k:"経路", e_settle_k:"決済", e_tx_k:"tx",
  e_note:"これはGate Cで実際にBase Sepoliaへ決済した記録です。上のログはmock railの今回の実行で、資金は動いていません。混同しないよう分けて表示しています。",
  running:"実行中…",
};
const EN = {
  badge:"DEMO — no real money moves", lang:"日本語",
  title:"You gave an AI a wallet. Who stops the spending?",
  lede:"Hand an agent a wallet or a billing key and it works faster — with nobody to stop it. UNBLOCK takes the spending authority away from the model and checks the amount, the weekly budget, the counterparty and the approved terms in code the model cannot rewrite. Inside the rules it pays and finishes the job; outside them it asks a person.",
  defn:"UNBLOCK is a local spending firewall for AI agents.",
  f_head:"Where this matters",
  f_now_k:"Today", f_now:"The moment an agent holds a wallet, a billing key or a cloud budget. The faster it works, the more it needs something that can stop it.",
  f_next_k:"Next", f_next:"As machine-to-machine rails like x402 and Tempo MPP spread. Every agent that can spend will need a control layer.",
  f_bound:"To be exact: what this code proves is the payment path. The same shape extends to other irreversible actions, but that is not built or verified here.",
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
  w_head:"what actually moved",
  w_empty:"Press a button and every request and response appears here, in order.",
  w_402:"This is an invoice, not a payment. In x402 the client retries with a signed X-PAYMENT header and the facilitator settles on-chain at that point. This preview runs on the mock rail and never gets there. payTo is 0x…dEaD (the burn address) and the URL says testserver because the terms are pulled in-process - nothing here can move a cent.",
  w_decide:"The human decision is recorded here. state:FAILED means the purchase was not authorised, not that the job failed - the next run finishes it from a free source.",
  w_toggle:"Show data", w_close:"Close",
  err_t:"The run failed part-way", err_p:"Anything held back was discarded. Start over.",
  k_amount:"Amount", k_network:"Network", k_asset:"Asset", k_payto:"Pay to",
  k_merchant:"Merchant", k_settle:"Settlement", k_rail:"Rail", k_verdict:"Verdict",
  k_job:"Job", k_action:"Decision", k_state:"State", k_files:"Files", k_count:"Count",
  v_notbroadcast:"NOT BROADCAST", v_inproc:"in-process merchant (not a public URL)",
  v_burn:"burn address (nothing can reach it)",
  raw:"raw JSON",
  e_head:"verified live run (a different run)",
  e_rail_k:"Rail", e_settle_k:"Settlement", e_tx_k:"tx",
  e_note:"A real Base Sepolia settlement from Gate C. The log above is this run, on the mock rail, where no money moved. They are kept apart on purpose.",
  running:"running…",
};
let L = localStorage.getItem("lang") === "en" ? EN : JA;
const j = (r) => r.json();

// Every request the page makes goes through here, so the side panel is a
// record of what actually moved rather than a hand-written illustration of it.
let STEP = 0;
let HELD = [];

// `defer` holds the entry back until flushWire(). One response can feed three
// things on the left (the verdict, the payment, the result), so logging it the
// instant it arrives put the outcome on the right before the story had said
// it. The record is unchanged - only the moment it is shown moves, to the beat
// of the first step that reads from it.
async function call(path, opts = {}, defer = false) {
  const response = await fetch(path, opts);
  let body = null;
  try { body = await response.clone().json(); } catch { body = "<not json>"; }
  const entry = [opts.method || "GET", path, response.status, body, STEP];
  if (defer) HELD.push(entry); else logWire(...entry);
  return body;
}

// Drains in arrival order, so holding an entry back never reorders the record.
function flushWire() {
  const queued = HELD;
  HELD = [];
  for (const entry of queued) logWire(...entry);
}

function noteFor(path) {
  if (path.startsWith("/api/merchant/challenge") && !path.includes("nope")) return L.w_402;
  if (path.includes("/decision")) return L.w_decide;
  return "";
}

// The fields worth reading first, per endpoint. Anything not summarised here
// still shows its full JSON below - the summary is a lens, never a filter.
function summarise(path, body) {
  const kv = [];
  const badge = (cls, text) => `<span class="badge ${cls}">${text}</span>`;

  if (path.startsWith("/api/merchant/challenge") && body?.payment_required) {
    const t = body.payment_required.accepts?.[0] || {};
    // USDC carries 6 decimals; show both so the raw number is not a mystery.
    const human = t.amount ? (Number(t.amount) / 1e6).toFixed(2) : "?";
    kv.push([L.k_amount, `$${human} USDC <span class="dim">(${esc(t.amount)} atomic, 6 dp)</span>`]);
    kv.push([L.k_network, `Base Sepolia <span class="dim">(${esc(t.network || "")})</span>`]);
    kv.push([L.k_asset, esc(t.asset || "")]);
    kv.push([L.k_payto, `${esc(t.payTo || "")} <span class="dim">${L.v_burn}</span>`]);
    kv.push([L.k_merchant, L.v_inproc]);
    kv.push([L.k_settle, badge("mock", L.v_notbroadcast)]);
  } else if (path.startsWith("/api/demo/run") && body?.verdicts) {
    const v = body.verdicts[0];
    if (!v) return "";
    kv.push([L.k_verdict, esc(v.status)]);
    kv.push([L.k_job, esc(v.job_id || "")]);
    kv.push([L.k_rail, `MOCK`]);
    if (v.receipt) kv.push([L.k_amount, `$${esc(v.receipt.amount)} ${esc(v.receipt.currency)}`]);
    kv.push([L.k_settle, badge("mock", L.v_notbroadcast)]);
  } else if (path.includes("/decision")) {
    kv.push([L.k_action, esc(body?.action_in_effect || "")]);
    kv.push([L.k_state, esc(body?.state || "")]);
    kv.push([L.k_settle, badge("mock", L.v_notbroadcast)]);
  } else if (Array.isArray(body)) {
    kv.push([L.k_count, String(body.length)]);
    if (body[0]?.path) kv.push([L.k_files, body.map(f => esc(f.path)).join(", ")]);
  }

  if (!kv.length) return "";
  return `<dl class="w-kv">${kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
}

function logWire(verb, path, status, body, atStep = STEP) {
  document.getElementById("wirehint").style.display = "none";
  const note = noteFor(path);
  const entry = el(`<div class="w-entry current">
      <div class="w-top">
        <span class="w-step">${atStep || "·"}</span>
        <span class="w-verb">${esc(verb)}</span>
        <span class="w-path">${esc(path)}</span>
        <span class="w-code ${status < 400 ? "ok" : "no"}">${status}</span>
      </div>
      ${summarise(path, body)}
      ${note ? `<p class="w-note">${esc(note)}</p>` : ""}
      <details><summary>${esc(L.raw)}</summary>
        <pre>${esc(JSON.stringify(body, null, 1))}</pre></details>
    </div>`);
  const log = document.getElementById("wirelog");
  // Only the newest entry is highlighted: the panel follows the story rather
  // than leaving the reader to find their place in it.
  for (const previous of log.querySelectorAll(".w-entry.current"))
    previous.classList.remove("current");
  log.appendChild(entry);
  entry.scrollIntoView({behavior: "smooth", block: "nearest"});
}
const el = (h) => { const d = document.createElement("div"); d.innerHTML = h.trim(); return d.firstChild; };
const esc = (t) => String(t).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));

// One place to end a run badly. A held response must never survive an error:
// the next story would flush somebody else's outcome into the panel.
function abortStory(error) {
  HELD = [];
  for (const id of ["go","go2"]) document.getElementById(id).disabled = false;
  const banner = el(`<div class="step ask"><div class="num">!</div><div>
      <h3>${esc(L.err_t)}</h3><p>${esc(L.err_p)}</p>
      <div class="fact mono">${esc(String(error && error.message || error))}</div></div></div>`);
  steps().appendChild(banner);
  banner.scrollIntoView({behavior: "smooth", block: "end"});
}

function toggleWire(){
  const open = document.querySelector(".wire").classList.toggle("open");
  document.getElementById("wiretoggle").textContent = open ? L.w_close : L.w_toggle;
}

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
  document.getElementById("wirelog").innerHTML = "";
  document.getElementById("wirehint").style.display = "";
  document.getElementById("again").style.display = "none";
  for (const id of ["go","go2"]) document.getElementById(id).disabled = false;
}
async function meta(){
  const h = await fetch("/health").then(j);
  document.getElementById("meta").textContent = `${h.commit.slice(0,7)} · ${h.expires_at_utc}`;
}

// The story is paced so a person can read one thing before the next arrives.
// The delay sits BEFORE each request, not after it, so the step on the left and
// its wire entry on the right appear together and neither runs ahead of the
// work it describes.
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const pace = (ms) => new Promise(r => setTimeout(r, REDUCED ? Math.min(ms, 120) : ms));
const BEAT = 800, HALF = 380;

const steps = () => document.getElementById("steps");
function add(html){ const n = el(html); steps().appendChild(n); n.scrollIntoView({behavior:"smooth", block:"end"}); return n; }
const step = (n, cls, title, body, extra="") => add(
  `<div class="step ${cls}"><div class="num">${n}</div><div>
     <h3>${esc(title)}</h3><p>${esc(body)}</p>${extra}</div></div>`);

// Append into an already-visible step, so a group of checks arrives one at a
// time rather than as a finished list.
async function reveal(node, html, wait = HALF) {
  node.querySelector("div:last-child").appendChild(el(html));
  await pace(wait);
}

let PENDING = null;

async function story(scenario){
  try { await runStory(scenario); } catch (error) { abortStory(error); }
}

async function runStory(scenario){
  for (const id of ["go","go2"]) document.getElementById(id).disabled = true;
  steps().innerHTML = "";
  document.getElementById("wirelog").innerHTML = "";
  HELD = [];   // a story never inherits anything a previous one held back
  STEP = 0;
  await call("/api/demo/reset", {method:"POST"});

  await pace(BEAT);
  STEP = 1;
  const before = await call("/api/site");
  const index = before.find(f => f.path === "index.md");
  const broken = (index.body.match(/\]\(([^)]*install[^)]*)\)/) || [null,"guides/install.md"])[1];
  step(1, "", L.s1t, L.s1p,
    `<div class="fact">index.md → <span class="mono">${esc(broken)}</span> ✕</div>`);

  const price = scenario === "allow" ? "0.05" : "0.50";
  await pace(BEAT);
  STEP = 2;
  // Ask the merchant for the terms at the price this run is about to narrate,
  // so the story and the wire log cannot disagree about what it costs.
  await call(`/api/merchant/challenge?price=${price}`);
  step(2, "", L.s2t, L.s2p,
    `<div class="fact">HTTP <span class="mono">402 Payment Required</span> ·
      ${L.k_price}: <span class="mono">$${price} USDC</span> ·
      ${L.k_shop}: <span class="mono">${esc(scenario === "ask-unknown-merchant" ? "stranger.example" : "intel.example")}</span></div>`);

  await pace(BEAT);
  const overCap = Number(price) > 0.10;
  const known = scenario !== "ask-unknown-merchant";
  const card = step(3, overCap || !known ? "ask" : "good", L.s3t, L.s3p,
    `<div class="rules"></div>`);
  const rules = card.querySelector(".rules");
  // One check at a time: the point of this step is that a rule was applied,
  // and a finished list does not show anything being applied.
  const checks = [
    [!overCap, `${L.r_cap}: $0.10 &nbsp;<span class="dim">(→ $${price})</span>`],
    [true, `${L.r_week}: $1.00`],
    [known, `${L.r_shop}: intel.example`],
  ];
  for (const [ok, text] of checks) {
    rules.appendChild(el(`<div class="rule"><span class="${ok ? "yes" : "no"}">${ok ? "✓" : "✕"}</span><span>${text}</span></div>`));
    await pace(HALF);
  }

  // Tagged 3, not 4: this response is read first by step 3's verdict. The tag
  // is what the "panel never runs ahead of the story" check compares against,
  // so it has to name the step the data is actually used by.
  STEP = 3;
  const run = await call(`/api/demo/run?scenario=${scenario}`, {method:"POST"}, true);
  const verdict = run.verdicts[0];
  const parked = verdict.status === "waiting-approval";
  // The verdict line comes from what the policy actually returned, not from a
  // restatement of it, so the screen cannot claim a decision the code did not make.
  await pace(BEAT);
  card.querySelector("div:last-child").appendChild(
    el(`<div class="verdict ${parked ? "ask" : "pay"}">${parked ? L.v_ask : L.v_pay}</div>`));
  flushWire();   // the response reaches the panel as the verdict it produced appears
  STEP = 4;
  await pace(BEAT);

  if (parked) {
    PENDING = {job: verdict.job_id, scenario, before: index.body, price};
    step(4, "ask", L.s4t_ask, L.s4p_ask, `
      <div class="fact"><b>${L.decide}</b> — $${price} USDC → intel.example</div>
      <div class="row" style="margin-top:12px">
        <button class="approve" onclick="decide('APPROVE')">${L.approve}</button>
        <button class="reject" onclick="decide('REJECT')">${L.reject}</button>
      </div>`);
    return;   // nothing further is generated until a human chooses
  }
  await paid(verdict, index.body, price);
}

async function decide(action){
  try { await runDecision(action); } catch (error) { abortStory(error); }
}

async function runDecision(action){
  const {job, scenario, before, price} = PENDING;
  for (const b of document.querySelectorAll(".approve,.reject")) b.disabled = true;
  STEP = 4;
  await call(`/approval/v1/approvals/${job}/decision`, {
    method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({action})});
  await pace(BEAT);
  const run = await call(`/api/demo/run?scenario=${scenario}`, {method:"POST"}, true);
  await paid(run.verdicts[0], before, action === "APPROVE" ? price : null);
}

async function paid(verdict, beforeBody, price){
  const free = verdict.status === "done-free";
  if (!free && price) {
    await pace(BEAT);
    // The badge belongs on this side too: the story column is what gets
    // filmed and screenshotted, and a receipt id next to a dollar amount
    // reads as a real payment once it is cropped out of the page.
    step(4, "good", L.s4t_pay, L.s4p_pay,
      `<div class="fact"><span class="mono">${esc(verdict.receipt?.tx || "")}</span> ·
        $${verdict.receipt?.amount || price} ${esc(verdict.receipt?.currency || "USDC")}
        <span class="badge mock" style="margin-left:6px">${esc(L.v_notbroadcast)}</span></div>`);
    flushWire();   // same tick as the step it belongs to
  }

  await pace(BEAT);
  STEP = 5;
  // Held as well: on the rejected path the run response carries done-free, and
  // showing that before step 5 is drawn tells the ending early - the same fault
  // the paid path had, one branch over.
  const after = await call("/api/site", {}, true);
  const afterIndex = after.find(f => f.path === "index.md").body;
  // The line that actually moved, not the first link on the page: index.md
  // lists two links and only one of them was broken.
  const bLines = beforeBody.split("\n"), aLines = afterIndex.split("\n");
  const at = bLines.findIndex((line, n) => line !== aLines[n]);
  const bLine = (bLines[at] ?? "").trim(), aLine = (aLines[at] ?? "").trim();
  const prs = await call("/api/pr", {}, true);

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
  flushWire();   // run (if still held), site and pr, in the same tick as step 5
  document.getElementById("again").style.display = "inline-block";
}

paint(); meta();
</script></body></html>
"""
