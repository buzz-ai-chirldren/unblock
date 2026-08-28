"""Owner preview: the real UNBLOCK code behind one URL, on the mock rail.

This exists so a human can drive the demo from a browser and a terminal before
we film it. It adds NO business logic: the pipeline, the unblock, the policy and
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
  UNBLOCK_PREVIEW_TOKEN=<token> uv run uvicorn demo.preview_app:app --port 8410
Env:
  UNBLOCK_PREVIEW_TOKEN   required, the owner's bearer token
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
    HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse,
)

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from unblock.approval_api import create_app  # noqa: E402
from unblock import Unblock  # noqa: E402
from unblock import Ledger  # noqa: E402
from unblock.policy import Policy  # noqa: E402
from unblock.rails import FileRail  # noqa: E402
from unblock.demo_pipeline import Incident, IncidentPipeline, IntelOffer, detect  # noqa: E402

# --- guards ----------------------------------------------------------------

FORBIDDEN_ENV = (
    "BEDROCK_KEY_FILE", "UNBLOCK_WALLET_FILE", "AWS_ACCESS_KEY_ID",
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

TOKEN = os.environ.get("UNBLOCK_PREVIEW_TOKEN") or ""
if len(TOKEN) < 24:
    raise RuntimeError("UNBLOCK_PREVIEW_TOKEN must be set and at least 24 chars")

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
VENDOR = "threat-intel.example"
OFFER = IntelOffer(VENDOR, Decimal("0.05"), url=f"http://{VENDOR}/intel")
BIG_OFFER = IntelOffer(VENDOR, Decimal("0.50"), url=f"http://{VENDOR}/intel")
UNKNOWN_OFFER = IntelOffer("stranger.example", Decimal("0.05"), url="http://stranger.example/intel")
POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("1.00"),
    per_invoice_cap=Decimal("0.10"),
    merchant_allowlist=frozenset({OFFER.merchant}),
)
# Preview-only fixtures. The Gate C demo keeps its own; see
# fixtures/README_preview.md for why the preview does not reuse them.
PREVIEW_SITE = REPO / "fixtures" / "preview_site"
PREVIEW_INTEL = REPO / "fixtures" / "preview_intel.json"
UNREVIEWED = "vendor/quickparse-0.4.1.md"
CLEARED = "vendor/quickparse-0.4.3.md"        # what the paid analysis clears
QUARANTINED = "vendor/quickparse-quarantined.md"   # where refusing to pay lands

INTEL_RECORD = json.dumps(json.loads(PREVIEW_INTEL.read_text())[UNREVIEWED])

# Refusing to pay must not land where paying lands, or the $0.05 buys nothing.
# Without the analysis nobody knows what 0.4.1 does, so the only safe move is to
# switch the dependency off: the build still ships, the feature does not. The
# paid path keeps the feature by moving to the version the analysis cleared.
FREE_SOURCES = {UNREVIEWED: QUARANTINED}

SCENARIOS = {
    # label -> (offer, what the human should expect to see)
    "allow": (OFFER, "under the cap: UNBLOCK pays on the mock rail, no human needed"),
    "ask-over-cap": (BIG_OFFER, "$0.50 exceeds the $0.10 cap: parks for approval"),
    "ask-unknown-merchant": (UNKNOWN_OFFER, "merchant not allowlisted: parks for approval"),
}


def _site() -> Path:
    site = RUN_DIR / "site"
    if not site.exists():
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copytree(PREVIEW_SITE, site)
    return site


def _rail() -> FileRail:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    return FileRail(RUN_DIR / "rail.db", paid_body=INTEL_RECORD)


def _unblock_factory():
    # Reading the ledger before anything has been run is a normal first move
    # for a human poking at the preview; sqlite will not create a database in
    # a directory that does not exist yet.
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    return Unblock(Ledger(RUN_DIR / "ledger.db"), POLICY, _rail())


def _pipeline(offer: IntelOffer) -> Unblock:
    policy = POLICY
    return IncidentPipeline(
        site_dir=_site(),
        allowed_file="release.md",
        unblock_factory=lambda: Unblock(Ledger(RUN_DIR / "ledger.db"), policy, _rail()),
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
approval = create_app(_unblock_factory, tokens={"owner": TOKEN})
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

    os.environ["INTEL_DB_FILE"] = str(PREVIEW_INTEL)
    os.environ["INTEL_DESCRIPTION"] = (
        "Threat intelligence report for an unreviewed dependency"
    )
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
def merchant_challenge(broken_url: str = UNREVIEWED, price: str = "0.05") -> dict:
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


@app.get("/api/analysis")
def analysis(job_id: str) -> dict:
    """The record this job actually paid for, read back out of the ledger.

    Not a copy of the fixture: UNBLOCK stores what the rail returned, and
    `pipeline._replacement_from` is handed exactly this object. Without it the
    screen claims a threat report was bought while nothing on the page ever
    shows one - the report's whole value is that it names what the package was
    doing, and that was invisible.

    Empty when nothing was bought, which is the honest state of the rejected
    path: you do not have the analysis, because you did not buy it.
    """
    unblock = _unblock_factory()
    try:
        job = unblock.ledger.job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")
        invoice = unblock.ledger.invoice_row(job["merchant"] or "", job["invoice_id"] or "")
        receipt = unblock.ledger.receipt(invoice) if invoice else None
        if not receipt or not receipt.get("resource"):
            return {"purchased": False, "analysis": None}
        try:
            record = json.loads(receipt["resource"])
        except (json.JSONDecodeError, TypeError):
            return {"purchased": False, "analysis": None}
        return {"purchased": True, "analysis": record}
    finally:
        unblock.ledger.close()


@app.get("/api/jobs")
def jobs() -> list[dict]:
    """Every job in the preview ledger, newest first."""
    unblock = _unblock_factory()
    try:
        rows = unblock.ledger.conn.execute(
            "SELECT job_id, state, merchant, invoice_id FROM jobs ORDER BY rowid DESC"
        ).fetchall()
        return [
            {"job_id": r[0], "state": r[1], "merchant": r[2], "invoice_id": r[3]}
            for r in rows
        ]
    finally:
        unblock.ledger.close()


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
<meta name="robots" content="noindex"><title>UNBLOCK</title>
<style>
  :root { color-scheme: dark; --bg:#0d1117; --panel:#161b22; --line:#30363d;
          --fg:#e6edf3; --dim:#8b949e; --accent:#58a6ff;
          --risk:#f85149; --pay:#d29922; --rule:#58a6ff; --safe:#3fb950; --off:#6e7681; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:15px/1.6 -apple-system,BlinkMacSystemFont,"Hiragino Sans","Noto Sans JP",sans-serif; }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  header { padding:12px 20px; border-bottom:1px solid var(--line); display:flex;
           gap:10px; align-items:center; font-size:13px; }
  header b { font-size:14px; }
  .spacer { flex:1 } .dim { color:var(--dim); }
  .tag { background:var(--pay); color:#000; padding:2px 7px; border-radius:3px;
         font-weight:700; font-size:11px; }
  button { background:#21262d; color:var(--fg); border:1px solid var(--line);
           border-radius:6px; padding:8px 14px; cursor:pointer; font:inherit; }
  button:hover:not(:disabled){ border-color:#6e7681; } button:disabled{ opacity:.4; cursor:default; }
  button.primary { background:#238636; border-color:#2ea043; font-weight:600;
                   font-size:16px; padding:12px 22px; }
  button.link { background:none;border:none;color:var(--accent);padding:0;
                text-decoration:underline;font-size:13px; }
  /* 1280, not 1180: at 1180 the left column was 816px while the finished
     five-node chain measures 871px, so the row auto-scrolled and clipped
     the first node once the last one landed. Narrower viewports still
     scroll - that is the graceful case - but a desktop must fit it. */
  main { padding:26px 20px 70px; max-width:1280px; margin:0 auto;
         display:grid; grid-template-columns:minmax(0,1fr) 300px; gap:24px; align-items:start; }
  @media (max-width:1000px){ main{ grid-template-columns:minmax(0,1fr); } }
  h1 { font-size:24px; margin:0 0 6px; }
  .sub { color:var(--dim); margin:0 0 22px; font-size:15px; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }

  /* the flow */
  /* One line, always. Wrapping put the newest node alone on a second row with
     a dangling arrow, which reads as two flows rather than one. */
  .flow { margin-top:30px; display:flex; align-items:stretch; gap:10px;
          flex-wrap:nowrap; overflow-x:auto; padding-bottom:6px; }
  .step { flex:0 0 auto; display:flex; align-items:center; gap:10px;
          opacity:0; transform:translateY(6px); animation:in .3s ease forwards; }
  @keyframes in { to { opacity:1; transform:none } }
  .node { border:1px solid var(--line); border-radius:10px; background:var(--panel);
          padding:14px 16px; min-width:150px; transition:padding .25s, min-width .25s; }
  .node .ico { font-size:20px; line-height:1; }
  .node .lab { font-size:13px; color:var(--dim); margin-top:6px; }
  .node .val { font-size:17px; font-weight:600; margin-top:2px; word-break:break-all; }
  /* Finished nodes shrink but keep their value: the point of the final frame
     is that the whole chain is still readable - what was found, what it cost,
     what it became. Hiding it left a row of ticks that says nothing. */
  .step.done .node { padding:9px 12px; min-width:0; }
  .step.done .node .lab { display:none; }
  .step.done .node .val { font-size:13px; font-weight:500; color:var(--dim); margin-top:4px; }
  .step.done .node .ico { font-size:15px; }
  .step.done .node .ico::after { content:" ✓"; color:var(--safe); font-size:12px; }
  .step.done .chips { display:none; }
  .arrow { color:var(--line); font-size:20px; align-self:center; }
  .t-risk .node { border-color:var(--risk); box-shadow:inset 3px 0 0 var(--risk); }
  .t-pay  .node { border-color:var(--pay);  box-shadow:inset 3px 0 0 var(--pay); }
  .t-rule .node { border-color:var(--rule); box-shadow:inset 3px 0 0 var(--rule); }
  .t-safe .node { border-color:var(--safe); box-shadow:inset 3px 0 0 var(--safe); }
  .t-ask  .node { border-color:#db6d28;     box-shadow:inset 3px 0 0 #db6d28; }
  .t-off  .node { border-color:var(--off);  box-shadow:inset 3px 0 0 var(--off); }
  .chips { display:flex; gap:6px; margin-top:9px; }
  .rule { font-size:12px; padding:2px 7px; border-radius:99px; border:1px solid var(--line);
          opacity:0; animation:in .25s ease forwards; }
  .rule.yes { color:var(--safe); border-color:#2ea043; }
  .rule.no  { color:var(--pay);  border-color:#9e7615; }
  .verdict { display:none; }

  /* the one decision */
  .decide { margin-top:26px; padding:18px; border:1px solid #db6d28; border-radius:10px;
            background:#2a1a0b; }
  .decide .q { font-size:17px; font-weight:600; margin-bottom:14px; }
  .decide button { font-size:17px; padding:14px 26px; font-weight:600; }
  .approve { background:#238636; border-color:#2ea043; }
  .reject  { background:#4a1f1f; border-color:#6e2b2b; }

  /* the result */
  .result { margin-top:26px; }
  .diff { border:1px solid var(--line); border-radius:8px; overflow:hidden; font-size:13px; }
  .diff div { padding:6px 12px; }
  .diff .del { background:#3a1414; color:#ffa198; }
  .diff .add { background:#12321c; color:#7ee787; }
  .summary { margin-top:12px; display:flex; gap:10px; flex-wrap:wrap; }
  .cell { background:var(--panel); border:1px solid var(--line); border-radius:8px;
          padding:10px 14px; }
  .cell .k { font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:.07em; }
  .cell .v { font-size:17px; font-weight:600; margin-top:2px; }
  .badge { display:inline-block; padding:1px 6px; border-radius:3px; font-size:10px;
           font-weight:700; }
  .badge.mock { background:#3a2d09; color:var(--pay); border:1px solid #9e7615; }
  .badge.live { background:#12321c; color:var(--safe); border:1px solid #2ea043; }

  /* the panel */
  .wire { position:sticky; top:14px; background:var(--panel); border:1px solid var(--line);
          border-radius:10px; max-height:calc(100vh - 28px); overflow:auto; }
  .wire > h2 { font-size:11px; margin:0; padding:10px 13px; color:var(--dim);
               text-transform:uppercase; letter-spacing:.08em;
               border-bottom:1px solid var(--line); display:flex; align-items:center; gap:8px; }
  .wire .hint { padding:12px 13px; color:var(--dim); font-size:12px; margin:0; }
  .w-entry { border-bottom:1px solid var(--line); padding:9px 13px; font-size:12px; }
  .w-entry:last-child { border-bottom:none; }
  .w-top { display:flex; gap:6px; align-items:center; font-family:ui-monospace,Menlo,monospace; }
  .w-step { width:17px;height:17px;border-radius:50%;background:#21262d;border:1px solid var(--line);
            display:grid;place-items:center;font-size:10px;color:var(--dim);flex:none; }
  .w-verb { color:var(--accent); } .w-path { color:var(--fg); flex:1; word-break:break-all; }
  .w-code { padding:0 5px;border-radius:3px;font-weight:600; }
  .w-code.ok { background:#12321c;color:var(--safe); } .w-code.no { background:#3a1414;color:var(--risk); }
  .w-kv { margin:7px 0 0; display:grid; grid-template-columns:auto 1fr; gap:2px 8px; font-size:12px; }
  .w-kv dt { color:var(--dim); white-space:nowrap; } .w-kv dd { margin:0; word-break:break-all; }
  .w-note { margin:7px 0 0; font-size:11px; color:var(--pay); line-height:1.5; }
  .w-entry details { margin:6px 0 0; } .w-entry summary { font-size:11px; color:var(--dim); }
  .w-entry pre { margin:6px 0 0; background:#0d1117; border:1px solid var(--line);
                 border-radius:5px; padding:9px; overflow:auto; max-height:200px;
                 font-size:11px; white-space:pre-wrap; word-break:break-word; }
  .w-entry.current { background:#11161d; box-shadow:inset 2px 0 0 var(--accent); }
  /* collapsed by default: one line each, no detail */
  .wire.slim .w-kv, .wire.slim .w-note, .wire.slim .w-entry details { display:none; }
  .evidence { border-top:1px solid var(--line); padding:11px 13px; font-size:12px; }
  .evidence a { color:var(--accent); }
  .wire.slim .evidence { display:none; }

  #wiretoggle { display:none; }
  @media (max-width:1000px){
    #wiretoggle { display:block; position:fixed; left:0; right:0; bottom:0; z-index:21;
                  border-radius:0; border-left:none; border-right:none; border-bottom:none;
                  padding:11px; font-weight:600; }
    main { padding-bottom:64px; }
    /* top:auto matters: the sticky rule above sets top:14px, and on a fixed
       element top wins over bottom - the drawer stayed a third on screen. */
    .wire { position:fixed; top:auto; left:0; right:0; bottom:44px; z-index:20;
            max-height:70vh; border-radius:12px 12px 0 0;
            transform:translateY(calc(101% + 44px)); transition:transform .22s ease; }
    .wire.open { transform:none; }
  }
  @media (max-width:700px){
    /* Stacked, not scrolled sideways. A horizontal scroller lands the reader on
       the last node with the previous four off-screen, which is the opposite of
       a chain you can take in at a glance. */
    .flow { flex-direction:column; align-items:stretch; overflow-x:visible; gap:6px; }
    /* The arrow sits above its node rather than beside it, so every node starts
       at the same left edge - beside it, the first node was the only one
       without an arrow and stood out of line. */
    .step { flex-direction:column; align-items:stretch; gap:2px; }
    .step .arrow { transform:rotate(90deg); margin-left:20px; }
    .node { width:100%; }
    #meta { display:none; }
  }
  @media (prefers-reduced-motion: reduce){
    .step, .rule, .w-entry { animation:none; opacity:1; transform:none; }
    .wire, .node { transition:none; }
  }
</style></head><body>
<header>
  <b>UNBLOCK</b><span class="tag" data-i="badge"></span>
  <span class="spacer"></span>
  <button class="link" id="lang" onclick="toggleLang()"></button>
  <span class="dim" id="meta"></span>
</header>
<main>
 <div>
  <h1 data-i="title"></h1>
  <p class="sub" data-i="sub"></p>
  <div class="row">
    <button class="primary" id="go" onclick="story('allow')" data-i="cta"></button>
    <button id="go2" onclick="story('ask-over-cap')" data-i="cta2"></button>
    <button id="again" onclick="location.reload()" data-i="again" style="display:none"></button>
  </div>
  <div class="flow" id="steps"></div>
  <div id="tail"></div>
  <p class="dim" style="margin-top:34px;font-size:12px" data-i="bound"></p>
 </div>

 <aside class="wire slim" id="wire">
   <h2><span data-i="w_head"></span><span class="spacer"></span>
       <button class="link" onclick="toggleEvidence()" id="evtoggle" data-i="w_more"></button></h2>
   <p class="hint" id="wirehint" data-i="w_empty"></p>
   <div id="wirelog"></div>
   <div class="evidence">
     <div class="dim" data-i="e_head"></div>
     <div style="margin-top:5px">x402 · Base Sepolia <span class="badge live">CONFIRMED</span></div>
     <a href="https://sepolia.basescan.org/tx/0xa6b5b1d37e27c1e227de99688092e884164064f9897f8845b2fc1981c877024a"
        target="_blank" rel="noreferrer">0xa6b5b1d3…c877024a</a>
     <p class="w-note" style="color:var(--dim)" data-i="e_note"></p>
   </div>
 </aside>
 <button id="wiretoggle" onclick="toggleWire()" data-i="w_toggle"></button>
</main>
<script>
const JA = {
  badge:"デモ用fixture・実際のお金は動きません・NOT BROADCAST", lang:"English",
  title:"AIのお金の使い方を守る、ローカルな防火壁。",
  sub:"未評価の部品を見つけた → 少額で調べた → 安全に直した。",
  cta:"やってみる", cta2:"上限超過なら", again:"もう一度",
  n1:"未評価", n2:"解析", n3:"予算内", n3_ask:"ASK・上限超過",
  n4:"支払い済", n5:"安全版へ", n5_off:"隔離",
  decide:"UNBLOCK policy: ASK — $0.50 は 1 件あたり上限 $0.10 を超えています。",
  decide_sub:"agent は止まっています。再開できるのは人間の決定だけです。",
  approve:"承認（支払う）", reject:"却下（支払わない）",
  k_paid:"支払い", k_left:"残り", k_pr:"証拠", nopay:"なし",
  k_amount:"金額", k_shop:"相手", k_settle:"決済", k_verdict:"判定",
  k_observed:"送信先", k_cleared:"安全版", k_action:"決定",
  v_notbroadcast:"NOT BROADCAST",
  w_head:"実データ", w_more:"証拠を見る", w_less:"畳む",
  w_empty:"押すと、やり取りがここに出ます。",
  w_402:"これは請求書で、支払いではありません。payTo は burn address、相手は公開URLではない in-process merchant なので、ここから1円も動きません。",
  w_decide:"FAILED は「支払いを許可しなかった」です。仕事の失敗ではありません。",
  bound:"実証済みは支払いの経路だけです。",
  w_toggle:"データ", w_close:"閉じる",
  e_head:"過去のLIVE実証（別の実行）",
  e_note:"Gate A で実際に決済した記録です（再現手順は docs/gate-a-evidence.md）。上は mock の今回分で、資金は動いていません。",
  err_t:"失敗しました", err_p:"保留は破棄しました。",
  raw:"生JSON",
};
const EN = {
  badge:"DEMO FIXTURE · no real money · NOT BROADCAST", lang:"日本語",
  title:"A local spending firewall for AI agents.",
  sub:"Found an unreviewed package → bought one analysis → fixed it safely.",
  cta:"Run it", cta2:"Over the cap", again:"Again",
  n1:"Unreviewed", n2:"Analysis", n3:"In budget", n3_ask:"ASK · over cap",
  n4:"Paid", n5:"Safe version", n5_off:"Quarantined",
  decide:"UNBLOCK policy: ASK — $0.50 exceeds the $0.10 per-request cap.",
  decide_sub:"The agent is stopped. Only a human decision can restart it.",
  approve:"Approve", reject:"Reject",
  k_paid:"Paid", k_left:"Left", k_pr:"Evidence", nopay:"none",
  k_amount:"Amount", k_shop:"Merchant", k_settle:"Settlement", k_verdict:"Verdict",
  k_observed:"Posting to", k_cleared:"Cleared", k_action:"Decision",
  v_notbroadcast:"NOT BROADCAST",
  w_head:"live data", w_more:"evidence", w_less:"collapse",
  w_empty:"Press a button and the exchange appears here.",
  w_402:"An invoice, not a payment. payTo is the burn address and the merchant is in-process, not a public URL - nothing here can move a cent.",
  w_decide:"FAILED means the purchase was not authorised, not that the job failed.",
  bound:"Only the payment path is proven.",
  w_toggle:"Data", w_close:"Close",
  e_head:"verified live run (a different run)",
  e_note:"A real Gate A settlement, reproduced in docs/gate-a-evidence.md. Above is this mock run, where no money moved.",
  err_t:"The run failed", err_p:"Anything held back was discarded.",
  raw:"raw JSON",
};
let L = localStorage.getItem("lang") === "en" ? EN : JA;
const j = (r) => r.json();
const el = (h) => { const d = document.createElement("div"); d.innerHTML = h.trim(); return d.firstChild; };
const esc = (t) => String(t).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));

let STEP = 0;
let HELD = [];

async function call(path, opts = {}, defer = false) {
  const response = await fetch(path, opts);
  let body = null;
  try { body = await response.clone().json(); } catch { body = "<not json>"; }
  const entry = [opts.method || "GET", path, response.status, body, STEP];
  if (defer) HELD.push(entry); else logWire(...entry);
  return body;
}
function flushWire() {
  const queued = HELD; HELD = [];
  for (const entry of queued) logWire(...entry);
}
function noteFor(path) {
  if (path.startsWith("/api/merchant/challenge") && !path.includes("nope")) return L.w_402;
  if (path.includes("/decision")) return L.w_decide;
  return "";
}
// At most four rows: the panel is a glance, the raw JSON is the detail.
function summarise(path, body) {
  const kv = [];
  const badge = `<span class="badge mock">${L.v_notbroadcast}</span>`;
  if (path.startsWith("/api/merchant/challenge") && body?.payment_required) {
    const t = body.payment_required.accepts?.[0] || {};
    kv.push([L.k_amount, `$${(Number(t.amount || 0) / 1e6).toFixed(2)} USDC`]);
    kv.push([L.k_shop, "threat-intel.example"]);
    kv.push([L.k_settle, badge]);
  } else if (path.startsWith("/api/demo/run") && body?.verdicts?.[0]) {
    const v = body.verdicts[0];
    kv.push([L.k_verdict, esc(v.status)]);
    if (v.receipt) kv.push([L.k_amount, `$${esc(v.receipt.amount)}`]);
    kv.push([L.k_settle, badge]);
  } else if (path.startsWith("/api/analysis")) {
    if (!body?.purchased) return "";
    kv.push([L.k_observed, esc(body.analysis?.final_url || "")]);
    kv.push([L.k_cleared, esc(body.analysis?.suggested_replacement || "")]);
  } else if (path.includes("/decision")) {
    kv.push([L.k_action, esc(body?.action_in_effect || "")]);
    kv.push([L.k_settle, badge]);
  } else return "";
  return `<dl class="w-kv">${kv.slice(0, 4).map(([k, v]) =>
    `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
}
function logWire(verb, path, status, body, atStep = STEP) {
  document.getElementById("wirehint").style.display = "none";
  const note = noteFor(path);
  const entry = el(`<div class="w-entry current">
      <div class="w-top"><span class="w-step">${atStep || "·"}</span>
        <span class="w-verb">${esc(verb)}</span><span class="w-path">${esc(path)}</span>
        <span class="w-code ${status < 400 ? "ok" : "no"}">${status}</span></div>
      ${summarise(path, body)}
      ${note ? `<p class="w-note">${esc(note)}</p>` : ""}
      <details><summary>${esc(L.raw)}</summary>
        <pre>${esc(JSON.stringify(body, null, 1))}</pre></details>
    </div>`);
  const log = document.getElementById("wirelog");
  for (const previous of log.querySelectorAll(".w-entry.current"))
    previous.classList.remove("current");
  log.appendChild(entry);
  entry.scrollIntoView({behavior: "smooth", block: "nearest"});
}

const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const pace = (ms) => new Promise(r => setTimeout(r, REDUCED ? Math.min(ms, 120) : ms));
const BEAT = 800, HALF = 380;
const steps = () => document.getElementById("steps");

// One line of text per node: an icon, what it is, what it says.
function node(n, tone, ico, label, value, extra = "") {
  for (const previous of steps().querySelectorAll(".step:not(.done)"))
    previous.classList.add("done");
  const wrap = el(`<div class="step t-${tone}" data-n="${n}">
      ${n > 1 ? `<span class="arrow">→</span>` : ""}
      <div class="node"><div class="ico">${ico}</div>
        <div class="lab">${esc(label)}</div>
        <div class="val">${value}</div>${extra}</div>
    </div>`);
  steps().appendChild(wrap);
  wrap.scrollIntoView({behavior: "smooth", block: "nearest", inline: "end"});
  return wrap;
}

function toggleEvidence() {
  const wire = document.getElementById("wire");
  const slim = wire.classList.toggle("slim");
  document.getElementById("evtoggle").textContent = slim ? L.w_more : L.w_less;
}
function toggleWire() {
  const open = document.getElementById("wire").classList.toggle("open");
  document.getElementById("wiretoggle").textContent = open ? L.w_close : L.w_toggle;
}
function abortStory(error) {
  HELD = [];
  for (const id of ["go","go2"]) document.getElementById(id).disabled = false;
  document.getElementById("tail").appendChild(el(
    `<div class="decide"><div class="q">${esc(L.err_t)}</div>
       <div class="dim">${esc(L.err_p)}</div>
       <div class="mono" style="margin-top:8px">${esc(String(error && error.message || error))}</div></div>`));
}

function paint(){
  document.documentElement.lang = L === JA ? "ja" : "en";
  document.getElementById("lang").textContent = L.lang;
  for (const n of document.querySelectorAll("[data-i]")) n.textContent = L[n.dataset.i] ?? "";
  const wire = document.getElementById("wire");
  document.getElementById("evtoggle").textContent =
    wire.classList.contains("slim") ? L.w_more : L.w_less;
}
function toggleLang(){
  L = (L === JA) ? EN : JA;
  localStorage.setItem("lang", L === EN ? "en" : "ja");
  paint();
  steps().innerHTML = ""; document.getElementById("tail").innerHTML = "";
  document.getElementById("wirelog").innerHTML = "";
  document.getElementById("wirehint").style.display = "";
  document.getElementById("again").style.display = "none";
  for (const id of ["go","go2"]) document.getElementById(id).disabled = false;
}
async function meta(){
  const h = await fetch("/health").then(j);
  document.getElementById("meta").textContent = `${h.commit.slice(0,7)} · ${h.expires_at_utc}`;
}

let PENDING = null;

async function story(scenario){
  try { await runStory(scenario); } catch (error) { abortStory(error); }
}

async function runStory(scenario){
  for (const id of ["go","go2"]) document.getElementById(id).disabled = true;
  steps().innerHTML = ""; document.getElementById("tail").innerHTML = "";
  document.getElementById("wirelog").innerHTML = "";
  HELD = []; STEP = 0;
  await call("/api/demo/reset", {method:"POST"});

  await pace(BEAT);
  STEP = 1;
  const before = await call("/api/site");
  const doc = before.find(f => f.path === "release.md");
  node(1, "risk", "📦", L.n1, `<span class="mono">quickparse 0.4.1</span>`);

  const price = scenario === "allow" ? "0.05" : "0.50";
  await pace(BEAT);
  STEP = 2;
  await call(`/api/merchant/challenge?price=${price}`);
  node(2, "pay", "🔒", L.n2, `<span class="mono">$${price}</span>`);

  await pace(BEAT);
  const overCap = Number(price) > 0.10;
  // Drawn with the rules it is about to apply; the wording and the colour are
  // set from what the policy actually returned, a beat later.
  const card = node(3, "rule", "🛡️", L.n3, `<span class="mono">$0.10 / $1.00</span>`,
                    `<div class="chips"></div>`);
  const chips = card.querySelector(".chips");
  for (const [ok, text] of [[!overCap, "$0.10"], [true, "$1.00"],
                            [scenario !== "ask-unknown-merchant", "🏪"]]) {
    chips.appendChild(el(`<span class="rule ${ok ? "yes" : "no"}">${ok ? "✓" : "✕"} ${text}</span>`));
    await pace(HALF);
  }

  STEP = 4;
  const run = await call(`/api/demo/run?scenario=${scenario}`, {method:"POST"}, true);
  const verdict = run.verdicts[0];
  const parked = verdict.status === "waiting-approval";
  card.classList.remove("t-rule");
  card.classList.add(parked ? "t-ask" : "t-rule");
  card.querySelector(".ico").textContent = parked ? "🙋" : "🛡️";
  card.querySelector(".lab").textContent = parked ? L.n3_ask : L.n3;
  await pace(BEAT);

  if (parked) {
    PENDING = {job: verdict.job_id, scenario, before: doc.body, price};
    document.getElementById("tail").appendChild(el(`<div class="decide">
        <div class="q">${esc(L.decide)}</div>
        <div class="dim" style="margin-top:4px">${esc(L.decide_sub)}</div>
        <div class="row">
          <button class="approve" onclick="decide('APPROVE')">${esc(L.approve)}</button>
          <button class="reject" onclick="decide('REJECT')">${esc(L.reject)}</button>
        </div></div>`));
    flushWire();
    return;
  }
  await paid(verdict, doc.body, price);
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
  document.getElementById("tail").innerHTML = "";
  await paid(run.verdicts[0], before, action === "APPROVE" ? price : null);
}

async function paid(verdict, beforeBody, price){
  const free = verdict.status === "done-free";
  if (!free && price) {
    node(4, "safe", "💳", L.n4,
      `<span class="mono">$${esc(verdict.receipt?.amount || price)}</span>
       <span class="badge mock">${esc(L.v_notbroadcast)}</span>`);
    flushWire();
    await pace(BEAT);
  }

  STEP = 5;
  if (!free && price) await call(`/api/analysis?job_id=${encodeURIComponent(verdict.job_id)}`, {}, true);
  const after = await call("/api/site", {}, true);
  const afterIndex = after.find(f => f.path === "release.md").body;
  const bLines = beforeBody.split("\n"), aLines = afterIndex.split("\n");
  const at = bLines.findIndex((line, n) => line !== aLines[n]);
  const bLine = (bLines[at] ?? "").trim(), aLine = (aLines[at] ?? "").trim();
  const prs = await call("/api/pr", {}, true);

  node(5, free ? "off" : "safe", free ? "🚫" : "✅", free ? L.n5_off : L.n5,
       `<span class="mono">${esc(free ? "quarantined" : "quickparse 0.4.3")}</span>`);
  document.getElementById("tail").appendChild(el(`<div class="result">
      <div class="diff">
        <div class="del">− ${esc(bLine)}</div>
        <div class="add">+ ${esc(aLine)}</div>
      </div>
      <div class="summary">
        <div class="cell"><div class="k">${esc(L.k_paid)}</div><div class="v">${
          free || !price ? esc(L.nopay) : "$" + esc(verdict.receipt?.amount || price)}</div></div>
        <div class="cell"><div class="k">${esc(L.k_left)}</div><div class="v">0</div></div>
        <div class="cell"><div class="k">${esc(L.k_pr)}</div><div class="v mono" style="font-size:13px">${
          esc(prs[0]?.name || "—")}</div></div>
      </div></div>`));
  flushWire();
  document.getElementById("again").style.display = "inline-block";
}

paint(); meta();
</script></body></html>
"""
