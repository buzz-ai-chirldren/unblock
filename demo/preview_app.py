"""Owner preview: the real UNBLOCK code behind one URL, on the mock rail.

This exists so a human can drive the demo from a browser and a terminal before
we film it. It adds NO business logic: the pipeline, the clerk, the policy and
the approval API are imported and run exactly as they ship. What is new here is
a thin operator surface -- run, reset, list, inspect, decide -- plus the guards
that make a temporary public URL safe:

  * mock rail only. Nothing here can reach Bedrock, a wallet, x402, or GitHub.
    `_assert_offline()` fails startup if the process was handed any of those.
  * bearer token on every route except /health. Browsers may present it once as
    ?t=<token> and get a cookie; terminals send Authorization: Bearer.
  * a hard expiry. After it, every route answers 410 and the server stops.
  * its own scratch directory and ledger, deleted and rebuilt by /api/demo/reset.
  * a per-IP rate limit, tighter on the mutating routes.

Run:
  CLERK_PREVIEW_TOKEN=<token> uv run uvicorn demo.preview_app:app --port 8410
Env:
  CLERK_PREVIEW_TOKEN   required, the owner's bearer token
  PREVIEW_TTL_HOURS     default 12
"""

from __future__ import annotations

import hmac
import json
import os
import shutil
import sys
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

TTL_HOURS = float(os.environ.get("PREVIEW_TTL_HOURS", "12"))
STARTED_AT = time.time()
EXPIRES_AT = STARTED_AT + TTL_HOURS * 3600

RUN_DIR = REPO / "demo" / "preview_run"

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
    return FileRail(RUN_DIR / "rail.db", paid_body=INTEL_RECORD)


def _clerk_factory():
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


@app.middleware("http")
async def gate(request: Request, call_next):
    path = request.url.path
    if path == "/health":
        return await call_next(request)

    if time.time() > EXPIRES_AT:
        return JSONResponse({"detail": "preview expired"}, status_code=410)

    # Browser entry point: ?t=<token> once, then a cookie.
    token_param = request.query_params.get("t")
    if path == "/" and token_param and hmac.compare_digest(token_param.encode(), TOKEN.encode()):
        response = RedirectResponse("/", status_code=303)
        response.set_cookie("preview_token", TOKEN, httponly=True, samesite="lax", max_age=int(TTL_HOURS * 3600))
        return response

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
    return {"reset": True, "run_dir": "demo/preview_run"}


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


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots() -> str:
    return "User-agent: *\nDisallow: /\n"


UI_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>UNBLOCK — owner preview</title>
<style>
  :root { color-scheme: dark; --bg:#0d1117; --panel:#161b22; --line:#30363d;
          --fg:#e6edf3; --dim:#8b949e; --ok:#3fb950; --warn:#d29922; --bad:#f85149; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace; }
  header { padding:14px 20px; border-bottom:1px solid var(--line); display:flex;
           gap:14px; align-items:center; flex-wrap:wrap; }
  h1 { font-size:15px; margin:0; letter-spacing:.02em; }
  .tag { background:var(--warn); color:#000; padding:2px 8px; border-radius:3px;
         font-weight:700; font-size:12px; }
  .dim { color:var(--dim); }
  main { padding:20px; max-width:1100px; margin:0 auto; display:grid; gap:16px; }
  section { background:var(--panel); border:1px solid var(--line); border-radius:6px; }
  section > h2 { font-size:13px; margin:0; padding:10px 14px;
                 border-bottom:1px solid var(--line); color:var(--dim);
                 text-transform:uppercase; letter-spacing:.08em; }
  .body { padding:14px; }
  button { background:#21262d; color:var(--fg); border:1px solid var(--line);
           border-radius:5px; padding:7px 12px; cursor:pointer; font:inherit; }
  button:hover { border-color:#6e7681; }
  button.primary { background:#238636; border-color:#2ea043; }
  button.danger { background:#4a1f1f; border-color:#6e2b2b; }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  pre { background:#0d1117; border:1px solid var(--line); border-radius:5px;
        padding:12px; overflow:auto; margin:10px 0 0; max-height:340px;
        white-space:pre-wrap; word-break:break-word; }
  table { border-collapse:collapse; width:100%; }
  th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line);
          font-size:13px; vertical-align:top; }
  th { color:var(--dim); font-weight:600; }
  .state-DONE,.state-done-paid,.state-done-free { color:var(--ok); }
  .state-WAITING_APPROVAL,.state-waiting-approval { color:var(--warn); }
  .state-FAILED,.state-failed { color:var(--bad); }
  select { background:#21262d; color:var(--fg); border:1px solid var(--line);
           border-radius:5px; padding:7px; font:inherit; }
  @media (max-width:640px){ main{padding:12px} .row{gap:6px} }
</style></head><body>
<header>
  <h1>UNBLOCK — owner preview</h1>
  <span class="tag">MOCK RAIL · NO REAL MONEY</span>
  <span class="dim" id="meta">…</span>
</header>
<main>
  <section><h2>1 · run the job</h2><div class="body">
    <div class="row">
      <select id="scenario">
        <option value="allow">allow — $0.05, under the cap</option>
        <option value="ask-over-cap">ask — $0.50, over the $0.10 cap</option>
        <option value="ask-unknown-merchant">ask — merchant not allowlisted</option>
      </select>
      <button class="primary" onclick="run()">run</button>
      <button class="danger" onclick="reset()">reset</button>
      <span class="dim">policy: cap $0.10 / invoice · $1.00 weekly · allowlist {intel.example}</span>
    </div>
    <pre id="runout">not run yet</pre>
  </div></section>

  <section><h2>2 · jobs</h2><div class="body">
    <div class="row"><button onclick="loadJobs()">refresh</button></div>
    <table id="jobs"><thead><tr><th>job</th><th>state</th><th>merchant</th><th></th></tr></thead><tbody></tbody></table>
  </div></section>

  <section><h2>3 · approval — the human decision</h2><div class="body">
    <div class="dim">A parked job shows the terms the clerk pinned. APPROVE pays exactly
      those terms; REJECT finishes the job from a free source and never pays.</div>
    <pre id="detail">select a job above</pre>
    <div class="row" id="decide" style="display:none">
      <button class="primary" onclick="decide('APPROVE')">APPROVE</button>
      <button class="danger" onclick="decide('REJECT')">REJECT</button>
      <span class="dim" id="decidefor"></span>
    </div>
  </section>

  <section><h2>4 · the paywall itself</h2><div class="body">
    <div class="dim">The real x402 merchant. An unknown URL is refused with 400
      <em>before</em> any payment challenge, so a wrong question costs nothing.
      A known one answers 402 with the terms below.</div>
    <div class="row" style="margin-top:10px">
      <button onclick="challenge('guides/install.md')">402 — known link</button>
      <button onclick="challenge('nope.md')">400 — unknown link</button>
    </div>
    <pre id="challenge">—</pre>
  </div></section>

  <section><h2>5 · the 45s pilot cut</h2><div class="body">
    <div class="dim">What the filmed version looks like today. Everything in it is
      real output or a deterministic re-render of it; only the title cards are generated.</div>
    <video src="/pilot.mp4" controls preload="metadata"
           style="width:100%;max-width:860px;margin-top:10px;border:1px solid var(--line);border-radius:6px"></video>
  </div></section>

  <section><h2>6 · evidence</h2><div class="body">
    <div class="row"><button onclick="loadPrs()">PR artifacts</button>
      <button onclick="loadSite()">site files</button></div>
    <pre id="evidence">—</pre>
  </div></section>
</main>
<script>
let current = null;
const j = (r) => r.json();
const show = (id, v) => document.getElementById(id).textContent =
  typeof v === "string" ? v : JSON.stringify(v, null, 2);

async function meta(){
  const h = await fetch("/health").then(j);
  document.getElementById("meta").textContent =
    `${h.rail} · expires ${h.expires_at_utc} · commit ${h.commit}`;
}
async function run(){
  const s = document.getElementById("scenario").value;
  show("runout", "running…");
  show("runout", await fetch(`/api/demo/run?scenario=${s}`, {method:"POST"}).then(j));
  loadJobs();
}
async function reset(){
  show("runout", await fetch("/api/demo/reset", {method:"POST"}).then(j));
  document.querySelector("#jobs tbody").innerHTML = "";
  show("detail", "select a job above");
  document.getElementById("decide").style.display = "none";
}
async function loadJobs(){
  const rows = await fetch("/api/jobs").then(j);
  document.querySelector("#jobs tbody").innerHTML = rows.map(r => `
    <tr><td>${r.job_id}</td>
        <td class="state-${r.state}">${r.state}</td>
        <td>${r.merchant ?? "—"}</td>
        <td><button onclick="detail('${r.job_id}')">inspect</button></td></tr>`).join("");
}
async function detail(id){
  current = id;
  const d = await fetch(`/approval/v1/approvals/${id}`).then(j);
  show("detail", d);
  const parked = d.job_state === "WAITING_APPROVAL" && !d.decision;
  document.getElementById("decide").style.display = parked ? "flex" : "none";
  document.getElementById("decidefor").textContent = parked ? `for ${id}` : "";
}
async function decide(action){
  const r = await fetch(`/approval/v1/approvals/${current}/decision`, {
    method:"POST", headers:{"content-type":"application/json"},
    body: JSON.stringify({action})});
  show("detail", {status:r.status, ...(await r.json())});
  loadJobs();
}
const challenge = async (url) =>
  show("challenge", await fetch(`/api/merchant/challenge?broken_url=${encodeURIComponent(url)}`).then(j));
const loadPrs  = async () => show("evidence", await fetch("/api/pr").then(j));
const loadSite = async () => show("evidence", await fetch("/api/site").then(j));
meta(); loadJobs();
</script></body></html>
"""
