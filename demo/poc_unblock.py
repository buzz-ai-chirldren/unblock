"""Gate C live demo: a Strands agent (Bedrock by default) runs the UNBLOCK
story end-to-end on a scratch copy of the fixture site.

  BEDROCK_KEY_FILE=... uv run python demo/poc_unblock.py \
      [--rail mock|x402] [--provider bedrock|anthropic] [--model-id ...]

The agent only sequences scan_site / unblock_incident tool calls; payment
policy, idempotency, file allowlisting, verification and PR emission are the
deterministic pipeline's job (src/unblock/). Work products (site copy, ledger,
PR) land in demo/unblock_run/ - delete that directory to reset the demo.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from strands import Agent, tool  # noqa: E402

from model_provider import build_model  # noqa: E402

from clerk.jobs import Clerk  # noqa: E402
from clerk.ledger import Ledger  # noqa: E402
from clerk.policy import Policy  # noqa: E402
from clerk.rails import FileRail  # noqa: E402
from unblock import Incident, IntelOffer, Unblock, detect  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
RUN_DIR = REPO / "demo" / "unblock_run"

INTEL_BODY = (REPO / "fixtures" / "intel_db.json").read_text()
INTEL_RECORD = json.dumps(json.loads(INTEL_BODY)["guides/install.md"])

ap = argparse.ArgumentParser()
ap.add_argument("--rail", choices=["mock", "x402"], default="mock")
ap.add_argument("--provider", choices=["bedrock", "anthropic"], default="bedrock")
ap.add_argument("--model-id", default=None)
args = ap.parse_args()

RUN_DIR.mkdir(parents=True, exist_ok=True)
site = RUN_DIR / "site"
if not site.exists():
    shutil.copytree(REPO / "fixtures" / "site", site)

if args.rail == "x402":
    import os

    from clerk.x402_rail import X402Rail

    wallet = json.load(open(os.environ["CLERK_WALLET_FILE"]))
    rail = X402Rail(private_key=wallet["private_key"])
    offer = IntelOffer("local-x402-merchant", Decimal("0.05"),
                       url="http://127.0.0.1:8402/intel")
else:
    # FileRail so the settlement count survives crashes/re-runs and can be
    # audited from outside the process; the paid body is the link-intel record.
    rail = FileRail(RUN_DIR / "rail.db", paid_body=INTEL_RECORD)
    offer = IntelOffer("intel.example", Decimal("0.05"), url="http://intel.example/intel")

POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("1.00"),
    per_invoice_cap=Decimal("0.10"),
    merchant_allowlist=frozenset({offer.merchant}),
)

pipeline = Unblock(
    site_dir=site,
    allowed_file="index.md",
    clerk_factory=lambda: Clerk(Ledger(RUN_DIR / "ledger.db"), POLICY, rail),
    offer=offer,
    pr_dir=RUN_DIR / "prs",
)

INCIDENTS: dict[str, Incident] = {}


@tool
def scan_site() -> str:
    """Run the deterministic link checker over the site and list broken-link
    incidents. Returns a JSON array of {incident_id, file, broken_link}."""
    found = detect(site)
    INCIDENTS.update({i.incident_id: i for i in found})
    return json.dumps([
        {"incident_id": i.incident_id, "file": i.file, "broken_link": i.link}
        for i in found
    ])


@tool
def unblock_incident(incident_id: str) -> str:
    """Repair one incident end-to-end: buy link intelligence through the
    allowance clerk (policy may park it for human approval), fix the single
    allowlisted file, verify, and emit a PR artifact. Returns the pipeline's
    verdict verbatim as JSON; never claim success beyond what it says.

    Args:
        incident_id: id from scan_site.
    """
    incident = INCIDENTS.get(incident_id)
    if incident is None:
        return json.dumps({"status": "unknown-incident", "incident_id": incident_id})
    return json.dumps(pipeline.run(incident))


agent = Agent(
    model=build_model(args.provider, args.model_id),
    tools=[scan_site, unblock_incident],
    system_prompt=(
        "You are a site-maintenance work agent. Scan the site for broken "
        "links, then repair each incident with unblock_incident. Relay each "
        "verdict faithfully: done-paid/done-free mean fixed (with/without a "
        "payment), waiting-approval means a human must decide before any "
        "money moves, refused-file and failed mean not fixed. Never claim a "
        "payment or a fix happened unless the tool result proves it."
    ),
)

result = agent(
    "Scan the site and repair whatever broken links you find. Then summarize: "
    "what was broken, what information source was used, whether money moved, "
    "and where the PR artifact is."
)

print("\n--- final ---")
print(result)

prs = sorted((RUN_DIR / "prs").glob("*.md"))
settlements = sum(
    rail.settle_count(type("I", (), {"merchant": offer.merchant,
                                     "invoice_id": i.invoice_id})())
    for i in INCIDENTS.values()
) if args.rail == "mock" else "see on-chain receipts"
print("\n--- audit (from disk, not from the model) ---")
print(f"settlements: {settlements}")
print(f"remaining broken links: {len(detect(site))}")
for pr in prs:
    print(f"\n=== PR artifact {pr.name} ===")
    print(pr.read_text())
