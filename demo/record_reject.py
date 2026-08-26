"""Recording script: the human-in-the-loop REJECT path, fully deterministic.

  uv run python demo/record_reject.py

No LLM, no network, no randomness - every run parks the same 20 USDC invoice,
rejects it through the real v1 approval API surface, and completes the job
from the free fallback source with zero settlements. Work products land in
demo/reject_run/ (fixture-only scratch, recreated each run).

The success path for recording is demo/run_gate_c.sh (tests + live Bedrock
agent) or demo/poc_unblock.py --rail x402 for the real-money variant.
"""

from __future__ import annotations

import json
import shutil
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fastapi.testclient import TestClient  # noqa: E402

from clerk.approval_api import create_app  # noqa: E402
from clerk.jobs import Clerk  # noqa: E402
from clerk.ledger import Ledger  # noqa: E402
from clerk.policy import Policy  # noqa: E402
from clerk.rails import MockRail  # noqa: E402
from unblock import IntelOffer, Unblock, detect  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
RUN_DIR = REPO / "demo" / "reject_run"

BROKEN = "guides/install.md"
GOOD = "docs/setup.md"

TOKENS = {"akiyuki": "owner-token"}  # demo credential, matches the docs


def step(n: int, text: str) -> None:
    print(f"\n[{n}] {text}")


shutil.rmtree(RUN_DIR, ignore_errors=True)
site = RUN_DIR / "site"
shutil.copytree(REPO / "fixtures" / "site", site)

rail = MockRail()  # a settlement here would be a bug; we assert 0 at the end
offer = IntelOffer("intel.example", Decimal("20.00"), url="http://intel.example/intel")
policy = Policy(currency="USDC", weekly_allowance=Decimal("5.00"),
                per_invoice_cap=Decimal("1.00"),
                merchant_allowlist=frozenset({offer.merchant}))


def factory():
    return Clerk(Ledger(RUN_DIR / "ledger.db"), policy, rail)


pipeline = Unblock(site, "index.md", factory, offer, RUN_DIR / "prs",
                   free_sources={BROKEN: GOOD})

step(1, f"detect: {[(i.file, i.link) for i in detect(site)]}")
(incident,) = detect(site)

step(2, "the intel costs 20.00 USDC - over the 1.00 cap, so the job PARKS:")
print(json.dumps(pipeline.run(incident), indent=2))

client = TestClient(create_app(factory, tokens=TOKENS), raise_server_exceptions=False)
auth = {"Authorization": f"Bearer {TOKENS['akiyuki']}"}

step(3, "the human sees the pending approval on the v1 API:")
print(json.dumps(client.get("/v1/approvals", headers=auth).json(), indent=2))

step(4, "the human REJECTS the purchase:")
print(json.dumps(client.post(
    f"/v1/approvals/{incident.job_id}/decision", headers=auth,
    json={"action": "REJECT", "note": "20 USDC is too much for one link"},
).json(), indent=2))

step(5, "re-run: the job completes from the FREE fallback source:")
result = pipeline.run(incident)
print(json.dumps(result, indent=2))

step(6, "audit from disk:")
assert result["status"] == "done-free" and rail.settled == [] and detect(site) == []
print(f"settlements: {len(rail.settled)} (zero - nobody was paid)")
print(f"remaining broken links: {len(detect(site))}")
print(f"\n=== PR artifact ===\n{Path(result['pr']).read_text()}")
