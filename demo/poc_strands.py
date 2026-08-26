"""Gate A item 1: a real Strands agent drives the clerk through a structured
tool call. The LLM decides WHEN to fetch the paid resource; whether money moves
is decided ONLY by the deterministic policy/ledger inside the tool.

  BEDROCK_KEY_FILE=... uv run python demo/poc_strands.py \
      [--url http://127.0.0.1:8402/premium-data] [--rail mock|x402] \
      [--provider bedrock|anthropic]

Model provider defaults to Bedrock (us-east-1, credentials from
BEDROCK_KEY_FILE, an IAM access-key JSON). --provider anthropic keeps the
old path and needs ANTHROPIC_API_KEY.

The tool returns the clerk's verdict verbatim (DONE / WAITING_APPROVAL /
FAILED); the agent's job is to relay it, not to override it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from strands import Agent, tool  # noqa: E402

from clerk.jobs import Clerk  # noqa: E402
from clerk.ledger import Ledger  # noqa: E402
from clerk.policy import Invoice, Policy  # noqa: E402
from clerk.rails import MockRail  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://127.0.0.1:8402/premium-data")
ap.add_argument("--rail", choices=["mock", "x402"], default="mock")
ap.add_argument("--db", default="demo/strands_ledger.db")
ap.add_argument("--provider", choices=["bedrock", "anthropic"], default="bedrock")
ap.add_argument("--model-id", default=None)
args = ap.parse_args()


def build_model(provider: str, model_id: str | None):
    if provider == "anthropic":
        from strands.models.anthropic import AnthropicModel

        return AnthropicModel(model_id=model_id or "claude-opus-5", max_tokens=4096)

    import boto3
    from strands.models import BedrockModel

    creds = json.load(open(os.environ["BEDROCK_KEY_FILE"]))
    if "AccessKey" in creds:  # IAM console export wraps the key pair
        creds = creds["AccessKey"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        region_name="us-east-1",
    )
    return BedrockModel(
        model_id=model_id or "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        boto_session=session,
        max_tokens=4096,
    )

if args.rail == "x402":
    from clerk.x402_rail import X402Rail

    wallet = json.load(open(os.environ["CLERK_WALLET_FILE"]))
    rail = X402Rail(private_key=wallet["private_key"])
else:
    rail = MockRail()

POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("1.00"),
    per_invoice_cap=Decimal("0.10"),
    merchant_allowlist=frozenset({"local-x402-merchant"}),
)

@tool
def fetch_paid_resource(invoice_id: str, amount_usdc: str, url: str) -> str:
    """Fetch a paywalled resource, paying its invoice through the allowance clerk.

    The clerk applies a deterministic spending policy: within-allowance invoices
    from allowlisted merchants are paid automatically; anything else parks the
    job in a durable human-approval queue. This tool never overrides policy.

    Args:
        invoice_id: The merchant's invoice identifier (e.g. "inv-2026-001").
        amount_usdc: Invoice amount in USDC as a decimal string (e.g. "0.05").
        url: The paywalled resource URL from the 402 response.
    """
    invoice = Invoice(
        invoice_id=invoice_id,
        merchant="local-x402-merchant",
        amount=Decimal(amount_usdc),
        currency="USDC",
        memo=url,
    )
    # Strands runs tools on a worker thread; SQLite connections are
    # thread-bound, so build a fresh Ledger/Clerk per call. All state lives
    # in the on-disk ledger, so fresh connections are safe (see the restart
    # tests in tests/).
    clerk = Clerk(Ledger(args.db), POLICY, rail)
    try:
        state = clerk.run_job(f"job-{invoice_id}", invoice, work=f"GET {url}")
        receipt = clerk.ledger.receipt(invoice)
    finally:
        clerk.ledger.close()
    return json.dumps({"job_state": state, "receipt": receipt})


model = build_model(args.provider, args.model_id)
agent = Agent(
    model=model,
    tools=[fetch_paid_resource],
    system_prompt=(
        "You are a work agent. When asked to get premium data, call "
        "fetch_paid_resource with the exact invoice details given. Report the "
        "resulting job_state faithfully: DONE means the invoice was paid and "
        "work completed; WAITING_APPROVAL means a human must approve before "
        "payment; FAILED means policy rejected it. Never claim a payment "
        "happened unless the receipt proves it."
    ),
)

result = agent(
    f"Get the premium data at {args.url}. The merchant issued invoice "
    f"inv-strands-001 for 0.05 USDC. Then tell me whether it was paid."
)
print("\n--- final ---")
print(result)
