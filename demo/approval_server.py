"""Run the approval API over a real ledger for the Gate B live pass.

  CLERK_APPROVAL_TOKENS='{"akiyuki": "<token>"}' \
  CLERK_DB=demo/strands_x402_run2.db \
  [CLERK_WALLET_FILE=/path/to/wallet.json] \
  uv run uvicorn demo.approval_server:app --port 8403

With CLERK_WALLET_FILE set, resume settles over the real x402 rail
(Base Sepolia); without it, the mock rail is used.
"""

from __future__ import annotations

import json
import os
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from clerk.approval_api import create_app  # noqa: E402
from clerk.jobs import Clerk  # noqa: E402
from clerk.ledger import Ledger  # noqa: E402
from clerk.policy import Policy  # noqa: E402
from clerk.rails import MockRail  # noqa: E402

DB = os.environ.get("CLERK_DB", "demo/strands_ledger.db")

POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("1.00"),
    per_invoice_cap=Decimal("0.10"),
    merchant_allowlist=frozenset({"local-x402-merchant"}),
)

if os.environ.get("CLERK_WALLET_FILE"):
    from clerk.x402_rail import X402Rail

    wallet = json.load(open(os.environ["CLERK_WALLET_FILE"]))
    RAIL = X402Rail(private_key=wallet["private_key"])
else:
    RAIL = MockRail()

app = create_app(lambda: Clerk(Ledger(DB), POLICY, RAIL))
