"""Run the approval API over a real ledger for the Gate B live pass.

  UNBLOCK_APPROVAL_TOKENS='{"akiyuki": "<token>"}' \
  UNBLOCK_DB=demo/strands_x402_run2.db \
  [UNBLOCK_WALLET_FILE=/path/to/wallet.json] \
  uv run uvicorn demo.approval_server:app --port 8403

With UNBLOCK_WALLET_FILE set, resume settles over the real x402 rail
(Base Sepolia); without it, the mock rail is used.
"""

from __future__ import annotations

import json
import os
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from unblock import Ledger, Policy, Unblock  # noqa: E402
from unblock.approval_api import create_app  # noqa: E402
from unblock.rails import MockRail  # noqa: E402

DB = os.environ.get("UNBLOCK_DB", "demo/strands_ledger.db")

POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("1.00"),
    per_invoice_cap=Decimal("0.10"),
    merchant_allowlist=frozenset({"local-x402-merchant"}),
)

if os.environ.get("UNBLOCK_WALLET_FILE"):
    from unblock.x402_rail import X402Rail

    wallet = json.load(open(os.environ["UNBLOCK_WALLET_FILE"]))
    RAIL = X402Rail(private_key=wallet["private_key"])
else:
    RAIL = MockRail()

app = create_app(lambda: Unblock(Ledger(DB), POLICY, RAIL))
