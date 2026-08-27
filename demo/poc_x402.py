"""Gate A item 3 driver: real x402 settlement on Base Sepolia through the full
UNBLOCK state machine (policy -> ledger claim -> idempotent gate -> rail -> receipt).

Prereqs: demo/merchant.py running, payer wallet funded with Base Sepolia USDC.

  UNBLOCK_WALLET_FILE=~/.wallets/payer.json \
  uv run python demo/poc_x402.py --url http://127.0.0.1:8402/premium-data \
      --merchant local-x402-merchant --amount 0.05 [--job job-x402-1] [--rerun]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from unblock import Unblock  # noqa: E402
from unblock import Ledger  # noqa: E402
from unblock.policy import Invoice, Policy  # noqa: E402
from unblock.x402_rail import X402Rail  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--merchant", default="local-x402-merchant")
    ap.add_argument("--amount", default="0.05")
    ap.add_argument("--invoice-id", default="inv-x402-001")
    ap.add_argument("--job", default="job-x402-1")
    ap.add_argument("--db", default="demo/x402_ledger.db")
    args = ap.parse_args()

    wallet_file = os.environ["UNBLOCK_WALLET_FILE"]
    wallet = json.load(open(wallet_file))
    rail = X402Rail(private_key=wallet["private_key"])

    policy = Policy(
        currency="USDC",
        weekly_allowance=Decimal("1.00"),
        per_invoice_cap=Decimal("0.10"),
        merchant_allowlist=frozenset({args.merchant}),
    )
    invoice = Invoice(
        invoice_id=args.invoice_id,
        merchant=args.merchant,
        amount=Decimal(args.amount),
        currency="USDC",
        memo=args.url,  # resource URL is part of the digest
    )
    unblock = Unblock(Ledger(args.db), policy, rail)

    print(f"payer   : {rail.address}")
    print(f"invoice : {invoice.merchant}/{invoice.invoice_id} {invoice.amount} {invoice.currency}")
    state = unblock.run_job(args.job, invoice, work=f"GET {args.url}")
    print(f"state   : {state}")
    receipt = unblock.ledger.receipt(invoice)
    if receipt:
        print("receipt :", json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
