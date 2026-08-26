"""x402 test merchant: one paywalled endpoint priced in USDC on Base Sepolia.

This is the counterparty for the Gate A real-settlement test. It uses the
public x402.org facilitator for verify/settle (the facilitator submits the
EIP-3009 transferWithAuthorization on-chain and pays gas), so the merchant
process itself holds no keys at all - only a receiving address.

Run:
  MERCHANT_ADDRESS=0x... uv run uvicorn demo.merchant:app --port 8402
Env:
  MERCHANT_ADDRESS  receiving address (required)
  MERCHANT_PRICE    e.g. "$0.05" (default)
  FACILITATOR_URL   default https://x402.org/facilitator
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from x402.http import FacilitatorConfig, HTTPFacilitatorClient
from x402.http.middleware.fastapi import payment_middleware
from x402.http.types import PaymentOption, RouteConfig
from x402.mechanisms.evm.exact.register import register_exact_evm_server
from x402.server import x402ResourceServer

NETWORK = "eip155:84532"  # Base Sepolia

PAY_TO = os.environ["MERCHANT_ADDRESS"]
PRICE = os.environ.get("MERCHANT_PRICE", "$0.05")
FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "https://x402.org/facilitator")

facilitator = HTTPFacilitatorClient(FacilitatorConfig(url=FACILITATOR_URL))
server = x402ResourceServer(facilitator)
register_exact_evm_server(server, networks=[NETWORK])

app = FastAPI()
app.middleware("http")(
    payment_middleware(
        {
            "/premium-data": RouteConfig(
                accepts=PaymentOption(
                    scheme="exact", pay_to=PAY_TO, price=PRICE, network=NETWORK
                ),
                description="Premium data behind an x402 paywall (Gate A demo)",
            )
        },
        server,
    )
)


@app.get("/premium-data")
def premium_data():
    return {"data": "premium payload", "paid_via": "x402/base-sepolia"}


@app.get("/health")
def health():
    return {"ok": True, "pay_to": PAY_TO, "price": PRICE, "network": NETWORK}
