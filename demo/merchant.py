"""x402 demo merchant: paywalled endpoints priced in USDC on Base Sepolia.

/premium-data is the Gate A counterparty; /intel is the Gate C "Link
Intelligence API" (a DEMO merchant, deliberately self-hosted so the 402
terms, response schema, and failure fixtures are pinned to this repo).
It uses the public x402.org facilitator for verify/settle (the facilitator
submits the EIP-3009 transferWithAuthorization on-chain and pays gas), so
the merchant process itself holds no keys at all - only a receiving address.

/intel answers only for broken URLs present in its fixture database and
rejects everything else with 400 BEFORE any payment challenge is issued:
an unknown URL costs the caller nothing.

Run:
  MERCHANT_ADDRESS=0x... uv run uvicorn demo.merchant:app --port 8402
Env:
  MERCHANT_ADDRESS  receiving address (required)
  MERCHANT_PRICE    e.g. "$0.05" (default)
  FACILITATOR_URL   default https://x402.org/facilitator
  INTEL_DB_FILE     default fixtures/intel_db.json
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from x402.http import FacilitatorConfig, HTTPFacilitatorClient
from x402.http.middleware.fastapi import payment_middleware
from x402.http.types import PaymentOption, RouteConfig
from x402.mechanisms.evm.exact.register import register_exact_evm_server
from x402.server import x402ResourceServer

NETWORK = "eip155:84532"  # Base Sepolia

PAY_TO = os.environ["MERCHANT_ADDRESS"]
PRICE = os.environ.get("MERCHANT_PRICE", "$0.05")
FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "https://x402.org/facilitator")
INTEL_DB_FILE = os.environ.get(
    "INTEL_DB_FILE", str(Path(__file__).resolve().parent.parent / "fixtures" / "intel_db.json")
)
INTEL_DB: dict[str, dict] = json.loads(Path(INTEL_DB_FILE).read_text())

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
            ),
            "/intel": RouteConfig(
                accepts=PaymentOption(
                    scheme="exact", pay_to=PAY_TO, price=PRICE, network=NETWORK
                ),
                description="Link Intelligence record behind an x402 paywall (Gate C demo)",
            ),
        },
        server,
    )
)


@app.middleware("http")
async def reject_unknown_intel_before_payment(request: Request, call_next):
    # Added AFTER the payment middleware, so Starlette runs it FIRST: an
    # /intel query outside the fixture allowlist is rejected before any 402
    # challenge exists - nobody can be charged for a question we can't answer.
    if request.url.path == "/intel":
        broken_url = request.query_params.get("broken_url")
        if broken_url not in INTEL_DB:
            return JSONResponse(
                {"error": "unknown broken_url; not in the fixture allowlist"},
                status_code=400,
            )
    return await call_next(request)


@app.get("/premium-data")
def premium_data():
    return {"data": "premium payload", "paid_via": "x402/base-sepolia"}


@app.get("/intel")
def intel(broken_url: str):
    return INTEL_DB[broken_url]


@app.get("/health")
def health():
    return {"ok": True, "pay_to": PAY_TO, "price": PRICE, "network": NETWORK}
