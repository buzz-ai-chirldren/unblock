"""X402Rail: real settlement over the x402 protocol (exact scheme, EIP-3009
USDC) - UNBLOCK's only rail that moves real value.

Contract with the state machine (same as every rail):
  - pay() is called ONLY after policy allowed (or a human approved) the exact
    invoice terms; the resource URL is pinned in invoice.memo, so it is part
    of the digest and cannot be swapped after approval.
  - pay() enforces the invoice terms AGAIN at the protocol layer: the x402
    client is built per-call with a max_amount policy equal to the invoice
    amount, so a merchant demanding more than the approved amount gets no
    signature - the request simply fails with 402 and we raise RailError
    (safe: nothing was signed, nothing moved).
  - lookup() answers crash-window reconciliation from the chain itself: scan
    recent USDC Transfer logs from our payer address. UNBLOCK never re-pays
    a PAYING row on its own.

The facilitator submits transferWithAuthorization on-chain and pays gas, so
the payer wallet needs USDC only (no ETH).
"""

from __future__ import annotations

from decimal import Decimal

from .policy import Invoice
from .rails import RailError, SettlementUncertain, _receipt

NETWORK = "eip155:84532"  # Base Sepolia
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"  # Base Sepolia USDC (6 decimals)
DEFAULT_RPC = "https://sepolia.base.org"
FACILITATOR_URL = "https://x402.org/facilitator"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


class X402Rail:
    name = "x402"

    def __init__(self, private_key: str, network: str = NETWORK, rpc_url: str = DEFAULT_RPC):
        from eth_account import Account

        self._account = Account.from_key(private_key)
        self.address = self._account.address
        self.network = network
        self.rpc_url = rpc_url

    def _atomic(self, invoice: Invoice) -> int:
        if invoice.currency != "USDC":
            raise RailError(f"x402 rail only settles USDC, got {invoice.currency}")
        return int(invoice.amount * Decimal(10**6))

    def pay(self, invoice: Invoice) -> dict:
        from x402.client import max_amount, prefer_network, x402ClientSync
        from x402.http import decode_payment_response_header
        from x402.http.clients.requests import x402_requests
        from x402.mechanisms.evm import EthAccountSigner
        from x402.mechanisms.evm.exact.register import register_exact_evm_client

        url = invoice.memo
        if not url.startswith("http"):
            raise RailError(f"invoice.memo must carry the x402 resource URL, got {url!r}")
        atomic = self._atomic(invoice)

        # Fresh client per payment: the spend ceiling IS this invoice's amount.
        client = x402ClientSync()
        register_exact_evm_client(
            client,
            EthAccountSigner(self._account),
            networks=[self.network],
            policies=[max_amount(atomic), prefer_network(self.network)],
        )
        from x402.http.clients.requests import PaymentError

        session = x402_requests(client)
        try:
            resp = session.get(url, timeout=60)
        except PaymentError as e:
            if "filtered out by policies" in str(e):
                # Our max_amount/network policies rejected every requirement:
                # provably nothing was signed. Safe refusal.
                raise RailError(
                    f"merchant demands terms outside the approved invoice "
                    f"(max {invoice.amount} {invoice.currency}); refused before signing"
                ) from e
            # Anything else: an authorization may have been signed/sent already.
            raise SettlementUncertain(str(e)) from e
        except Exception as e:
            # Transport failure mid-flow: cannot prove the payment header never
            # reached the merchant/facilitator.
            raise SettlementUncertain(str(e)) from e
        if resp.status_code == 402:
            # Transport returned the original 402 without paying: nothing signed.
            raise RailError(
                f"402 not payable under approved invoice terms "
                f"({invoice.amount} {invoice.currency}); refused before signing"
            )
        if resp.status_code >= 400:
            raise SettlementUncertain(f"HTTP {resp.status_code} after payment attempt")
        header = resp.headers.get("PAYMENT-RESPONSE") or resp.headers.get("X-PAYMENT-RESPONSE")
        if not header:
            raise SettlementUncertain("200 response without a payment response header")
        settle = decode_payment_response_header(header)
        if not settle.success:
            # A signed authorization reached the facilitator; even on reported
            # failure it could settle within its validity window. Reconcile.
            raise SettlementUncertain(
                f"facilitator settle failed: {settle.error_reason}: {settle.error_message}"
            )
        receipt = _receipt(self.name, settle.network or self.network, FACILITATOR_URL, invoice, settle.transaction or "")
        receipt["payer"] = settle.payer or self.address
        # The paid response body IS the purchased good: keep it with the
        # receipt so the job that paid for it can consume it after resume.
        receipt["resource"] = resp.text[:4096]
        return receipt

    def lookup(self, invoice: Invoice) -> dict | None:
        """Chain-side settlement query for reconciliation: newest USDC Transfer
        FROM our payer address matching the invoice's atomic amount, scanned
        over the last ~50k blocks (~1 day on Base). Conservative by design: a
        None here keeps the row PAYING for a human."""
        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        latest = w3.eth.block_number
        payer_topic = "0x" + "0" * 24 + self.address[2:].lower()
        logs = w3.eth.get_logs(
            {
                "address": Web3.to_checksum_address(USDC),
                "topics": [TRANSFER_TOPIC, payer_topic],
                "fromBlock": max(0, latest - 50_000),
                "toBlock": latest,
            }
        )
        atomic = self._atomic(invoice)
        for log in reversed(logs):
            if int.from_bytes(log["data"], "big") == atomic:
                receipt = _receipt(self.name, self.network, FACILITATOR_URL, invoice, log["transactionHash"].hex())
                receipt["payer"] = self.address
                receipt["reconciled_from_chain"] = True
                return receipt
        return None
