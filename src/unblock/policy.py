"""Deterministic payment policy: the LLM never decides whether money moves.

Every invoice is evaluated by plain code against the wallet's policy and the
ledger's recorded spending. Three outcomes:

  ALLOW - pay now without asking anyone
  ASK   - park the job in a durable approval queue; a human decides
  DENY  - never payable (malformed, wrong currency, blocked merchant)

ASK is the product: the official AgentCore payments flow ends over-limit
requests with a deny, and nothing waits for a human or resumes the job.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ASK = "ASK"
    DENY = "DENY"


@dataclass(frozen=True)
class Invoice:
    """One request for payment, normalized before policy ever sees it."""

    invoice_id: str  # merchant-scoped id; uniqueness key is (merchant, invoice_id)
    merchant: str
    amount: Decimal
    currency: str
    memo: str = ""

    def digest(self) -> str:
        """Hash of the payment terms as presented. The ledger pins the digest at
        first claim and approvals bind to it, so a merchant re-issuing the same
        invoice_id with different amount/currency/memo can never ride an earlier
        claim or an earlier human approval."""
        canon = "|".join([self.merchant, self.invoice_id, str(self.amount), self.currency, self.memo])
        return hashlib.sha256(canon.encode()).hexdigest()


@dataclass(frozen=True)
class Policy:
    currency: str = "USDC"
    weekly_allowance: Decimal = Decimal("5.00")
    per_invoice_cap: Decimal = Decimal("1.00")
    merchant_allowlist: frozenset[str] = frozenset()
    merchant_blocklist: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str


def evaluate(invoice: Invoice, policy: Policy, spent_this_week: Decimal) -> Verdict:
    """Pure function: (invoice, policy, recorded spend) -> verdict. No I/O, no clock."""
    if invoice.amount <= 0:
        return Verdict(Decision.DENY, f"non-positive amount {invoice.amount}")
    if invoice.currency != policy.currency:
        return Verdict(Decision.DENY, f"currency {invoice.currency} != policy {policy.currency}")
    if invoice.merchant in policy.merchant_blocklist:
        return Verdict(Decision.DENY, f"merchant {invoice.merchant} is blocklisted")
    if invoice.merchant not in policy.merchant_allowlist:
        return Verdict(Decision.ASK, f"merchant {invoice.merchant} not in allowlist")
    if invoice.amount > policy.per_invoice_cap:
        return Verdict(
            Decision.ASK, f"amount {invoice.amount} exceeds per-invoice cap {policy.per_invoice_cap}"
        )
    if spent_this_week + invoice.amount > policy.weekly_allowance:
        return Verdict(
            Decision.ASK,
            f"would spend {spent_this_week + invoice.amount} of weekly {policy.weekly_allowance}",
        )
    return Verdict(Decision.ALLOW, "within allowance, allowlisted merchant")
