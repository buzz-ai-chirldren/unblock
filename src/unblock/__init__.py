"""UNBLOCK: spending controls for any AI agent.

An agent asks to spend; a deterministic policy decides; a human approves the
exceptions. The agent never decides, and the LLM is not in the approval path.

    from decimal import Decimal
    from unblock import Invoice, Ledger, Policy, Unblock, X402Rail

    unblock = Unblock(
        Ledger("spend.db"),
        Policy(per_invoice_cap    = Decimal("0.10"),
               weekly_allowance   = Decimal("1.00"),
               merchant_allowlist = {"threat-intel.example"}),
        X402Rail(wallet_key),
    )

    state = unblock.run_job(job_id, invoice, work)
    #  "DONE"              paid - the agent continues
    #  "WAITING_APPROVAL"  policy stopped it - a human decides

`Ledger`, `Policy` and the rails are UNBLOCK's own parts, not services to sign
up for: the ledger is a local SQLite audit log that makes settlement
at-most-once, the policy is the rule set, and a rail is the adapter to whatever
actually moves the money.

The approval side is `unblock.approval_api.create_app`, the shipped v1
contract. The link-repair demo built on top of this lives in
`unblock.demo_pipeline` and is not part of the product surface.
"""

from .controller import Unblock
from .ledger import Ledger
from .policy import Decision, Invoice, Policy, Verdict, evaluate
from .rails import FileRail, MockRail, PaymentRail, RailError, SettlementUncertain

__all__ = [
    "Unblock", "Ledger", "Policy", "Invoice", "Decision", "Verdict", "evaluate",
    "PaymentRail", "MockRail", "FileRail", "RailError", "SettlementUncertain",
    "X402Rail",
]


def __getattr__(name):
    # X402Rail pulls in eth-account and the x402 stack. Importing `unblock`
    # should not cost that for a caller who only wants the policy types, so it
    # is resolved on first use and still appears in __all__ and dir().
    if name == "X402Rail":
        from .x402_rail import X402Rail
        return X402Rail
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
