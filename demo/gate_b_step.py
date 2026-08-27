"""One step of the Gate B live pass, as its own OS process.

Gate B's claim is about durability: a job parked for a human survives the death
of the process that parked it, and the decision that releases it can only
settle once no matter how many processes replay it. A single-process script
cannot show that -- it would be asserting the claim inside the very memory the
claim is about. So each step here is invoked separately, and everything shared
between them is on disk: UNBLOCK's ledger, and the rail's own settlement file.

  park <ledger> <rail> <job> <amount>   submit an invoice, print the state
  resume <ledger> <rail> <job>          re-drive the job, print the state
  state <ledger> <rail> <job>           read state and settlement count only

Prints one JSON object. Mock rail throughout: nothing here can move money.
"""

from __future__ import annotations

import json
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from unblock import Invoice, Ledger, Policy, Unblock  # noqa: E402
from unblock.rails import FileRail  # noqa: E402

# The policy the demo ships with: $0.10 a request, $1.00 a week, one merchant.
POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("1.00"),
    per_invoice_cap=Decimal("0.10"),
    merchant_allowlist=frozenset({"threat-intel.example"}),
)
MERCHANT = "threat-intel.example"


def invoice_for(job: str, amount: str) -> Invoice:
    """Deterministic from the job id, so a later process rebuilds the identical
    invoice -- including its digest -- without being handed one."""
    return Invoice(f"inv-{job}", MERCHANT, Decimal(amount), "USDC")


def main() -> int:
    command, ledger_path, rail_path, job = sys.argv[1:5]
    amount = sys.argv[5] if len(sys.argv) > 5 else "0.50"

    rail = FileRail(rail_path)
    invoice = invoice_for(job, amount)
    ledger = Ledger(ledger_path)
    unblock = Unblock(ledger, POLICY, rail)
    try:
        if command == "park":
            state = unblock.run_job(job, invoice, work="fetch premium intel")
        elif command == "resume":
            state = unblock.resume(job)
        elif command == "state":
            row = ledger.job(job)
            state = row["state"] if row else None
        else:
            raise SystemExit(f"unknown step {command!r}")

        row = ledger.job(job)
        print(json.dumps({
            "step": command,
            "pid": __import__("os").getpid(),
            "job": job,
            "returned": state,
            "ledger_state": row["state"] if row else None,
            "invoice_digest": invoice.digest()[:16],
            "settlements_for_this_invoice": rail.settle_count(invoice),
        }, indent=1))
    finally:
        ledger.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
