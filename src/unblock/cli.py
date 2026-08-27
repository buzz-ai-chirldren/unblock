"""`unblock` on the command line.

UNBLOCK is a library an agent calls, so there is no run-the-agent command here
on purpose. What a terminal is useful for is answering "what would the policy
do with this?" without writing a script, and reading the ledger a run left
behind. Both are read-only.
"""

from __future__ import annotations

import argparse
import json
from decimal import Decimal, InvalidOperation

from . import Decision, Invoice, Ledger, Policy, evaluate


def _policy(args) -> Policy:
    return Policy(
        currency=args.currency,
        per_invoice_cap=Decimal(args.per_request_cap),
        weekly_allowance=Decimal(args.weekly_budget),
        merchant_allowlist=frozenset(args.allow or ()),
        merchant_blocklist=frozenset(args.block or ()),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="unblock", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="what the policy would decide for one invoice")
    check.add_argument("--merchant", required=True)
    check.add_argument("--amount", required=True)
    check.add_argument("--currency", default="USDC")
    check.add_argument("--per-request-cap", default="0.10")
    check.add_argument("--weekly-budget", default="1.00")
    check.add_argument("--allow", action="append", metavar="MERCHANT",
                       help="allowlisted merchant; repeat for more")
    # Without this the CLI cannot express a whole input to the policy, and DENY
    # is only reachable by asking about a non-positive amount -- which reads as
    # "DENY does not really happen" to anyone using this to understand the rules.
    check.add_argument("--block", action="append", metavar="MERCHANT",
                       help="blocklisted merchant (always DENY); repeat for more")
    check.add_argument("--spent-this-week", default="0")

    jobs = sub.add_parser("jobs", help="jobs in a ledger, newest first")
    jobs.add_argument("db")
    jobs.add_argument("--waiting", action="store_true",
                      help="only the ones parked for a human")

    args = parser.parse_args(argv)

    if args.command == "check":
        try:
            invoice = Invoice("cli", args.merchant, Decimal(args.amount), args.currency)
            verdict = evaluate(invoice, _policy(args), Decimal(args.spent_this_week))
        except InvalidOperation:
            parser.error("amounts must be decimal numbers")
        print(json.dumps({"decision": verdict.decision.value, "reason": verdict.reason}, indent=1))
        # ASK is not a failure -- it is the product working -- so only DENY is
        # worth a non-zero status to a caller wiring this into a script. A usage
        # error also leaves with 2, but prints no JSON, so the two are still
        # tellable apart by a caller that reads stdout.
        return 2 if verdict.decision is Decision.DENY else 0

    ledger = Ledger(args.db)
    try:
        if args.waiting:
            rows = ledger.waiting_jobs(limit=100, offset=0)
        else:
            rows = [
                {"job_id": r[0], "state": r[1], "merchant": r[2], "invoice_id": r[3]}
                for r in ledger.conn.execute(
                    "SELECT job_id, state, merchant, invoice_id FROM jobs ORDER BY rowid DESC"
                ).fetchall()
            ]
        print(json.dumps(rows, indent=1, default=str))
    finally:
        ledger.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
