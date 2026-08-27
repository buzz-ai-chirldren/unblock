# UNBLOCK — an agent that finishes the job, even behind a paywall

Agents stop when they hit HTTP 402. UNBLOCK doesn't: it buys the information
it needs **within a hard, deterministic budget policy**, parks anything
over-limit for a **real human decision**, survives crashes without ever paying
twice, and hands you a PR with the payment receipt pinned into the evidence.

Built for the AWS "Agents for Humans" hackathon on **Strands Agents + Amazon
Bedrock**, with real **x402** micropayments (USDC on Base Sepolia).

## Use it

UNBLOCK is a library your agent calls, not an app you watch. Put it between
the agent and the payment rail:

```python
from decimal import Decimal
from unblock import Ledger, Policy, Unblock, X402Rail

unblock = Unblock(
    Ledger("spend.db"),
    Policy(per_invoice_cap    = Decimal("0.10"),
           weekly_allowance   = Decimal("1.00"),
           merchant_allowlist = {"threat-intel.example"}),
    X402Rail(wallet_key),
)

state = unblock.run_job(job_id, invoice, work)
#  "DONE"              paid — the agent continues
#  "WAITING_APPROVAL"  policy stopped it — a human decides
```

`Ledger`, `Policy` and the rails are UNBLOCK's own parts, not services to sign
up for: the ledger is a local SQLite audit log that makes settlement
at-most-once, the policy is the rule set, and a rail is the adapter to whatever
moves the money. Swap `X402Rail` for `MockRail` or `FileRail` and nothing else
changes.

To ask what the policy would do without writing a script:

```bash
uv run unblock check --merchant threat-intel.example --amount 0.50 \
  --allow threat-intel.example
# {"decision": "ASK", "reason": "amount 0.50 exceeds per-invoice cap 0.10"}

uv run unblock jobs spend.db --waiting     # what is parked for a human
```

`check` takes `--allow`, `--block`, `--per-request-cap`, `--weekly-budget` and
`--spent-this-week`, so it can express any input the policy reads. It exits 0
for ALLOW **and for ASK** — being stopped for a human is the policy working,
not a failure — and 2 for DENY.

## The demo story

A docs site has a broken link. Fixing it needs paid "Link Intelligence" from
an x402-paywalled API. UNBLOCK:

1. **detects** the broken link (deterministic link checker),
2. **buys** the intel through UNBLOCK — the LLM never touches money; a
   pure-code policy decides pay / ask-a-human / deny,
3. **fixes** exactly one allowlisted file (hostile replacement targets are
   refused), **re-verifies** the site,
4. **emits a PR artifact** cross-referencing incident, job, invoice digest,
   and the on-chain payment id.

Re-run it, crash it mid-flight, race two copies — you still get **one
settlement and one PR**.

## One-command demo

```bash
BEDROCK_KEY_FILE=/path/to/iam-key.json demo/run_gate_c.sh
```

Runs the full acceptance suite, then a live Strands agent (Bedrock, Claude
Sonnet 4.5) that repairs the fixture site end-to-end on a local rail.

> `demo/unblock_run/` is a **fixture-only scratch directory** — the demo
> deletes and recreates it on every run. Nothing outside it is touched.

### Real-money variant (Base Sepolia USDC)

```bash
# terminal 1: the x402 Link Intelligence demo merchant
MERCHANT_ADDRESS=0x... uv run uvicorn demo.merchant:app --port 8402

# terminal 2: pay for real over x402, then fix
BEDROCK_KEY_FILE=... UNBLOCK_WALLET_FILE=/path/to/wallet.json \
  uv run python demo/poc_unblock.py --rail x402
```

Proven settlement (independently auditable):
[0.05 USDC on Base Sepolia](https://sepolia.basescan.org/tx/0x64a0a2d15d9dd4e33c419c0af1289acf30b0eea074630ab177e9760bff430834)
— two consecutive live runs produced exactly this one transfer.

## Human-in-the-loop path

When the invoice exceeds policy (amount cap, weekly allowance, or unknown
merchant), the job **parks durably** instead of failing:

```bash
UNBLOCK_APPROVAL_TOKENS='{"akiyuki": "<token>"}' \
  uv run uvicorn demo.approval_server:app --port 8403   # v1 approval API
# a human (authenticated by token) then:
POST /v1/approvals/{job_id}/decision  {"action": "REJECT"}   # or APPROVE
```

REJECT completes the job from a free fallback source — **no payment ever
happens**. APPROVE pays under the exact digest-pinned terms the human saw.
Decisions are terminal: the first one wins, replays and flips are refused.

## Architecture

```
Strands Agent (Bedrock Sonnet 4.5)          <- sequences tools, no authority
  |  scan_site / unblock_incident
  v
Demo pipeline (unblock.demo_pipeline)       <- deterministic: detect, strict
  |                                            5-field intel validation,
  |                                            single-file fix, verify, PR
  v
UNBLOCK (unblock.Unblock)                   <- policy (ALLOW/ASK/DENY),
  |                                            durable ledger, idempotent
  |                                            settlement, crash reconcile,
  |                                            v1 human approval API
  v
Rails: mock | file | x402                   <- x402 = real USDC on Base
  |                                            Sepolia via x402.org
  v                                            facilitator (EIP-3009)
Link Intelligence merchant (demo/)          <- self-hosted DEMO merchant:
                                               402-paywalled /intel, fixture
                                               allowlist rejected pre-payment
```

Safety properties (all enforced in deterministic code, all tested):

- **The model has no money authority.** It can only call tools whose payment
  decisions are made by `unblock.policy.evaluate` — a pure function.
- **Idempotency by construction.** job/invoice ids derive from the incident;
  the ledger refuses double settlement across retries, races, and a real
  `os._exit` crash between payment and fix (tested with an on-disk rail).
- **Digest-pinned terms.** The invoice digest covers merchant, id, amount,
  currency, and the per-incident query URL — approving one purchase can never
  authorize a different one, and the PR records the digest.
- **Strict paid-response validation.** Exactly five fields
  (`broken_url/status/final_url/suggested_replacement/observed_at`), strict
  types, and the response's `broken_url` must match the incident — a paid
  answer for one incident can never repair another.
- **Blast-radius-limited fixes.** One allowlisted file; replacements must
  resolve inside the site and exist.

## Names

The package, the distribution, the import and the control class are all
`unblock` / `Unblock`. There was a period when the code called the control
layer `Clerk` and shipped as `allowance-clerk`; that name is gone from the
public surface, with no compatibility shim, because nothing outside this repo
ever imported it. `docs/gate-a-evidence.md` still shows the old names in the
commands that were actually run at the time — rewriting them would falsify a
record of what was measured.

Environment variables moved with it, and the old names are **not** read as a
fallback: silently picking up `CLERK_WALLET_FILE` could pay from a wallet the
caller did not mean to use.

| was | is |
|-----|-----|
| `CLERK_WALLET_FILE` | `UNBLOCK_WALLET_FILE` |
| `CLERK_APPROVAL_TOKENS` | `UNBLOCK_APPROVAL_TOKENS` |
| `CLERK_DB` | `UNBLOCK_DB` |
| `CLERK_PREVIEW_TOKEN` | `UNBLOCK_PREVIEW_TOKEN` |

## Reproduction prerequisites

- Python 3.12 + [uv](https://docs.astral.sh/uv/) (`uv sync` installs deps)
- **Bedrock**: an IAM key with `bedrock:InvokeModel` (us-east-1, Anthropic
  models enabled). Pass it as `BEDROCK_KEY_FILE` (IAM console JSON export or
  flat `AccessKeyId`/`SecretAccessKey`).
- **Live x402 only**: a Base Sepolia wallet JSON (`{"private_key": ...}`)
  holding testnet USDC (gas is paid by the facilitator), and the local
  merchant from `demo/merchant.py`.
- Tests need neither: `uv run pytest tests/ -q` is fully offline.

The merchant here is deliberately **self-hosted demo infrastructure** so the
402 terms, response schema, and failure fixtures are pinned to this repo and
the demo cannot be broken by third-party outages.

## License

Apache-2.0
