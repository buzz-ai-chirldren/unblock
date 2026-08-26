# Gate A Evidence — Allowance Clerk

Formal verdict: **PASS** (independent audit by Codex, 2026-08-26, MyTeam channel).
Audited commit: `93f177de03b3d0a9f4084b71ebc83371d974a4c3` (tag: `gate-a-pass`).
Test suite at that commit: `uv run pytest tests/ -q` → **14 passed**.

All on-chain settlements below are on **Base Sepolia** (`eip155:84532`), USDC
`0x036CbD53842c5426634e7929541eC2318f3dCF7e` (6 decimals), settled by the
public facilitator `https://x402.org/facilitator` (facilitator submits
EIP-3009 `transferWithAuthorization` and pays gas; the payer wallet holds
USDC only, no ETH).

| Role | Address |
|------|---------|
| payer (clerk wallet) | `0x137dD6658Abb749A6B0197477c674A1e49C210dc` |
| merchant (demo receiver) | `0xBb3f0B20D21b3e34769C8762CC6A5598Ac20788E` |

Funding: 3.00 USDC testnet from Circle faucet via owner, tx
`0x46a63cef2bf691f96daad1755be9e86b01bcbb795fc36a3a4cc76a58671ba979`.

## Gate A items and their evidence

### 1. Strands structured tool call → deterministic clerk

`demo/poc_strands.py`: a Strands `Agent` (model `claude-opus-5`) calls
`@tool fetch_paid_resource(invoice_id: str, amount_usdc: str, url: str)` with
structured args; the tool delegates to the deterministic policy/ledger. The
LLM never decides whether money moves — it only relays the clerk's verdict.

Measured run (mock rail, 2026-08-26):

- structured args recorded in the ledger: `invoice_id="inv-strands-001"`,
  `amount_usdc="0.05"`, `url="http://127.0.0.1:8402/premium-data"`
- job `job-inv-strands-001` → **DONE**, invoice **PAID**, mock receipt stored
- the agent relayed the receipt and spontaneously flagged that rail=mock moved
  no real funds — the honesty property held without being prompted for it

Bonus end-to-end (Strands → clerk → real x402, same commit):

- tx [`0x254b30110bf9d2db0ec63d4bcffb226b4c6357605b4d6c5f29aa401c3e7f6ff3`](https://sepolia.basescan.org/tx/0x254b30110bf9d2db0ec63d4bcffb226b4c6357605b4d6c5f29aa401c3e7f6ff3)
  — status `0x1`, block 45,980,731, exactly one USDC Transfer log,
  payer → merchant, 0.05 USDC
- job **DONE**, receipt stores tx/network/facilitator

A first x402 attempt hit a transient 402 (rail refused **before signing**,
zero funds moved) and parked the job as `WAITING_APPROVAL` — live proof that
transient rail failures fall to the safe side instead of paying blindly. An
isolation test paid the rail directly (outside the clerk), tx
`0x684e3ad02ce99ba42475e434a94533ac958943a6ae5335d41ce23401e44e11fa`
(0.05 USDC), confirming rail/merchant/facilitator health; the retry on a
fresh ledger then succeeded end-to-end.

Engineering note fixed at `93f177d`: Strands executes tools on a worker
thread; SQLite connections are thread-bound, so the demo builds a fresh
`Ledger`/`Clerk` per tool call (fresh-connection safety is proven by the
restart tests).

### 2. Durable ASK → approve → resume

`tests/` cover: park to `WAITING_APPROVAL`, close all connections, reopen
fresh `Ledger`/`Clerk` (twice), approve, resume to DONE
(`test_restart_with_fresh_connections_ask_approve_resume`). Approvals are
**terminal** (PK `(merchant, invoice_id)`; first APPROVED/REJECTED decision
wins, reversal is a no-op) and **digest-bound** (sha256 over
`merchant|id|amount|currency|memo` fixed at claim time — approving different
terms authorizes nothing, `test_approval_for_other_terms_authorizes_nothing`).

### 3. Real x402 settlement on Base Sepolia

Clerk-driven payment (commit `7c74e54`, full state machine:
policy → claim → idempotent gate → rail → receipt):

- invoice `local-x402-merchant/inv-x402-001`, 0.05 USDC
- tx [`0xa6b5b1d37e27c1e227de99688092e884164064f9897f8845b2fc1981c877024a`](https://sepolia.basescan.org/tx/0xa6b5b1d37e27c1e227de99688092e884164064f9897f8845b2fc1981c877024a)
  — status `0x1`, block 45,980,466, exactly one USDC Transfer log,
  payer → merchant, `0xc350` = 50,000 atomic = 0.05 USDC
- unpaid `GET` → HTTP 402 with `payment-required` header measured beforehand;
  facilitator `exact`/`eip155:84532` support confirmed via `/supported`
- live per-invoice guard test: merchant demanding $0.05 against an approved
  $0.01 invoice was refused **before signing** (parked, zero funds moved)

### 4. Receipt persisted → original job DONE

Ledger rows after the run: invoice state=**PAID** with receipt JSON
(tx, network `eip155:84532`, facilitator, amount, settled_at); job
`job-x402-1` state=**DONE**. Same shape verified in both x402 runs above.

### 5. No double-pay: sequential, concurrent, crash

- **Sequential**: re-running the paid invoice returned the identical receipt
  (same tx, same settled_at), job result `already-paid`, payer balance
  unchanged, and the chain shows exactly one Transfer for the tx.
- **Concurrent**: two full `run_job` processes race on one invoice — external
  rail file records exactly one settlement; loser parks, winner DONE.
- **Crash**: child process killed with `os._exit(17)` immediately after rail
  settle (before receipt write). Parent observes ledger=PAYING with 1 rail
  settlement; retry does **not** pay (parks), and `reconcile()` adopts the
  receipt from the rail's own settlement lookup (PAYING→PAID, still exactly
  one payment). Rail failures are split into `RailError` (provably refused
  before signing → retryable ASK) vs `SettlementUncertain` (an authorization
  may exist → stay PAYING, reconcile only); the x402 SDK's exceptions are
  pinned to the latter by test.

## Balance ledger (public RPC, 2026-08-26)

| Event | payer | merchant |
|-------|-------|----------|
| after faucet funding | 3.00 | 0.00 |
| item 3 clerk payment (`0xa6b5…024a`) | 2.95 | 0.05 |
| isolation direct-rail tx (`0x684e…11fa`) | 2.90 | 0.10 |
| Strands→x402 payment (`0x254b…6ff3`) | 2.85 | 0.15 |

Every USDC movement from the payer wallet is accounted for by the three
transactions above; each tx carries exactly one Transfer log.

## Reproduce

```bash
uv sync && uv run pytest tests/ -q          # 14 passed

# merchant (terminal 1) — receiving address only, no keys
MERCHANT_ADDRESS=0xBb3f0B20D21b3e34769C8762CC6A5598Ac20788E \
MERCHANT_PRICE='$0.05' uv run uvicorn demo.merchant:app --port 8402

# clerk-driven real payment (terminal 2)
CLERK_WALLET_FILE=/path/to/payer-wallet.json uv run python demo/poc_x402.py

# Strands agent end-to-end (needs ANTHROPIC_API_KEY)
uv run python demo/poc_strands.py                          # mock rail
CLERK_WALLET_FILE=/path/to/payer-wallet.json \
uv run python demo/poc_strands.py --rail x402 --db demo/fresh.db
```

Note: public Base Sepolia RPCs (`sepolia.base.org`, `*.drpc.org`,
`*.publicnode.com`) reject requests without a `User-Agent` header (403).
