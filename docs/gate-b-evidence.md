# Gate B Evidence — the human approval boundary, across process boundaries

Run: **2026-08-27T08:17:20Z**, commit `965cfaa7e87a166f9fef280bebea8d31035aeeca`,
clean tree (0 modified paths, checked by the script itself).

**process-live / mock rail.** No network, no wallet, no x402, no real money.
The rail is `FileRail`, a mock that records settlements in its own SQLite file,
so the counts below are taken from *outside* every process that could have
paid. Nothing here settles anything on any chain. The real x402 settlements are
Gate A and Gate C, recorded separately in `docs/gate-a-evidence.md`.

Reproduce:

```bash
demo/run_gate_b.sh
```

## Why it runs as separate processes

Gate B's claim is durability: a job parked for a human survives the death of
the process that parked it, and the decision that releases it settles exactly
once no matter how many processes replay it.

A single-process script cannot show that. It would be arguing about persistence
from inside the very memory the argument is about — the job would still be in
RAM, and "it is still there" would prove nothing. So each step is a separate OS
process, and everything shared between them is on disk: UNBLOCK's ledger, and
the rail's own settlement file. The PIDs below are the point, not decoration.

Three different processes touch each job:

1. a step process submits the invoice and exits,
2. the **uvicorn approval server** (pid 4127136) takes the authenticated
   decision and resumes the job — payment happens here, in a process that never
   saw step 1,
3. further step processes replay `resume`, and must not be charged again.

`MockRail`, the launcher's default, keeps settlements in the server's own
memory, so a run against it could never show that a replay did not pay twice —
the count would come out right by luck. `UNBLOCK_RAIL_FILE` selects the file
rail for exactly this reason.

## Result

Policy: `$0.10` per request, `$1.00` a week, one allowlisted merchant. Every
invoice below is `$0.50` — over the per-request cap, so policy returns ASK.

### APPROVE

| # | process | action | result | settlements |
|---|---------|--------|--------|-------------|
| 1 | step, pid 4127169 | `run_job` $0.50 | `WAITING_APPROVAL` | **0** |
| 2 | server, pid 4127136 | `POST /v1/approvals/job-approve/decision {"action":"APPROVE"}` | **HTTP 200** — `action_in_effect: APPROVED`, `state: DONE` | **1** |
| 3 | step, pid 4127175 | `resume` | `DONE` | **1** |
| 4 | step, pid 4127197 | `resume` again | `DONE` | **1** |
| 5 | server | same decision re-sent | **HTTP 200**, idempotent | **1** |
| 6 | server | opposite decision `REJECT` | **HTTP 409**, refused | **1** |
| 7 | step, pid 4127222 | read state | `DONE` | **1** |

### REJECT

| # | process | action | result | settlements |
|---|---------|--------|--------|-------------|
| 1 | step, pid 4127229 | `run_job` $0.50 | `WAITING_APPROVAL` | **0** |
| 2 | server, pid 4127136 | `POST /v1/approvals/job-reject/decision {"action":"REJECT"}` | **HTTP 200** — `action_in_effect: REJECTED`, `state: FAILED` | **0** |
| 3 | step, pid 4127235 | `resume` | `FAILED` | **0** |
| 4 | step, pid 4127239 | `resume` again | `FAILED` | **0** |
| 5 | server | same decision re-sent | **HTTP 200**, idempotent | **0** |
| 6 | server | opposite decision `APPROVE` | **HTTP 409**, refused | **0** |
| 7 | step, pid 4127248 | read state | `FAILED` | **0** |

Counted from the shell, out of the rail's own file, after everything above:

```
threat-intel.example/inv-job-approve  ->  1
TOTAL rows: 1
```

One settlement for the approved job, none for the rejected one, across nine
processes. Two replays each and a re-sent decision each moved neither number.

Nothing was written to the server's stderr.

`FAILED` is the controller's word for "the purchase was not authorised" — not
for a broken job. The demo pipeline layers a free fallback on top, which is
what turns a rejected purchase into a completed job with `paid: none`; that
mapping is covered by `tests/test_unblock.py` and is what the demo video shows.

## Why the 409 matters

There is no resume endpoint. A client that loses the HTTP response recovers by
re-sending the same decision, so that has to be an idempotent 200 (row 5). The
cost of that design is that a late or duplicated *opposite* decision must not
be able to flip a terminal outcome — otherwise a retry storm could unpay an
approved job. Row 6 is that boundary, measured on both branches.

## What this does not show

- **No real settlement.** Gate B is the approval boundary. The payment rail is
  proven separately, on chain, in `docs/gate-a-evidence.md`.
- **No LLM.** No model is anywhere in the approval path, by design.
- **Not a crash test.** Each step exits normally. The kill-between-settle-and-
  record case is `tests/test_unblock.py::test_process_crash_between_pay_and_fix_recovers`,
  which uses a real `os._exit`.
- Tokens are generated per run and never printed, so this transcript is
  publishable as-is.
