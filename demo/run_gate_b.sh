#!/usr/bin/env bash
# Gate B live pass: the human approval boundary, driven across real process
# boundaries against a real HTTP server.
#
#   demo/run_gate_b.sh
#
# process-live / mock rail. No network, no wallet, no x402, no real money. The
# rail is FileRail, whose settlements land in their own SQLite file so this
# script can count them from OUTSIDE every process that could have paid.
#
# What each step is for:
#   1. a fresh process parks an over-cap invoice and exits. Nothing paid.
#   2. a DIFFERENT process -- the uvicorn approval server -- takes an
#      authenticated APPROVE and resumes the job. This is where payment happens.
#   3. a THIRD, fresh process replays resume. Still DONE, still one settlement.
#      This is the crash-recovery path: there is no resume endpoint, so a
#      client that lost the response re-sends, and must not be charged twice.
#   4. the same three steps for REJECT: the job ends FAILED, nothing settles.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN=$(mktemp -d)
PORT=${GATE_B_PORT:-8404}
# Generated here, never printed, never written to the evidence file.
TOKEN=$(python3 -c "import secrets;print(secrets.token_urlsafe(32))")

cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$RUN"
}
trap cleanup EXIT

run_step() { uv run python demo/gate_b_step.py "$1" "$RUN/ledger.db" "$RUN/rail.db" "${@:2}"; }

echo "=== Gate B live pass — process-live, mock rail (FileRail), no network ==="
echo "date_utc  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "HEAD      $(git rev-parse HEAD)"
echo "tree      $(git status --porcelain | wc -l) modified path(s)"
echo

echo "--- approval API (its own process) ---"
UNBLOCK_APPROVAL_TOKENS="{\"akiyuki\": \"$TOKEN\"}" \
UNBLOCK_DB="$RUN/ledger.db" \
UNBLOCK_RAIL_FILE="$RUN/rail.db" \
  uv run uvicorn demo.approval_server:app --port "$PORT" --log-level warning \
  > "$RUN/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 60); do
  curl -sf -o /dev/null "http://127.0.0.1:$PORT/v1/approvals" \
    -H "Authorization: Bearer $TOKEN" && break
  sleep 0.5
done
echo "server_pid $SERVER_PID  port $PORT  rail FileRail  db shared with the step processes"
echo

decide() {  # job, action -> prints status and body, never the token
  local job=$1 action=$2
  local out
  out=$(curl -sS -o "$RUN/body.json" -w '%{http_code}' \
        -X POST "http://127.0.0.1:$PORT/v1/approvals/$job/decision" \
        -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
        -d "{\"action\": \"$action\"}")
  echo "POST /v1/approvals/$job/decision {\"action\":\"$action\"} -> HTTP $out"
  cat "$RUN/body.json"; echo
}

for case in APPROVE REJECT; do
  job="job-$(echo "$case" | tr 'A-Z' 'a-z')"
  echo "=============================================================="
  echo "case $case  (invoice \$0.50, over the \$0.10 per-request cap)"
  echo "=============================================================="

  echo "--- 1. fresh process: submit ---"
  run_step park "$job" 0.50
  echo

  echo "--- 2. approval server process: authenticated decision ---"
  decide "$job" "$case"
  echo

  echo "--- 3. fresh process: replay resume (lost-response recovery) ---"
  run_step resume "$job"
  echo

  echo "--- 4. fresh process: replay resume AGAIN ---"
  run_step resume "$job"
  echo

  # There is no resume endpoint: a client that lost the HTTP response recovers
  # by re-sending the SAME decision, so that has to be an idempotent 200. The
  # OPPOSITE decision arriving later must not flip a terminal outcome, or a
  # retry storm could unpay an approved job.
  echo "--- 5. same decision re-sent (the documented crash-recovery path) ---"
  decide "$job" "$case"
  echo

  other=$([ "$case" = "APPROVE" ] && echo REJECT || echo APPROVE)
  echo "--- 6. CONFLICTING decision after the fact (must be refused) ---"
  decide "$job" "$other"
  echo

  echo "--- 7. fresh process: state after both replays ---"
  run_step state "$job"
  echo
done

echo "=============================================================="
echo "settlement rows in the rail's own file, counted from this shell"
echo "=============================================================="
uv run python - "$RUN/rail.db" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
for key, n in conn.execute("SELECT key, COUNT(*) FROM settlements GROUP BY key ORDER BY key"):
    print(f"  {key}  ->  {n}")
print(f"  TOTAL rows: {conn.execute('SELECT COUNT(*) FROM settlements').fetchone()[0]}")
conn.close()
PY
echo
echo "server stderr (should be empty):"
grep -vE '^\s*$' "$RUN/server.log" | grep -viE 'INFO|Started|Waiting|Application|Uvicorn|Finished|Shutting|complete' || echo "  (none)"
