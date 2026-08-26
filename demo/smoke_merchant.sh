#!/usr/bin/env bash
# Smoke test for a deployed Link Intelligence merchant (local or public).
#
#   demo/smoke_merchant.sh [BASE_URL]   # default http://127.0.0.1:8402
#
# Checks, without paying: /health is up and advertises Base Sepolia terms,
# an allowlisted query is 402-paywalled, and an unknown query is rejected
# with 400 BEFORE any payment challenge. The paid response schema itself is
# covered by tests/test_unblock.py (strict 5-field validation) and the live
# x402 run in demo/poc_unblock.py --rail x402.
set -euo pipefail
BASE="${1:-http://127.0.0.1:8402}"
KNOWN="guides%2Finstall.md"

fail() { echo "SMOKE FAIL: $1" >&2; exit 1; }

health=$(curl -sf "$BASE/health") || fail "/health unreachable"
echo "$health" | grep -q '"network":"eip155:84532"' || fail "wrong network in /health: $health"
echo "ok: /health $health"

code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/intel?broken_url=$KNOWN")
[ "$code" = "402" ] || fail "known broken_url expected 402, got $code"
echo "ok: known query is paywalled (402)"

code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/intel?broken_url=not-in-allowlist.md")
[ "$code" = "400" ] || fail "unknown broken_url expected 400, got $code"
echo "ok: unknown query rejected before payment (400)"

code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/intel")
[ "$code" = "400" ] || fail "missing broken_url expected 400, got $code"
echo "ok: missing query rejected before payment (400)"

echo "SMOKE PASS: $BASE"
