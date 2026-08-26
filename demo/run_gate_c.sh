#!/usr/bin/env bash
# Gate C, one command: acceptance proofs (tests) + the live LLM demo.
#
#   BEDROCK_KEY_FILE=<iam-key.json> demo/run_gate_c.sh
#
# 1-3 of the acceptance criteria are proven by tests/test_unblock.py:
#   1. detect -> paid link intel -> single-file fix -> verify -> PR, one job id
#   2. over-cap purchase parks; human REJECT completes from a free source
#      (and APPROVE completes paid) via the v1 approval API
#   3. retries and a real process crash: settlement count stays 1, one PR
# The live run then shows a Strands agent (Bedrock) driving the same pipeline.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Gate C acceptance tests =="
uv run pytest tests/test_unblock.py -q

echo "== Full suite =="
uv run pytest tests/ -q

echo "== Live LLM orchestrator (fresh run dir) =="
rm -rf demo/unblock_run
uv run python demo/poc_unblock.py "$@"
