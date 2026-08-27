"""The pieces the Gate B live pass depends on, pinned so the pass stays honest.

`demo/run_gate_b.sh` is the evidence, and it takes about a minute of real
processes and a real HTTP server, so it is not in this suite. What is here are
the two things that would let that script quietly stop proving anything:

  * the launcher's rail selection. Gate B counts settlements out of a file the
    server does not own. If UNBLOCK_RAIL_FILE stopped selecting FileRail, the
    server would fall back to a rail that keeps its settlements in its own
    memory, every count would read 0 or 1 by luck, and the run would still look
    like a pass.
  * the step driver rebuilding an identical invoice from a job id. A later
    process is handed no invoice; it reconstructs one, and if the digest came
    out different the approval would not bind and `resume` would refuse. A
    passing run depends on that determinism, so it is worth stating.
"""

import importlib
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))

from unblock.rails import FileRail, MockRail  # noqa: E402


def _launcher(monkeypatch, tmp_path, **env):
    for name in ("UNBLOCK_WALLET_FILE", "UNBLOCK_RAIL_FILE", "UNBLOCK_DB"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("UNBLOCK_DB", str(tmp_path / "ledger.db"))
    monkeypatch.setenv("UNBLOCK_APPROVAL_TOKENS", '{"akiyuki": "' + "t" * 32 + '"}')
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return importlib.reload(importlib.import_module("demo.approval_server"))


def test_the_launcher_takes_the_file_rail_when_asked(monkeypatch, tmp_path):
    rail_db = tmp_path / "rail.db"
    server = _launcher(monkeypatch, tmp_path, UNBLOCK_RAIL_FILE=str(rail_db))
    assert isinstance(server.RAIL, FileRail)
    assert server.RAIL.path == str(rail_db)
    assert rail_db.exists(), "the rail must create its file, or nothing can count it"


def test_the_launcher_falls_back_to_the_in_memory_rail(monkeypatch, tmp_path):
    """Default behaviour, unchanged -- and the reason the file rail exists:
    settlements here die with the process, so they cannot be counted from
    outside it."""
    server = _launcher(monkeypatch, tmp_path)
    assert isinstance(server.RAIL, MockRail)


def test_a_wallet_still_wins_over_the_mock(monkeypatch, tmp_path):
    """Rail precedence must not have been reordered by adding a branch to it:
    a run holding a wallet has to keep settling on the real rail."""
    source = (REPO / "demo/approval_server.py").read_text()
    wallet_at = source.index('os.environ.get("UNBLOCK_WALLET_FILE")')
    file_at = source.index('os.environ.get("UNBLOCK_RAIL_FILE")')
    assert wallet_at < file_at, "the file rail must not shadow a configured wallet"


def test_the_step_driver_rebuilds_the_same_invoice_from_the_job_id(tmp_path):
    """Every step process reconstructs the invoice rather than being handed
    one; the approval binds to its digest, so they have to agree."""
    from demo.gate_b_step import invoice_for

    first, second = invoice_for("job-approve", "0.50"), invoice_for("job-approve", "0.50")
    assert first == second and first.digest() == second.digest()
    assert first.amount == Decimal("0.50")
    # A different amount must NOT bind to the same approval.
    assert invoice_for("job-approve", "0.05").digest() != first.digest()


@pytest.mark.parametrize("script", ["demo/run_gate_b.sh"])
def test_the_evidence_script_parses_and_never_prints_its_token(script):
    """The transcript gets published, so the token must not be able to reach
    it: generated in-script, and never echoed."""
    assert subprocess.run(["bash", "-n", str(REPO / script)]).returncode == 0
    body = (REPO / script).read_text()
    assert "token_urlsafe" in body, "the token must be generated per run"
    for leak in ('echo "$TOKEN"', "echo $TOKEN", "echo \"token", "$TOKEN\" >"):
        assert leak not in body, f"the script prints its token: {leak!r}"
