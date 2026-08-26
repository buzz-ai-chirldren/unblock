"""Observability: one trace per job, the documented span map, and no secret
or paid-body material in any attribute."""

import json
import shutil
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from clerk.jobs import Clerk  # noqa: E402
from clerk.ledger import Ledger  # noqa: E402
from clerk.policy import Policy  # noqa: E402
from clerk.rails import MockRail  # noqa: E402
from unblock import IntelOffer, Unblock, detect  # noqa: E402

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "site"
BROKEN = "guides/install.md"
INTEL = json.dumps({"broken_url": BROKEN, "status": 404, "final_url": None,
                    "suggested_replacement": "docs/setup.md",
                    "observed_at": "2026-08-26T00:00:00Z"})

EXPORTER = InMemorySpanExporter()


@pytest.fixture(scope="module", autouse=True)
def provider():
    p = TracerProvider()
    p.add_span_processor(SimpleSpanProcessor(EXPORTER))
    trace.set_tracer_provider(p)  # global; safe - other tests ignore spans
    yield


def run_pipeline(tmp_path):
    site = tmp_path / "site"
    shutil.copytree(FIXTURE, site)
    rail = MockRail(paid_body=INTEL)
    policy = Policy(currency="USDC", weekly_allowance=Decimal("5.00"),
                    per_invoice_cap=Decimal("1.00"),
                    merchant_allowlist=frozenset({"intel.example"}))
    offer = IntelOffer("intel.example", Decimal("0.05"), url="http://intel.example/intel")
    pipeline = Unblock(site, "index.md",
                       lambda: Clerk(Ledger(tmp_path / "ledger.db"), policy, rail),
                       offer, tmp_path / "prs")
    (incident,) = detect(site)
    result = pipeline.run(incident)
    assert result["status"] == "done-paid"
    return incident


def test_span_map_and_hygiene(tmp_path):
    EXPORTER.clear()
    incident = run_pipeline(tmp_path)
    spans = EXPORTER.get_finished_spans()
    by_name = {s.name: s for s in spans}

    # The documented span map is present.
    for name in ("unblock.job", "detect", "policy", "pay", "fetch", "fix", "verify", "pr"):
        assert name in by_name, f"missing span {name}"

    # One trace, rooted at the job span, which carries the job id.
    job = by_name["unblock.job"]
    assert job.parent is None
    assert job.attributes["unblock.job_id"] == incident.job_id
    assert job.attributes["unblock.status"] == "done-paid"
    in_trace = [s for s in spans if s.context.trace_id == job.context.trace_id]
    for name in ("policy", "pay", "fetch", "fix", "verify", "pr"):
        assert by_name[name].context.trace_id == job.context.trace_id

    # Stage outcomes are recorded.
    assert by_name["policy"].attributes["clerk.decision"] == "ALLOW"
    assert by_name["pay"].attributes["clerk.rail"] == "mock"
    assert by_name["fetch"].attributes["unblock.intel_valid"] is True
    assert by_name["verify"].attributes["unblock.resolved"] is True

    # Hygiene: no attribute anywhere carries the paid body or the intel JSON.
    for s in in_trace:
        for value in (s.attributes or {}).values():
            assert "suggested_replacement" not in str(value)
            assert "observed_at" not in str(value)
