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


STAGES = ("detect", "policy", "pay", "fetch", "fix", "verify", "pr")


def test_span_map_and_hygiene(tmp_path):
    EXPORTER.clear()
    incident = run_pipeline(tmp_path)
    spans = EXPORTER.get_finished_spans()

    # Exactly one job root, carrying the job id and outcome.
    (job,) = [s for s in spans if s.name == "unblock.job"]
    assert job.parent is None
    assert job.attributes["unblock.job_id"] == incident.job_id
    assert job.attributes["unblock.status"] == "done-paid"

    # The job trace contains each of the 7 stages exactly once, every one a
    # DIRECT child of the job root - including detect.
    stage_spans = [s for s in spans
                   if s.context.trace_id == job.context.trace_id and s is not job]
    assert sorted(s.name for s in stage_spans) == sorted(STAGES)
    for s in stage_spans:
        assert s.parent.span_id == job.context.span_id, f"{s.name} not rooted at job"

    # Stage outcomes are recorded.
    by_name = {s.name: s for s in stage_spans}
    assert by_name["detect"].attributes["unblock.still_broken"] is True
    assert by_name["policy"].attributes["clerk.decision"] == "ALLOW"
    assert by_name["pay"].attributes["clerk.rail"] == "mock"
    assert by_name["fetch"].attributes["unblock.intel_valid"] is True
    assert by_name["verify"].attributes["unblock.resolved"] is True

    # The standalone scan is its own trace, never mixed into the job trace.
    scans = [s for s in spans if s.name == "scan"]
    assert scans
    for s in scans:
        assert s.context.trace_id != job.context.trace_id

    # Hygiene: no attribute anywhere carries the paid body or the intel JSON.
    for s in spans:
        for value in (s.attributes or {}).values():
            assert "suggested_replacement" not in str(value)
            assert "observed_at" not in str(value)
