"""UNBLOCK Gate C mechanics on the deterministic pipeline.

The rail settlement count stays the money oracle (FileRail for cross-process
observation). Properties under test: real broken-link detection on the fixture
site, one job id from purchase to PR, edits confined to the single allowlisted
file with no escape via hostile replacement targets, verification after fix,
PR artifacts cross-referencing incident/receipt/verification, zero extra
settlements and zero duplicate PRs across retries and a real process crash,
and the park -> human decision (v1 approval API) -> free-fallback/paid paths.
"""

import json
import multiprocessing
import os
import shutil
import sys
from decimal import Decimal
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from unblock.approval_api import create_app  # noqa: E402
from unblock import Unblock  # noqa: E402
from unblock import Ledger  # noqa: E402
from unblock.policy import Policy  # noqa: E402
from unblock.rails import FileRail, MockRail  # noqa: E402
from unblock.demo_pipeline import Incident, IncidentPipeline, IntelOffer, detect  # noqa: E402

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "site"
BROKEN_LINK = "guides/install.md"
GOOD_TARGET = "docs/setup.md"


def intel_body(broken=BROKEN_LINK, target=GOOD_TARGET, **overrides):
    record = {"broken_url": broken, "status": 404, "final_url": None,
              "suggested_replacement": target, "observed_at": "2026-08-26T00:00:00Z"}
    record.update(overrides)
    return json.dumps(record)


INTEL_BODY = intel_body()

POLICY = Policy(
    currency="USDC",
    weekly_allowance=Decimal("5.00"),
    per_invoice_cap=Decimal("1.00"),
    merchant_allowlist=frozenset({"intel.example"}),
)
CHEAP = IntelOffer("intel.example", Decimal("0.05"), url="http://intel.example/db")
PRICEY = IntelOffer("intel.example", Decimal("20.00"), url="http://intel.example/premium-db")

TOKENS = {"akiyuki": "owner-token"}
AUTH = {"Authorization": f"Bearer {TOKENS['akiyuki']}"}


def make_site(tmp_path) -> Path:
    site = tmp_path / "site"
    shutil.copytree(FIXTURE, site)
    return site


def make_pipeline(tmp_path, site, rail, offer=CHEAP, free_sources=None):
    db = tmp_path / "ledger.db"

    def factory():
        return Unblock(Ledger(db), POLICY, rail)

    return IncidentPipeline(site, "index.md", factory, offer, tmp_path / "prs",
                            free_sources=free_sources), factory


# -- detection -----------------------------------------------------------------

def test_detect_finds_seeded_broken_link(tmp_path):
    site = make_site(tmp_path)
    incidents = detect(site)
    assert [(i.file, i.link) for i in incidents] == [("index.md", BROKEN_LINK)]
    (incident,) = incidents
    assert incident.job_id == f"unblock-{incident.incident_id}"  # stable, derived
    assert detect(site) == incidents  # deterministic


# -- the paid happy path: one job id from purchase to PR -------------------------

def test_e2e_paid_fix_verifies_and_prs(tmp_path):
    site = make_site(tmp_path)
    rail = MockRail(paid_body=INTEL_BODY)
    pipeline, _ = make_pipeline(tmp_path, site, rail)
    (incident,) = detect(site)

    result = pipeline.run(incident)
    assert result["status"] == "done-paid"
    assert result["job_id"] == incident.job_id
    assert rail.settled == [f"intel.example/{incident.invoice_id}"]  # exactly one settlement
    assert f"({GOOD_TARGET})" in (site / "index.md").read_text()
    assert detect(site) == []  # all link checks pass after the fix

    pr = Path(result["pr"]).read_text()
    assert incident.incident_id in pr and incident.job_id in pr          # incident refs
    assert rail.receipts[f"intel.example/{incident.invoice_id}"]["tx"] in pr  # receipt ref
    assert "0 broken link(s) remaining" in pr                            # verification ref
    assert f"-- [Install guide]({BROKEN_LINK})" in pr.replace("\r", "")  # diff included
    assert "0.05 USDC" in pr
    invoice = pipeline._invoice(incident)
    assert invoice.digest() in pr and invoice.memo in pr  # purchase terms pinned


# -- retries and a real process crash: 0 extra settlements, 0 duplicate PRs ------

def test_rerun_is_idempotent(tmp_path):
    site = make_site(tmp_path)
    rail = MockRail(paid_body=INTEL_BODY)
    pipeline, _ = make_pipeline(tmp_path, site, rail)
    (incident,) = detect(site)

    first = pipeline.run(incident)
    again = pipeline.run(incident)
    assert (first["status"], again["status"]) == ("done-paid", "already-done")
    assert len(rail.settled) == 1
    assert len(list((tmp_path / "prs").iterdir())) == 1


class _CrashAfterPay(IncidentPipeline):
    def _apply_fix(self, incident, new_target):
        os._exit(17)  # payment settled and recorded; fixer never ran


def _crash_worker(site, tmp_dir, rail_db):
    tmp_path = Path(tmp_dir)
    db = tmp_path / "ledger.db"

    def factory():
        return Unblock(Ledger(db), POLICY, FileRail(rail_db, paid_body=INTEL_BODY))

    pipeline = _CrashAfterPay(Path(site), "index.md", factory, CHEAP, tmp_path / "prs")
    pipeline.run(detect(Path(site))[0])


def test_process_crash_between_pay_and_fix_recovers(tmp_path):
    site = make_site(tmp_path)
    rail_db = str(tmp_path / "rail.db")
    (incident,) = detect(site)

    p = multiprocessing.Process(target=_crash_worker, args=(str(site), str(tmp_path), rail_db))
    p.start()
    p.join(timeout=60)
    assert p.exitcode == 17

    rail = FileRail(rail_db)
    invoice_key_settlements = rail.settle_count(
        type("I", (), {"merchant": "intel.example", "invoice_id": incident.invoice_id})()
    )
    assert invoice_key_settlements == 1          # money moved exactly once...
    assert f"({BROKEN_LINK})" in (site / "index.md").read_text()  # ...but no fix yet
    assert not list((tmp_path / "prs").iterdir())                 # and no PR

    # Retry with a fresh process-equivalent pipeline: reuses the recorded
    # receipt, never pays again, single PR.
    pipeline, _ = make_pipeline(tmp_path, site, rail)
    result = pipeline.run(incident)
    assert result["status"] == "done-paid"
    assert rail.settle_count(
        type("I", (), {"merchant": "intel.example", "invoice_id": incident.invoice_id})()
    ) == 1
    assert detect(site) == []
    assert len(list((tmp_path / "prs").iterdir())) == 1


# -- the fixer can only ever touch the one allowlisted file ----------------------

def test_non_allowlisted_file_is_refused_before_payment(tmp_path):
    site = make_site(tmp_path)
    (site / "docs" / "setup.md").write_text("# Setup\n\nSee [old page](missing/page.md).\n")
    rail = MockRail(paid_body=INTEL_BODY)
    pipeline, _ = make_pipeline(tmp_path, site, rail)

    other = next(i for i in detect(site) if i.file != "index.md")
    result = pipeline.run(other)
    assert result["status"] == "refused-file"
    assert rail.settled == []  # refused BEFORE any payment
    assert "missing/page.md" in (site / "docs" / "setup.md").read_text()  # untouched


def test_hostile_replacement_targets_are_refused(tmp_path):
    outside = tmp_path / "outside.md"
    outside.write_text("# outside the site\n")
    site = make_site(tmp_path)
    (incident,) = detect(site)
    before = (site / "index.md").read_text()

    for bad_target in ("../outside.md", "does/not/exist.md"):
        rail = MockRail(paid_body=intel_body(target=bad_target))
        pipeline, _ = make_pipeline(tmp_path / bad_target.replace("/", "_"), site, rail)
        result = pipeline.run(incident)
        assert result["status"] == "failed"
        assert (site / "index.md").read_text() == before  # never edited


# -- the paid intel record is strictly validated ---------------------------------

@pytest.mark.parametrize("body", [
    "not json",
    json.dumps(["broken_url"]),                      # not an object
    intel_body(extra_field="x"),                     # unknown field
    json.dumps({"broken_url": BROKEN_LINK}),         # missing fields
    intel_body(status="404"),                        # wrong type
    intel_body(status=True),                         # bool is not an int here
    intel_body(final_url=7),                         # wrong type on optional field
    intel_body(broken="docs/other.md"),              # response replay for another incident
])
def test_malformed_or_replayed_intel_never_edits(tmp_path, body):
    site = make_site(tmp_path)
    rail = MockRail(paid_body=body)
    pipeline, _ = make_pipeline(tmp_path, site, rail)
    (incident,) = detect(site)

    result = pipeline.run(incident)
    assert result["status"] == "failed"
    assert "strict intel validation" in result["why"]
    assert f"({BROKEN_LINK})" in (site / "index.md").read_text()  # untouched
    assert not list((tmp_path / "prs").iterdir())                 # no PR


def test_invoice_digest_binds_the_incident_query(tmp_path):
    site = make_site(tmp_path)
    (site / "docs" / "setup.md").write_text("# Setup\n\nSee [old page](missing/page.md).\n")
    pipeline, _ = make_pipeline(tmp_path, site, MockRail(paid_body=INTEL_BODY))

    first, second = detect(site)
    inv_a, inv_b = pipeline._invoice(first), pipeline._invoice(second)
    assert quote(first.link, safe="") in inv_a.memo   # the question asked is in the terms
    assert inv_a.memo != inv_b.memo                   # different incident, different query...
    assert inv_a.digest() != inv_b.digest()           # ...and a different pinned digest


# -- park -> human decision on the v1 approval API -> fallback or paid -----------

def test_over_cap_parks_then_reject_completes_free(tmp_path):
    site = make_site(tmp_path)
    rail = MockRail(paid_body=INTEL_BODY)
    pipeline, factory = make_pipeline(tmp_path, site, rail, offer=PRICEY,
                                      free_sources={BROKEN_LINK: GOOD_TARGET})
    (incident,) = detect(site)

    parked = pipeline.run(incident)
    assert parked["status"] == "waiting-approval"
    assert rail.settled == []

    # The human rejects the 20 USDC purchase on the existing v1 approval API.
    client = TestClient(create_app(factory, tokens=TOKENS), raise_server_exceptions=False)
    listed = client.get("/v1/approvals", headers=AUTH).json()
    assert [a["job_id"] for a in listed] == [incident.job_id]
    assert listed[0]["reason_code"] == "over-invoice-cap"
    r = client.post(f"/v1/approvals/{incident.job_id}/decision", headers=AUTH,
                    json={"action": "REJECT", "note": "20 USDC is too much for a link"})
    assert r.json()["state"] == "FAILED"

    result = pipeline.run(incident)
    assert result["status"] == "done-free"
    assert result["receipt"] is None
    assert rail.settled == []  # completed WITHOUT paying anyone
    assert detect(site) == []
    assert "no payment was made" in Path(result["pr"]).read_text()


def test_over_cap_parks_then_approve_pays_and_completes(tmp_path):
    site = make_site(tmp_path)
    rail = MockRail(paid_body=INTEL_BODY)
    pipeline, factory = make_pipeline(tmp_path, site, rail, offer=PRICEY)
    (incident,) = detect(site)

    assert pipeline.run(incident)["status"] == "waiting-approval"

    client = TestClient(create_app(factory, tokens=TOKENS), raise_server_exceptions=False)
    r = client.post(f"/v1/approvals/{incident.job_id}/decision", headers=AUTH,
                    json={"action": "APPROVE"})
    assert r.json()["state"] == "DONE"  # decision endpoint resumed and paid

    result = pipeline.run(incident)
    assert result["status"] == "done-paid"
    assert len(rail.settled) == 1  # the approval-driven settlement, nothing more
    assert detect(site) == []
