"""UNBLOCK pipeline: detect a broken link, buy the information needed to fix
it through the allowance clerk, repair exactly one allowlisted file, verify,
and emit a PR artifact - all under ONE job id so payment idempotency, durable
approval, and crash recovery are inherited from the clerk unchanged.

Stage map (Gate C):

  detect()        deterministic link check over the site's markdown files
  Unblock.run()   one incident end-to-end:
                    clerk.run_job(job_id, invoice)   -- pay for link intel
                      DONE             -> strict 5-field intel record from the
                                          PAID response body, validated against
                                          THIS incident's broken link
                      WAITING_APPROVAL -> parked; a human decides on the v1
                                          approval API; re-run after
                      FAILED (rejected)-> free fallback source, no payment
                    _apply_fix()  edits ONLY the allowlisted file, refuses
                                  targets that escape the site or don't exist
                    detect() again must show this incident gone
                    _write_pr()   atomic exclusive create: one PR per job id

Idempotency by construction: incident_id (and so job_id / invoice_id) is a
hash of (file, link); the clerk never settles the same invoice twice; the fix
is a no-op when already applied; the PR file is created with O_EXCL. Re-running
after any crash converges to the same single settlement and single PR.

The LLM orchestrator (demo/poc_unblock.py) only sequences these calls; every
safety property lives in this deterministic code and the clerk beneath it.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Callable
from urllib.parse import quote

from opentelemetry import trace

from clerk.jobs import Clerk
from clerk.policy import Invoice

_tracer = trace.get_tracer("unblock")

_LINK = re.compile(r"\[[^\]]*\]\(([^)#?\s]+)(?:[#?][^)]*)?\)")

# The paid link-intelligence record: exactly these fields, exactly these types.
# bool is excluded from "int" explicitly (isinstance(True, int) is True).
INTEL_FIELDS: dict[str, tuple[type, ...]] = {
    "broken_url": (str,),
    "status": (int,),
    "final_url": (str, type(None)),
    "suggested_replacement": (str,),
    "observed_at": (str,),
}


@dataclass(frozen=True)
class Incident:
    file: str  # path of the markdown file, relative to the site root
    link: str  # the broken target exactly as written

    @property
    def incident_id(self) -> str:
        return hashlib.sha256(f"{self.file}|{self.link}".encode()).hexdigest()[:12]

    @property
    def job_id(self) -> str:
        return f"unblock-{self.incident_id}"

    @property
    def invoice_id(self) -> str:
        return f"inv-{self.incident_id}"


@dataclass(frozen=True)
class IntelOffer:
    """The paid link-intelligence source: who to pay, how much, and where the
    x402 resource lives (memo carries the URL so it is digest-pinned)."""

    merchant: str
    amount: Decimal
    currency: str = "USDC"
    url: str = ""


def detect(site_dir: Path) -> list[Incident]:
    """Deterministic link check: every relative markdown link must resolve to
    an existing file INSIDE the site. External schemes are out of scope."""
    site_dir = site_dir.resolve()
    with _tracer.start_as_current_span("detect") as span:
        incidents = []
        for md in sorted(site_dir.rglob("*.md")):
            rel = str(md.relative_to(site_dir))
            for target in _LINK.findall(md.read_text()):
                if "://" in target or target.startswith("mailto:"):
                    continue
                resolved = (md.parent / target).resolve()
                if not resolved.is_relative_to(site_dir) or not resolved.exists():
                    incidents.append(Incident(file=rel, link=target))
        span.set_attribute("unblock.broken_links", len(incidents))
        return incidents


class Unblock:
    def __init__(
        self,
        site_dir: Path,
        allowed_file: str,
        clerk_factory: Callable[[], Clerk],
        offer: IntelOffer,
        pr_dir: Path,
        free_sources: dict[str, str] | None = None,
    ):
        self.site_dir = Path(site_dir).resolve()
        self.allowed_file = allowed_file  # the ONE file this pipeline may edit
        self.clerk_factory = clerk_factory
        self.offer = offer
        self.pr_dir = Path(pr_dir)
        self.pr_dir.mkdir(parents=True, exist_ok=True)
        self.free_sources = free_sources or {}

    # -- public ---------------------------------------------------------------

    def run(self, incident: Incident) -> dict:
        """One incident end-to-end under a single trace root carrying the
        job id; every stage below emits a child span (clerk adds policy/pay)."""
        with _tracer.start_as_current_span("unblock.job", attributes={
            "unblock.job_id": incident.job_id,
            "unblock.incident_id": incident.incident_id,
            "unblock.file": incident.file,
            "unblock.link": incident.link,
        }) as span:
            result = self._run(incident)
            span.set_attribute("unblock.status", result["status"])
            return result

    def _run(self, incident: Incident) -> dict:
        pr_path = self.pr_dir / f"{incident.job_id}.md"
        if pr_path.exists():
            return {"status": "already-done", "job_id": incident.job_id, "pr": str(pr_path)}
        if incident.file != self.allowed_file:
            # Guardrail BEFORE any payment: this pipeline may only repair the
            # allowlisted file. Everything else needs a human, not an agent.
            return {"status": "refused-file", "job_id": incident.job_id,
                    "why": "file is not in the repair allowlist"}

        invoice = self._invoice(incident)
        clerk = self.clerk_factory()
        try:
            state = clerk.run_job(incident.job_id, invoice, work=f"buy link intel for {incident.link}")
            if state == "WAITING_APPROVAL":
                return {"status": "waiting-approval", "job_id": incident.job_id,
                        "approve_via": f"POST /v1/approvals/{incident.job_id}/decision"}
            if state == "FAILED":
                # Human rejected (or policy denied) the purchase: complete the
                # job from a free source instead of paying anyone.
                new_target = self.free_sources.get(incident.link)
                if new_target is None:
                    return {"status": "failed", "job_id": incident.job_id,
                            "why": "purchase not authorized and no free source known"}
                source = {"kind": "free-fallback", "receipt": None}
            else:  # DONE - paid now, or already paid on an earlier (crashed) run
                with _tracer.start_as_current_span("fetch") as span:
                    receipt = clerk.ledger.receipt(invoice) or {}
                    new_target = self._replacement_from(receipt, incident.link)
                    span.set_attribute("unblock.intel_valid", new_target is not None)
                if new_target is None:
                    return {"status": "failed", "job_id": incident.job_id,
                            "why": "paid response failed strict intel validation "
                                   "(schema, types, or broken_url mismatch)"}
                source = {"kind": "paid", "receipt": {
                    k: receipt.get(k) for k in ("rail", "network", "facilitator", "tx", "amount", "currency")
                }}
        finally:
            clerk.ledger.close()

        with _tracer.start_as_current_span("fix") as span:
            diff = self._apply_fix(incident, new_target)
            span.set_attribute("unblock.fix_applied", diff is not None)
        if diff is None:
            return {"status": "failed", "job_id": incident.job_id,
                    "why": "replacement target is unsafe or does not exist"}
        with _tracer.start_as_current_span("verify") as span:
            remaining = detect(self.site_dir)
            resolved = not any(i.incident_id == incident.incident_id for i in remaining)
            span.set_attribute("unblock.resolved", resolved)
        if not resolved:
            return {"status": "failed", "job_id": incident.job_id, "why": "fix did not verify"}
        with _tracer.start_as_current_span("pr") as span:
            self._write_pr(pr_path, incident, invoice, new_target, source, diff, len(remaining))
            span.set_attribute("unblock.pr", pr_path.name)
        status = "done-paid" if source["kind"] == "paid" else "done-free"
        return {"status": status, "job_id": incident.job_id, "pr": str(pr_path),
                "receipt": source["receipt"]}

    # -- internals --------------------------------------------------------------

    def _invoice(self, incident: Incident) -> Invoice:
        """The purchase terms for ONE incident: the query URL (with the exact
        broken link being asked about) rides in memo, so it is part of the
        invoice digest - approving intel for one incident can never authorize
        paying for another's."""
        query_url = f"{self.offer.url}?broken_url={quote(incident.link, safe='')}"
        return Invoice(
            invoice_id=incident.invoice_id, merchant=self.offer.merchant,
            amount=self.offer.amount, currency=self.offer.currency, memo=query_url,
        )

    @staticmethod
    def _replacement_from(receipt: dict, broken_url: str) -> str | None:
        """Strict parse of the paid intel record. Rejects: non-JSON, non-object,
        unknown or missing fields, wrong types, and a record about a different
        broken_url (no cross-incident response replay)."""
        try:
            data = json.loads(receipt.get("resource") or "")
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(data, dict) or set(data) != set(INTEL_FIELDS):
            return None
        for field, types in INTEL_FIELDS.items():
            if isinstance(data[field], bool) or not isinstance(data[field], types):
                return None
        if data["broken_url"] != broken_url:
            return None
        return data["suggested_replacement"]

    def _apply_fix(self, incident: Incident, new_target: str) -> str | None:
        """Replace the broken link with new_target in the allowlisted file only.
        Idempotent: a re-run after the edit already landed returns an empty
        diff instead of touching the file again. Returns None (refusal) when
        the replacement would escape the site or point at nothing."""
        path = (self.site_dir / self.allowed_file).resolve()
        if not path.is_relative_to(self.site_dir):
            return None
        resolved_target = (path.parent / new_target).resolve()
        if not resolved_target.is_relative_to(self.site_dir) or not resolved_target.exists():
            return None
        old = path.read_text()
        new = old.replace(f"({incident.link})", f"({new_target})")
        if new != old:
            path.write_text(new)
        return "".join(difflib.unified_diff(
            old.splitlines(keepends=True), new.splitlines(keepends=True),
            fromfile=f"a/{incident.file}", tofile=f"b/{incident.file}",
        ))

    def _write_pr(self, pr_path: Path, incident: Incident, invoice: Invoice,
                  new_target: str, source: dict, diff: str, remaining: int) -> None:
        receipt = source["receipt"]
        paid_lines = (
            f"- rail: `{receipt['rail']}` / network: `{receipt['network']}`\n"
            f"- payment id (tx): `{receipt['tx']}`\n"
            f"- amount: {receipt['amount']} {receipt['currency']}\n"
            if receipt else
            "- free fallback source; **no payment was made** (purchase rejected or denied)\n"
        )
        terms_lines = (
            f"- merchant: `{invoice.merchant}` / invoice: `{invoice.invoice_id}`\n"
            f"- query: `{invoice.memo}`\n"
            f"- terms: {invoice.amount} {invoice.currency}\n"
            f"- invoice digest: `{invoice.digest()}`\n"
        )
        body = (
            f"# UNBLOCK: repair broken link `{incident.link}`\n\n"
            f"## Incident\n"
            f"- incident: `{incident.incident_id}` / job: `{incident.job_id}`\n"
            f"- file: `{incident.file}`\n"
            f"- broken link: `{incident.link}` -> fixed to: `{new_target}`\n\n"
            f"## Purchase terms (digest-pinned)\n{terms_lines}\n"
            f"## Information source\n{paid_lines}\n"
            f"## Verification\n"
            f"- link check after fix: this incident resolved; {remaining} broken link(s) remaining site-wide\n\n"
            f"## Diff\n```diff\n{diff}```\n"
        )
        try:
            with open(pr_path, "x") as f:  # O_EXCL: at most one PR per job id, ever
                f.write(body)
        except FileExistsError:
            pass
