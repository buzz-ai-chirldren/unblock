"""Human approval API over the clerk's durable ASK queue (Gate B boundary).

Endpoints (every route requires `Authorization: Bearer <token>`):

  GET  /asks                    WAITING_APPROVAL jobs with their PINNED invoice
                                terms (redacted memo) and digest; bounded
                                pagination via limit/offset
  GET  /approvals/{job_id}      detail: job state, pinned terms, effective
                                decision, and the audit event trail
  POST /jobs/{job_id}/decision  record the terminal APPROVED/REJECTED decision
                                for the job's pinned invoice, then resume it.
                                Re-sending the SAME decision is the crash
                                recovery path - there is no resume endpoint.

Threat-model properties (per allowance-clerk-gate-b-threat-model):

- The actor is the authenticated principal: tokens are configured server-side
  as an actor->token map (env CLERK_APPROVAL_TOKENS, JSON). Bodies carry no
  actor. Startup fails on empty maps, empty names/tokens, or duplicate tokens
  (an ambiguous principal is worse than no server).
- Decisions target a job_id only; merchant, amount, and digest are read from
  the ledger row pinned at first claim. No caller input can override them.
- Decisions are race-safe: the ledger INSERT is the only arbiter. Every
  response and every resume branches on the STORED decision, never on the
  caller's requested action. Same-action resend is an idempotent 200;
  a conflicting action is 409 - under sequential calls and under races.
- A first decision is accepted only while the job is WAITING_APPROVAL;
  decorating DONE/FAILED/RUNNING jobs with after-the-fact decisions is 409.
- The decision commit and its audit event are both persisted BEFORE resume is
  attempted; a resume failure appends its own event (exception class only,
  no secrets) and the client recovers by re-sending the same decision.
- Responses never carry receipts, provider responses, credentials, or raw
  memos (a memo may embed URL query tokens; it is redacted at the query
  string). The digest still binds the FULL terms including the raw memo.
- Strict schemas (unknown fields rejected, note capped), request bodies over
  BODY_LIMIT bytes refused, constant-time token compare, tokens never logged,
  stored, or echoed.

SQLite connections are thread-bound and ASGI servers run handlers on worker
threads, so the app builds a fresh Ledger/Clerk per request via the injected
factory (fresh-connection safety is proven by the restart tests).
"""

from __future__ import annotations

import hmac
import json
import os
import uuid
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .jobs import Clerk
from .policy import Invoice

TOKENS_ENV = "CLERK_APPROVAL_TOKENS"  # JSON: {"<actor>": "<token>", ...}
BODY_LIMIT = 16 * 1024


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(pattern="^(APPROVED|REJECTED)$")
    note: str = Field(default="", max_length=500)


def _redacted_memo(memo: str) -> str:
    """Strip anything that can smuggle a secret out through a listing: URL
    query strings / fragments (paywall URLs often carry access tokens)."""
    for sep in ("?", "#"):
        if sep in memo:
            memo = memo.split(sep, 1)[0] + sep + "[redacted]"
            break
    return memo[:200]


def _pinned_terms(clerk: Clerk, invoice: Invoice) -> dict:
    return {
        "merchant": invoice.merchant,
        "invoice_id": invoice.invoice_id,
        "amount": str(invoice.amount),
        "currency": invoice.currency,
        "memo": _redacted_memo(invoice.memo),
        "digest": invoice.digest(),
        "invoice_state": clerk.ledger.state(invoice),
    }


def create_app(clerk_factory: Callable[[], Clerk], tokens: dict[str, str] | None = None) -> FastAPI:
    if tokens is None:
        tokens = json.loads(os.environ.get(TOKENS_ENV) or "{}")
    if (
        not tokens
        or not all(tokens.values())
        or not all(tokens.keys())
        or len(set(tokens.values())) != len(tokens)
    ):
        raise RuntimeError(
            f"{TOKENS_ENV} (JSON actor->token map) must be non-empty with unique, non-empty"
            " actors and tokens: the approval API never runs unauthenticated or ambiguous"
        )

    def authenticated_actor(request: Request) -> str:
        supplied = request.headers.get("Authorization", "")
        matched = None
        # Compare against every configured token so timing does not reveal
        # which actor names exist.
        for actor, token in tokens.items():
            if hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
                matched = actor
        if matched is None:
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")
        return matched

    app = FastAPI()

    @app.middleware("http")
    async def refuse_oversized_bodies(request: Request, call_next):
        length = request.headers.get("content-length")
        if length is not None and length.isdigit() and int(length) > BODY_LIMIT:
            return JSONResponse(status_code=413, content={"detail": "request body too large"})
        return await call_next(request)

    @app.get("/asks")
    def list_asks(
        actor: str = Depends(authenticated_actor),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> list[dict]:
        clerk = clerk_factory()
        try:
            out = []
            for job in clerk.ledger.waiting_jobs(limit=limit, offset=offset):
                invoice = clerk.ledger.invoice_row(job["merchant"], job["invoice_id"])
                if invoice is None:
                    continue
                decision = clerk.ledger.decision(invoice)
                out.append(
                    {
                        "job_id": job["job_id"],
                        "why": job["payload"].get("why", ""),
                        **_pinned_terms(clerk, invoice),
                        "decision": decision[0] if decision else None,
                    }
                )
            return out
        finally:
            clerk.ledger.close()

    @app.get("/approvals/{job_id}")
    def approval_detail(job_id: str, actor: str = Depends(authenticated_actor)) -> dict:
        clerk = clerk_factory()
        try:
            job = clerk.ledger.job(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="unknown job")
            invoice = clerk.ledger.invoice_row(job["merchant"] or "", job["invoice_id"] or "")
            decision = clerk.ledger.decision(invoice) if invoice else None
            return {
                "job_id": job_id,
                "job_state": job["state"],
                "why": job["payload"].get("why", ""),
                **(_pinned_terms(clerk, invoice) if invoice else {}),
                "decision": decision[0] if decision else None,
                "events": clerk.ledger.events(job_id),
            }
        finally:
            clerk.ledger.close()

    @app.post("/jobs/{job_id}/decision")
    def decide(job_id: str, req: DecisionRequest, actor: str = Depends(authenticated_actor)) -> dict:
        request_id = uuid.uuid4().hex
        clerk = clerk_factory()
        try:
            job = clerk.ledger.job(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="unknown job")
            invoice = clerk.ledger.invoice_row(job["merchant"] or "", job["invoice_id"] or "")
            if invoice is None:
                raise HTTPException(status_code=404, detail="job has no pinned invoice")
            digest = invoice.digest()
            state_before = f"{job['state']}/{clerk.ledger.state(invoice)}"

            def event(action: str, outcome: str, state_after: str) -> None:
                clerk.ledger.record_event(
                    request_id, actor, action, outcome, job_id,
                    invoice.merchant, invoice.invoice_id, digest, state_before, state_after,
                )

            # A FIRST decision is only valid for a parked job. (If a decision
            # already exists, fall through: the atomic insert below loses and
            # we branch on the stored action - the resend/conflict paths.)
            if clerk.ledger.decision(invoice) is None and job["state"] != "WAITING_APPROVAL":
                event(req.action, "refused-state", state_before)
                raise HTTPException(
                    status_code=409,
                    detail=f"job is {job['state']}, not WAITING_APPROVAL; decisions cannot be added after the fact",
                )

            # The ledger INSERT is the only arbiter; everything below branches
            # on the STORED action, never on what this request asked for.
            created, effective = clerk.decide(invoice, req.action, actor, req.note)
            if effective != req.action:
                event(req.action, f"conflict:stored={effective}", state_before)
                raise HTTPException(
                    status_code=409,
                    detail=f"terminal decision {effective} already recorded; issue a new invoice_id to revise",
                )

            # Decision and its evidence are durable BEFORE resume runs.
            event(effective, "recorded" if created else "idempotent-noop",
                  f"{job['state']}/{clerk.ledger.state(invoice)}")
            try:
                state = clerk.resume(job_id)
            except Exception as e:
                event("RESUME", f"resume-failed:{type(e).__name__}", state_before)
                raise HTTPException(
                    status_code=500,
                    detail="resume failed after the decision was recorded; re-send the same decision to recover",
                )
            event("RESUME", "resumed", f"{state}/{clerk.ledger.state(invoice)}")
            return {
                "request_id": request_id,
                "job_id": job_id,
                "decided": created,  # False = this same terminal decision already existed
                "action_in_effect": effective,
                "state": state,
            }
        finally:
            clerk.ledger.close()

    return app
