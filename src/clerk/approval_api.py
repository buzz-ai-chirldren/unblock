"""Human approval API over the clerk's durable ASK queue (Gate B boundary).

Endpoints (every route requires `Authorization: Bearer <token>`):

  GET  /asks                   list WAITING_APPROVAL jobs with their PINNED
                               invoice terms and digest, read from the ledger
  POST /jobs/{job_id}/decision record the terminal APPROVED/REJECTED decision
                               for the job's pinned invoice, then resume the job
  POST /jobs/{job_id}/resume   crash-recovery re-drive; allowed ONLY for jobs
                               currently WAITING_APPROVAL (not a free-form
                               resume surface — resume() itself pays only with
                               a digest-matching APPROVED decision)

Threat-model properties (per the Gate B note, allowance-clerk-gate-b-threat-model):

- The actor is the authenticated principal: tokens are configured server-side
  as an actor->token map (env CLERK_APPROVAL_TOKENS, JSON). The request body
  carries no actor and cannot spoof one.
- Decisions target a job_id only; merchant, amount, and digest are read from
  the ledger row pinned at first claim. No caller input can override them.
- First APPROVE/REJECT is terminal (ledger PK). Re-sending the same action is
  an idempotent 200 (decided=false); the opposite action is a 409 conflict.
- The decision is persisted BEFORE resume is attempted; a crash between the
  two leaves a recorded decision and a parked job that the recovery resume
  completes without paying twice (ledger PAYING/PAID gates still apply).
- Strict schemas: unknown fields are rejected, note length is capped.
- Bearer tokens are compared in constant time, never logged, never stored,
  and never echoed in errors; audit rows record the actor name only.
- Every authenticated action appends an api_events evidence row: request ID,
  actor, action, outcome, invoice digest, and state before/after.

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

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .jobs import Clerk

TOKENS_ENV = "CLERK_APPROVAL_TOKENS"  # JSON: {"<actor>": "<token>", ...}


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(pattern="^(APPROVED|REJECTED)$")
    note: str = Field(default="", max_length=500)


def create_app(clerk_factory: Callable[[], Clerk], tokens: dict[str, str] | None = None) -> FastAPI:
    if tokens is None:
        tokens = json.loads(os.environ.get(TOKENS_ENV) or "{}")
    if not tokens or not all(tokens.values()):
        raise RuntimeError(
            f"{TOKENS_ENV} (JSON actor->token map) is required: the approval API never runs unauthenticated"
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

    @app.get("/asks")
    def list_asks(actor: str = Depends(authenticated_actor)) -> list[dict]:
        clerk = clerk_factory()
        try:
            out = []
            for job in clerk.ledger.waiting_jobs():
                invoice = clerk.ledger.invoice_row(job["merchant"], job["invoice_id"])
                if invoice is None:
                    continue
                decision = clerk.ledger.decision(invoice)
                out.append(
                    {
                        "job_id": job["job_id"],
                        "why": job["payload"].get("why", ""),
                        "merchant": invoice.merchant,
                        "invoice_id": invoice.invoice_id,
                        "amount": str(invoice.amount),
                        "currency": invoice.currency,
                        "memo": invoice.memo,
                        "digest": invoice.digest(),
                        "invoice_state": clerk.ledger.state(invoice),
                        "decision": decision[0] if decision else None,
                    }
                )
            return out
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

            existing = clerk.ledger.decision(invoice)
            if existing is not None and existing[0] != req.action:
                clerk.ledger.record_event(
                    request_id, actor, req.action, "conflict", job_id,
                    invoice.merchant, invoice.invoice_id, digest, state_before, state_before,
                )
                raise HTTPException(
                    status_code=409,
                    detail=f"terminal decision {existing[0]} already recorded; issue a new invoice_id to revise",
                )

            if req.action == "APPROVED":
                decided = clerk.approve(invoice, actor=actor, note=req.note)
            else:
                decided = clerk.reject(invoice, actor=actor, note=req.note)
            # The decision row is committed at this point; resume may crash
            # without losing it.
            state = clerk.resume(job_id)
            clerk.ledger.record_event(
                request_id, actor, req.action,
                "recorded" if decided else "idempotent-noop",
                job_id, invoice.merchant, invoice.invoice_id, digest,
                state_before, f"{state}/{clerk.ledger.state(invoice)}",
            )
            return {
                "request_id": request_id,
                "job_id": job_id,
                "decided": decided,  # False = same terminal decision already existed
                "action_in_effect": req.action,
                "state": state,
            }
        finally:
            clerk.ledger.close()

    @app.post("/jobs/{job_id}/resume")
    def resume(job_id: str, actor: str = Depends(authenticated_actor)) -> dict:
        request_id = uuid.uuid4().hex
        clerk = clerk_factory()
        try:
            job = clerk.ledger.job(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="unknown job")
            if job["state"] != "WAITING_APPROVAL":
                raise HTTPException(status_code=409, detail=f"job is {job['state']}, not WAITING_APPROVAL")
            invoice = clerk.ledger.invoice_row(job["merchant"] or "", job["invoice_id"] or "")
            state_before = f"{job['state']}/{clerk.ledger.state(invoice) if invoice else None}"
            state = clerk.resume(job_id)
            clerk.ledger.record_event(
                request_id, actor, "RESUME", "resumed", job_id,
                invoice.merchant if invoice else None,
                invoice.invoice_id if invoice else None,
                invoice.digest() if invoice else None,
                state_before, f"{state}/{clerk.ledger.state(invoice) if invoice else None}",
            )
            return {"request_id": request_id, "job_id": job_id, "state": state}
        finally:
            clerk.ledger.close()

    return app
