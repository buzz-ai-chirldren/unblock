"""Human approval API over UNBLOCK's durable ASK queue (Gate B boundary).

Public v1 contract (every route requires `Authorization: Bearer <token>`):

  GET  /v1/approvals                    WAITING_APPROVAL jobs with their PINNED
                                        invoice terms and an allowlisted
                                        reason_code; bounded limit/offset
  GET  /v1/approvals/{job_id}           detail: job state, pinned terms,
                                        effective decision, audit event trail
  POST /v1/approvals/{job_id}/decision  body {"action": "APPROVE"|"REJECT"}.
                                        Records the terminal decision for the
                                        job's pinned invoice, then resumes it.
                                        Re-sending the SAME decision is the
                                        crash-recovery path - there is no
                                        resume endpoint.

External actions APPROVE/REJECT are explicitly mapped to the ledger's terminal
states APPROVED/REJECTED at this boundary; no other route names or verbs exist.

Threat-model properties (per unblock-gate-b-threat-model):

- The actor is the authenticated principal: tokens are configured server-side
  as an actor->token map (env UNBLOCK_APPROVAL_TOKENS, JSON). Bodies carry no
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
- Responses carry NO free-form strings: memo and the job's raw `why` are
  never returned (a memo/why can embed tokens or merchant-controlled text).
  The park reason is served as an allowlisted reason_code enum instead. The
  digest still binds the FULL raw terms including the memo. Receipts,
  provider responses, and credentials never appear in any response.
- Request bodies are limited by counting the bytes actually received on the
  ASGI stream (BODY_LIMIT), so chunked transfers and missing/false
  Content-Length headers cannot bypass the cap.
- Strict schemas (unknown fields rejected, note capped), constant-time token
  compare, tokens never logged, stored, or echoed.

SQLite connections are thread-bound and ASGI servers run handlers on worker
threads, so the app builds a fresh Ledger/Unblock per request via the injected
factory (fresh-connection safety is proven by the restart tests).
"""

from __future__ import annotations

import hmac
import json
import os
import uuid
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from .controller import Unblock
from .policy import Invoice

TOKENS_ENV = "UNBLOCK_APPROVAL_TOKENS"  # JSON: {"<actor>": "<token>", ...}
BODY_LIMIT = 16 * 1024

# External verb -> internal terminal state. The ONLY place the mapping exists.
ACTIONS = {"APPROVE": "APPROVED", "REJECT": "REJECTED"}

# Allowlisted park reasons. The raw `why` string is evidence (ledger-only);
# responses may carry one of these enum values and nothing else.
_REASON_CODES = (
    ("not in allowlist", "merchant-not-allowlisted"),
    ("exceeds per-invoice cap", "over-invoice-cap"),
    ("would spend", "over-weekly-allowance"),
    ("reconcile PAYING", "reconcile-pending"),
    ("settlement uncertain", "settlement-uncertain"),
    ("lost payment race", "payment-race-lost"),
    ("approval digest mismatch", "approval-digest-mismatch"),
    ("refused before signing", "rail-refused"),
    ("rail error", "rail-refused"),
    ("rejected", "rejected"),
)


def _reason_code(why: str) -> str:
    for marker, code in _REASON_CODES:
        if marker in why:
            return code
    return "other"


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(pattern="^(APPROVE|REJECT)$")
    note: str = Field(default="", max_length=500)


class _BodyLimit:
    """Pure ASGI middleware: buffers the request body while counting the bytes
    ACTUALLY received, refusing with 413 once the cap is crossed - independent
    of Content-Length honesty or chunked transfer encoding."""

    def __init__(self, app, limit: int = BODY_LIMIT):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = b""
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            if len(body) > self.limit:
                payload = b'{"detail":"request body too large"}'
                await send({
                    "type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(payload)).encode())],
                })
                await send({"type": "http.response.body", "body": payload})
                return
            if not message.get("more_body"):
                break

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def create_app(unblock_factory: Callable[[], Unblock],
               tokens: dict[str, str] | None = None) -> FastAPI:
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
    app.add_middleware(_BodyLimit, limit=BODY_LIMIT)

    def pinned_terms(controller: Unblock, invoice: Invoice) -> dict:
        return {
            "merchant": invoice.merchant,
            "invoice_id": invoice.invoice_id,
            "amount": str(invoice.amount),
            "currency": invoice.currency,
            "digest": invoice.digest(),
            "invoice_state": controller.ledger.state(invoice),
        }

    @app.get("/v1/approvals")
    def list_approvals(
        actor: str = Depends(authenticated_actor),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> list[dict]:
        controller = unblock_factory()
        try:
            out = []
            for job in controller.ledger.waiting_jobs(limit=limit, offset=offset):
                invoice = controller.ledger.invoice_row(job["merchant"], job["invoice_id"])
                if invoice is None:
                    continue
                decision = controller.ledger.decision(invoice)
                out.append(
                    {
                        "job_id": job["job_id"],
                        "reason_code": _reason_code(job["payload"].get("why", "")),
                        **pinned_terms(controller, invoice),
                        "decision": decision[0] if decision else None,
                    }
                )
            return out
        finally:
            controller.ledger.close()

    @app.get("/v1/approvals/{job_id}")
    def approval_detail(job_id: str, actor: str = Depends(authenticated_actor)) -> dict:
        controller = unblock_factory()
        try:
            job = controller.ledger.job(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="unknown job")
            invoice = controller.ledger.invoice_row(job["merchant"] or "", job["invoice_id"] or "")
            decision = controller.ledger.decision(invoice) if invoice else None
            return {
                "job_id": job_id,
                "job_state": job["state"],
                "reason_code": _reason_code(job["payload"].get("why", "")),
                **(pinned_terms(controller, invoice) if invoice else {}),
                "decision": decision[0] if decision else None,
                "events": controller.ledger.events(job_id),
            }
        finally:
            controller.ledger.close()

    @app.post("/v1/approvals/{job_id}/decision")
    def decide(job_id: str, req: DecisionRequest, actor: str = Depends(authenticated_actor)) -> dict:
        request_id = uuid.uuid4().hex
        requested = ACTIONS[req.action]  # external verb -> internal terminal state
        controller = unblock_factory()
        try:
            job = controller.ledger.job(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="unknown job")
            invoice = controller.ledger.invoice_row(job["merchant"] or "", job["invoice_id"] or "")
            if invoice is None:
                raise HTTPException(status_code=404, detail="job has no pinned invoice")
            digest = invoice.digest()
            state_before = f"{job['state']}/{controller.ledger.state(invoice)}"

            def event(action: str, outcome: str, state_after: str) -> None:
                controller.ledger.record_event(
                    request_id, actor, action, outcome, job_id,
                    invoice.merchant, invoice.invoice_id, digest, state_before, state_after,
                )

            # A FIRST decision is only valid for a parked job. (If a decision
            # already exists, fall through: the atomic insert below loses and
            # we branch on the stored action - the resend/conflict paths.)
            if controller.ledger.decision(invoice) is None and job["state"] != "WAITING_APPROVAL":
                event(requested, "refused-state", state_before)
                raise HTTPException(
                    status_code=409,
                    detail=f"job is {job['state']}, not WAITING_APPROVAL; decisions cannot be added after the fact",
                )

            # The ledger INSERT is the only arbiter; everything below branches
            # on the STORED action, never on what this request asked for.
            created, effective = controller.decide(invoice, requested, actor, req.note)
            if effective != requested:
                event(requested, f"conflict:stored={effective}", state_before)
                raise HTTPException(
                    status_code=409,
                    detail=f"terminal decision {effective} already recorded; issue a new invoice_id to revise",
                )

            # Decision and its evidence are durable BEFORE resume runs.
            event(effective, "recorded" if created else "idempotent-noop",
                  f"{job['state']}/{controller.ledger.state(invoice)}")
            try:
                state = controller.resume(job_id)
            except Exception as e:
                event("RESUME", f"resume-failed:{type(e).__name__}", state_before)
                raise HTTPException(
                    status_code=500,
                    detail="resume failed after the decision was recorded; re-send the same decision to recover",
                )
            event("RESUME", "resumed", f"{state}/{controller.ledger.state(invoice)}")
            return {
                "request_id": request_id,
                "job_id": job_id,
                "decided": created,  # False = this same terminal decision already existed
                "action_in_effect": effective,
                "state": state,
            }
        finally:
            controller.ledger.close()

    return app
