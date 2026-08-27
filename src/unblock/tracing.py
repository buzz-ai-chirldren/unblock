"""Opt-in trace export. UNBLOCK and the demo pipeline emit OpenTelemetry spans via
the API only, which is a no-op until a provider is installed - so production
behavior never depends on this module.

  UNBLOCK_TRACE=console   pretty-print spans to stderr (local inspection)
  UNBLOCK_TRACE=otlp      OTLP/HTTP export; endpoint + auth come from the
                          standard OTEL_EXPORTER_OTLP_* env vars (this is the
                          AgentCore Observability / CloudWatch path)
  unset                   no-op (default)

Span map: unblock.job (root, carries job_id) -> detect / policy / pay /
fetch / fix / verify / pr. Attributes carry ids, amounts, decisions and
digests only - never keys, tokens, or paid response bodies.
"""

from __future__ import annotations

import os


def configure_tracing(service_name: str = "unblock") -> str:
    """Install a span exporter per UNBLOCK_TRACE. Returns the mode installed
    ("console", "otlp", or "off"). Call at most once per process."""
    mode = os.environ.get("UNBLOCK_TRACE", "").strip().lower()
    if mode not in ("console", "otlp"):
        return "off"

    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    if mode == "console":
        exporter = ConsoleSpanExporter()
    else:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError as e:
            raise SystemExit(
                "UNBLOCK_TRACE=otlp needs the exporter: "
                "uv add opentelemetry-exporter-otlp-proto-http"
            ) from e
        exporter = OTLPSpanExporter()

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return mode
