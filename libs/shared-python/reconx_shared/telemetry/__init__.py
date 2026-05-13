"""OpenTelemetry instrumentation for distributed tracing and metrics."""

from __future__ import annotations

import os

from opentelemetry import trace, metrics
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

import structlog

logger = structlog.get_logger(__name__)


def init_telemetry(service_name: str | None = None) -> None:
    """Initialize OpenTelemetry tracing and metrics."""
    svc = service_name or os.getenv("OTEL_SERVICE_NAME", "reconx")
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

    resource = Resource.create({"service.name": svc, "service.version": "0.1.0"})

    # Tracing
    tracer_provider = TracerProvider(resource=resource)
    span_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    trace.set_tracer_provider(tracer_provider)

    # Metrics
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=endpoint, insecure=True),
        export_interval_millis=30000,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    logger.info("OpenTelemetry initialized", service=svc, endpoint=endpoint)


def get_tracer(name: str) -> trace.Tracer:
    """Get a named tracer."""
    return trace.get_tracer(name)


def get_meter(name: str) -> metrics.Meter:
    """Get a named meter."""
    return metrics.get_meter(name)
