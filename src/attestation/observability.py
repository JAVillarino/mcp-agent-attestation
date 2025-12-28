"""
MCP Agent Attestation - Observability

Provides observability hooks for monitoring attestation operations:
- OpenTelemetry tracing (optional)
- Prometheus-compatible metrics
- Structured event logging

Usage:
    from attestation.observability import get_metrics, trace_verification

    # Get metrics singleton
    metrics = get_metrics()
    print(metrics.to_prometheus())

    # Trace a verification (if OpenTelemetry installed)
    with trace_verification("https://api.anthropic.com") as span:
        result = await verifier.verify(token)
        span.set_attribute("verified", result.verified)

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Try to import OpenTelemetry
try:
    from opentelemetry import trace
    from opentelemetry.trace import Span, Status, StatusCode

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None  # type: ignore
    Span = Any  # type: ignore


class MetricType(Enum):
    """Types of metrics."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass
class MetricValue:
    """A single metric value with labels."""

    name: str
    value: float
    labels: dict[str, str] = field(default_factory=dict)
    metric_type: MetricType = MetricType.COUNTER
    help_text: str = ""
    timestamp: float = field(default_factory=time.time)


class AttestationMetrics:
    """
    Metrics collector for attestation operations.

    Provides Prometheus-compatible metrics export and real-time
    access to operation statistics.

    Usage:
        metrics = AttestationMetrics()

        # Record operations
        metrics.record_verification(issuer="anthropic", verified=True, duration_ms=15.2)
        metrics.record_token_creation(issuer="anthropic", duration_ms=5.1)

        # Export as Prometheus format
        print(metrics.to_prometheus())

        # Get raw counters
        print(metrics.verification_total)
    """

    def __init__(self):
        """Initialize metrics collector."""
        self._start_time = time.time()

        # Counters
        self._verification_total = 0
        self._verification_success = 0
        self._verification_failure = 0
        self._token_creation_total = 0
        self._replay_detected = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._jwks_fetches = 0
        self._jwks_fetch_errors = 0
        self._circuit_breaker_opens = 0

        # Gauges
        self._active_verifications = 0
        self._cached_keys_count = 0

        # Histograms (simplified as lists)
        self._verification_durations: list[float] = []
        self._token_creation_durations: list[float] = []
        self._jwks_fetch_durations: list[float] = []

        # Per-issuer breakdown
        self._by_issuer: dict[str, dict[str, int]] = {}

        # Event log for debugging
        self._events: list[dict[str, Any]] = []
        self._max_events = 1000

    # === Counter Accessors ===

    @property
    def verification_total(self) -> int:
        """Total verification attempts."""
        return self._verification_total

    @property
    def verification_success(self) -> int:
        """Successful verifications."""
        return self._verification_success

    @property
    def verification_failure(self) -> int:
        """Failed verifications."""
        return self._verification_failure

    @property
    def token_creation_total(self) -> int:
        """Total tokens created."""
        return self._token_creation_total

    @property
    def replay_detected(self) -> int:
        """Replay attacks detected."""
        return self._replay_detected

    # === Recording Methods ===

    def record_verification(
        self,
        issuer: str,
        verified: bool,
        duration_ms: float,
        trust_level: str | None = None,
        error_code: int | None = None,
    ) -> None:
        """Record a verification attempt."""
        self._verification_total += 1
        if verified:
            self._verification_success += 1
        else:
            self._verification_failure += 1

        self._verification_durations.append(duration_ms)
        self._ensure_issuer(issuer)
        self._by_issuer[issuer]["verifications"] += 1

        self._log_event(
            "verification",
            issuer=issuer,
            verified=verified,
            duration_ms=duration_ms,
            trust_level=trust_level,
            error_code=error_code,
        )

    def record_token_creation(
        self,
        issuer: str,
        duration_ms: float,
        audience: str | None = None,
    ) -> None:
        """Record a token creation."""
        self._token_creation_total += 1
        self._token_creation_durations.append(duration_ms)
        self._ensure_issuer(issuer)
        self._by_issuer[issuer]["tokens_created"] += 1

        self._log_event(
            "token_creation",
            issuer=issuer,
            duration_ms=duration_ms,
            audience=audience,
        )

    def record_replay_detected(self, issuer: str, jti: str) -> None:
        """Record a replay attack detection."""
        self._replay_detected += 1
        self._ensure_issuer(issuer)
        self._by_issuer[issuer]["replays"] += 1

        self._log_event(
            "replay_detected",
            issuer=issuer,
            jti=jti[:16] + "...",  # Truncate for privacy
        )
        logger.warning(f"Replay attack detected from issuer {issuer}")

    def record_cache_hit(self) -> None:
        """Record a cache hit."""
        self._cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a cache miss."""
        self._cache_misses += 1

    def record_jwks_fetch(
        self,
        issuer: str,
        duration_ms: float,
        success: bool,
        from_cache: bool = False,
    ) -> None:
        """Record a JWKS fetch operation."""
        self._jwks_fetches += 1
        if not success:
            self._jwks_fetch_errors += 1
        self._jwks_fetch_durations.append(duration_ms)

        self._log_event(
            "jwks_fetch",
            issuer=issuer,
            duration_ms=duration_ms,
            success=success,
            from_cache=from_cache,
        )

    def record_circuit_breaker_open(self, issuer: str) -> None:
        """Record a circuit breaker opening."""
        self._circuit_breaker_opens += 1
        self._log_event("circuit_breaker_open", issuer=issuer)
        logger.warning(f"Circuit breaker opened for {issuer}")

    def set_cached_keys_count(self, count: int) -> None:
        """Update the cached keys gauge."""
        self._cached_keys_count = count

    # === Export Methods ===

    def to_dict(self) -> dict[str, Any]:
        """Export metrics as dictionary."""
        return {
            "uptime_seconds": time.time() - self._start_time,
            "counters": {
                "verification_total": self._verification_total,
                "verification_success": self._verification_success,
                "verification_failure": self._verification_failure,
                "token_creation_total": self._token_creation_total,
                "replay_detected": self._replay_detected,
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "jwks_fetches": self._jwks_fetches,
                "jwks_fetch_errors": self._jwks_fetch_errors,
                "circuit_breaker_opens": self._circuit_breaker_opens,
            },
            "gauges": {
                "active_verifications": self._active_verifications,
                "cached_keys_count": self._cached_keys_count,
            },
            "histograms": {
                "verification_duration_ms": self._histogram_stats(self._verification_durations),
                "token_creation_duration_ms": self._histogram_stats(self._token_creation_durations),
                "jwks_fetch_duration_ms": self._histogram_stats(self._jwks_fetch_durations),
            },
            "by_issuer": self._by_issuer,
        }

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []

        # Helper to add metric
        def add_metric(name: str, value: float, help_text: str, mtype: str = "counter", labels: dict | None = None):
            full_name = f"attestation_{name}"
            lines.append(f"# HELP {full_name} {help_text}")
            lines.append(f"# TYPE {full_name} {mtype}")
            if labels:
                label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
                lines.append(f"{full_name}{{{label_str}}} {value}")
            else:
                lines.append(f"{full_name} {value}")

        # Counters
        add_metric("verification_total", self._verification_total, "Total verification attempts")
        add_metric("verification_success_total", self._verification_success, "Successful verifications")
        add_metric("verification_failure_total", self._verification_failure, "Failed verifications")
        add_metric("token_creation_total", self._token_creation_total, "Tokens created")
        add_metric("replay_detected_total", self._replay_detected, "Replay attacks detected")
        add_metric("cache_hits_total", self._cache_hits, "Cache hits")
        add_metric("cache_misses_total", self._cache_misses, "Cache misses")
        add_metric("jwks_fetch_total", self._jwks_fetches, "JWKS fetch operations")
        add_metric("jwks_fetch_errors_total", self._jwks_fetch_errors, "JWKS fetch errors")
        add_metric("circuit_breaker_opens_total", self._circuit_breaker_opens, "Circuit breaker opens")

        # Gauges
        add_metric("active_verifications", self._active_verifications, "Active verifications", "gauge")
        add_metric("cached_keys", self._cached_keys_count, "Cached keys count", "gauge")

        # Histogram summaries
        for name, durations in [
            ("verification_duration_ms", self._verification_durations),
            ("token_creation_duration_ms", self._token_creation_durations),
            ("jwks_fetch_duration_ms", self._jwks_fetch_durations),
        ]:
            if durations:
                stats = self._histogram_stats(durations)
                add_metric(f"{name}_sum", stats["sum"], f"Sum of {name}", "gauge")
                add_metric(f"{name}_count", stats["count"], f"Count of {name}", "gauge")
                add_metric(f"{name}_avg", stats["avg"], f"Average {name}", "gauge")

        # Per-issuer metrics
        for issuer, counts in self._by_issuer.items():
            for metric, value in counts.items():
                add_metric(
                    f"issuer_{metric}_total",
                    value,
                    f"Per-issuer {metric}",
                    labels={"issuer": issuer},
                )

        return "\n".join(lines)

    def get_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent events for debugging."""
        return self._events[-limit:]

    def reset(self) -> None:
        """Reset all metrics (for testing)."""
        self.__init__()

    # === Internal Helpers ===

    def _ensure_issuer(self, issuer: str) -> None:
        """Ensure issuer exists in breakdown."""
        if issuer not in self._by_issuer:
            self._by_issuer[issuer] = {
                "verifications": 0,
                "tokens_created": 0,
                "replays": 0,
            }

    def _histogram_stats(self, values: list[float]) -> dict[str, float]:
        """Calculate histogram statistics."""
        if not values:
            return {"count": 0, "sum": 0, "avg": 0, "min": 0, "max": 0, "p50": 0, "p95": 0, "p99": 0}

        sorted_values = sorted(values)
        count = len(sorted_values)
        return {
            "count": count,
            "sum": sum(sorted_values),
            "avg": sum(sorted_values) / count,
            "min": sorted_values[0],
            "max": sorted_values[-1],
            "p50": sorted_values[int(count * 0.5)],
            "p95": sorted_values[int(count * 0.95)] if count >= 20 else sorted_values[-1],
            "p99": sorted_values[int(count * 0.99)] if count >= 100 else sorted_values[-1],
        }

    def _log_event(self, event_type: str, **kwargs) -> None:
        """Log an event for debugging."""
        event = {
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            **kwargs,
        }
        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]


# Singleton metrics instance
_metrics: AttestationMetrics | None = None


def get_metrics() -> AttestationMetrics:
    """Get the global metrics instance."""
    global _metrics
    if _metrics is None:
        _metrics = AttestationMetrics()
    return _metrics


def reset_metrics() -> None:
    """Reset the global metrics instance (for testing)."""
    global _metrics
    _metrics = AttestationMetrics()


# === OpenTelemetry Integration ===


def get_tracer(name: str = "attestation"):
    """Get an OpenTelemetry tracer (or no-op if not available)."""
    if OTEL_AVAILABLE:
        return trace.get_tracer(name)
    return NoOpTracer()


class NoOpSpan:
    """No-op span for when OpenTelemetry is not available."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def record_exception(self, exception: Exception) -> None:
        pass

    def end(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class NoOpTracer:
    """No-op tracer for when OpenTelemetry is not available."""

    def start_span(self, name: str, **kwargs) -> NoOpSpan:
        return NoOpSpan()

    def start_as_current_span(self, name: str, **kwargs):
        return NoOpSpan()


@contextmanager
def trace_verification(issuer: str):
    """
    Context manager for tracing verification operations.

    Usage:
        with trace_verification("https://api.anthropic.com") as span:
            result = await verifier.verify(token)
            span.set_attribute("verified", result.verified)
    """
    tracer = get_tracer()
    start_time = time.time()
    metrics = get_metrics()
    metrics._active_verifications += 1

    try:
        with tracer.start_as_current_span("attestation.verify") as span:
            if OTEL_AVAILABLE:
                span.set_attribute("issuer", issuer)
            yield span
    finally:
        metrics._active_verifications -= 1
        duration_ms = (time.time() - start_time) * 1000
        logger.debug(f"Verification for {issuer} took {duration_ms:.2f}ms")


@contextmanager
def trace_token_creation(issuer: str, audience: str):
    """
    Context manager for tracing token creation operations.

    Usage:
        with trace_token_creation("https://issuer.com", "https://audience.com") as span:
            token = provider.create_token(...)
    """
    tracer = get_tracer()
    start_time = time.time()

    try:
        with tracer.start_as_current_span("attestation.create_token") as span:
            if OTEL_AVAILABLE:
                span.set_attribute("issuer", issuer)
                span.set_attribute("audience", audience)
            yield span
    finally:
        duration_ms = (time.time() - start_time) * 1000
        get_metrics().record_token_creation(issuer, duration_ms, audience)


@contextmanager
def trace_jwks_fetch(issuer: str):
    """
    Context manager for tracing JWKS fetch operations.

    Usage:
        with trace_jwks_fetch("https://api.anthropic.com") as span:
            jwks = await fetcher.get_jwks(issuer)
    """
    tracer = get_tracer()
    start_time = time.time()

    try:
        with tracer.start_as_current_span("attestation.jwks_fetch") as span:
            if OTEL_AVAILABLE:
                span.set_attribute("issuer", issuer)
            yield span
            success = True
    except Exception:
        success = False
        raise
    finally:
        duration_ms = (time.time() - start_time) * 1000
        get_metrics().record_jwks_fetch(issuer, duration_ms, success)


# === Logging Hooks ===


class AttestationEventHandler:
    """
    Base class for custom event handlers.

    Subclass this to implement custom logging, alerting, or metrics collection.

    Usage:
        class MyHandler(AttestationEventHandler):
            def on_verification_success(self, issuer, subject, trust_level):
                send_to_datadog(...)

        register_event_handler(MyHandler())
    """

    def on_verification_success(
        self, issuer: str, subject: str, trust_level: str
    ) -> None:
        """Called when verification succeeds."""
        pass

    def on_verification_failure(
        self, issuer: str | None, error: str, error_code: int | None
    ) -> None:
        """Called when verification fails."""
        pass

    def on_replay_detected(self, issuer: str, jti: str) -> None:
        """Called when a replay attack is detected."""
        pass

    def on_token_created(self, issuer: str, audience: str, lifetime_seconds: int) -> None:
        """Called when a token is created."""
        pass

    def on_circuit_breaker_state_change(
        self, issuer: str, old_state: str, new_state: str
    ) -> None:
        """Called when circuit breaker state changes."""
        pass


# Global event handlers
_event_handlers: list[AttestationEventHandler] = []


def register_event_handler(handler: AttestationEventHandler) -> None:
    """Register a custom event handler."""
    _event_handlers.append(handler)


def unregister_event_handler(handler: AttestationEventHandler) -> None:
    """Unregister a custom event handler."""
    _event_handlers.remove(handler)


def emit_verification_success(issuer: str, subject: str, trust_level: str) -> None:
    """Emit verification success event to all handlers."""
    for handler in _event_handlers:
        try:
            handler.on_verification_success(issuer, subject, trust_level)
        except Exception as e:
            logger.warning(f"Event handler error: {e}")


def emit_verification_failure(
    issuer: str | None, error: str, error_code: int | None
) -> None:
    """Emit verification failure event to all handlers."""
    for handler in _event_handlers:
        try:
            handler.on_verification_failure(issuer, error, error_code)
        except Exception as e:
            logger.warning(f"Event handler error: {e}")


def emit_replay_detected(issuer: str, jti: str) -> None:
    """Emit replay detection event to all handlers."""
    for handler in _event_handlers:
        try:
            handler.on_replay_detected(issuer, jti)
        except Exception as e:
            logger.warning(f"Event handler error: {e}")
