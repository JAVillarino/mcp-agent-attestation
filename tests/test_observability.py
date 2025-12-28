"""
Tests for Observability Module

Run with: pytest tests/test_observability.py -v
"""

import pytest
import time


class TestAttestationMetrics:
    """Tests for metrics collection."""

    def test_initial_state(self):
        """Test metrics start at zero."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()

        assert metrics.verification_total == 0
        assert metrics.verification_success == 0
        assert metrics.verification_failure == 0
        assert metrics.token_creation_total == 0
        assert metrics.replay_detected == 0

    def test_record_verification_success(self):
        """Test recording successful verification."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()
        metrics.record_verification(
            issuer="https://api.anthropic.com",
            verified=True,
            duration_ms=15.5,
            trust_level="provider",
        )

        assert metrics.verification_total == 1
        assert metrics.verification_success == 1
        assert metrics.verification_failure == 0

    def test_record_verification_failure(self):
        """Test recording failed verification."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()
        metrics.record_verification(
            issuer="https://api.anthropic.com",
            verified=False,
            duration_ms=5.0,
            error_code=1003,
        )

        assert metrics.verification_total == 1
        assert metrics.verification_success == 0
        assert metrics.verification_failure == 1

    def test_record_token_creation(self):
        """Test recording token creation."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()
        metrics.record_token_creation(
            issuer="https://api.anthropic.com",
            duration_ms=3.2,
            audience="https://server.com",
        )

        assert metrics.token_creation_total == 1

    def test_record_replay_detected(self):
        """Test recording replay detection."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()
        metrics.record_replay_detected(
            issuer="https://api.anthropic.com",
            jti="abc123",
        )

        assert metrics.replay_detected == 1

    def test_cache_metrics(self):
        """Test cache hit/miss recording."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()

        metrics.record_cache_hit()
        metrics.record_cache_hit()
        metrics.record_cache_miss()

        data = metrics.to_dict()
        assert data["counters"]["cache_hits"] == 2
        assert data["counters"]["cache_misses"] == 1

    def test_per_issuer_breakdown(self):
        """Test per-issuer metrics breakdown."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()

        metrics.record_verification("https://issuer1.com", True, 10.0)
        metrics.record_verification("https://issuer1.com", True, 12.0)
        metrics.record_verification("https://issuer2.com", False, 5.0)

        data = metrics.to_dict()
        assert data["by_issuer"]["https://issuer1.com"]["verifications"] == 2
        assert data["by_issuer"]["https://issuer2.com"]["verifications"] == 1

    def test_to_dict(self):
        """Test metrics export to dictionary."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()
        metrics.record_verification("test", True, 10.0)

        data = metrics.to_dict()

        assert "uptime_seconds" in data
        assert "counters" in data
        assert "gauges" in data
        assert "histograms" in data
        assert data["counters"]["verification_total"] == 1

    def test_to_prometheus(self):
        """Test Prometheus format export."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()
        metrics.record_verification("https://test.com", True, 10.0)
        metrics.record_token_creation("https://test.com", 5.0)

        prometheus = metrics.to_prometheus()

        assert "attestation_verification_total 1" in prometheus
        assert "attestation_token_creation_total 1" in prometheus
        assert "# HELP" in prometheus
        assert "# TYPE" in prometheus

    def test_histogram_stats(self):
        """Test histogram statistics calculation."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()

        # Add some durations
        for i in range(100):
            metrics.record_verification("test", True, float(i))

        data = metrics.to_dict()
        stats = data["histograms"]["verification_duration_ms"]

        assert stats["count"] == 100
        assert stats["min"] == 0.0
        assert stats["max"] == 99.0
        assert stats["avg"] == 49.5
        assert stats["p50"] == 50.0

    def test_events_logging(self):
        """Test event logging."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()
        metrics.record_verification("test", True, 10.0)
        metrics.record_replay_detected("test", "jti123")

        events = metrics.get_events()
        assert len(events) == 2
        assert events[0]["type"] == "verification"
        assert events[1]["type"] == "replay_detected"

    def test_events_max_limit(self):
        """Test events list is bounded."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()
        metrics._max_events = 10

        for i in range(20):
            metrics.record_verification("test", True, 1.0)

        events = metrics.get_events()
        assert len(events) == 10

    def test_reset(self):
        """Test metrics reset."""
        from attestation.observability import AttestationMetrics

        metrics = AttestationMetrics()
        metrics.record_verification("test", True, 10.0)
        metrics.reset()

        assert metrics.verification_total == 0


class TestGlobalMetrics:
    """Tests for global metrics singleton."""

    def test_get_metrics_singleton(self):
        """Test get_metrics returns same instance."""
        from attestation.observability import get_metrics, reset_metrics

        reset_metrics()  # Start fresh
        m1 = get_metrics()
        m2 = get_metrics()

        assert m1 is m2

    def test_reset_metrics(self):
        """Test reset_metrics creates new instance."""
        from attestation.observability import get_metrics, reset_metrics

        m1 = get_metrics()
        m1.record_verification("test", True, 1.0)

        reset_metrics()
        m2 = get_metrics()

        assert m2.verification_total == 0


class TestTracing:
    """Tests for tracing context managers."""

    def test_trace_verification(self):
        """Test verification tracing."""
        from attestation.observability import trace_verification, get_metrics, reset_metrics

        reset_metrics()

        with trace_verification("https://test.com") as span:
            # Simulate work
            time.sleep(0.01)

        # Active verifications should be back to 0
        metrics = get_metrics()
        assert metrics._active_verifications == 0

    def test_trace_token_creation(self):
        """Test token creation tracing."""
        from attestation.observability import trace_token_creation, get_metrics, reset_metrics

        reset_metrics()

        with trace_token_creation("https://issuer.com", "https://audience.com") as span:
            time.sleep(0.01)

        metrics = get_metrics()
        assert metrics.token_creation_total == 1

    def test_trace_jwks_fetch(self):
        """Test JWKS fetch tracing."""
        from attestation.observability import trace_jwks_fetch, get_metrics, reset_metrics

        reset_metrics()

        with trace_jwks_fetch("https://issuer.com") as span:
            time.sleep(0.01)

        metrics = get_metrics()
        data = metrics.to_dict()
        assert data["counters"]["jwks_fetches"] == 1


class TestEventHandlers:
    """Tests for custom event handlers."""

    def test_register_handler(self):
        """Test registering an event handler."""
        from attestation.observability import (
            AttestationEventHandler,
            register_event_handler,
            unregister_event_handler,
            emit_verification_success,
        )

        class TestHandler(AttestationEventHandler):
            def __init__(self):
                self.calls = []

            def on_verification_success(self, issuer, subject, trust_level):
                self.calls.append(("success", issuer, subject, trust_level))

        handler = TestHandler()
        register_event_handler(handler)

        try:
            emit_verification_success("issuer", "subject", "provider")
            assert len(handler.calls) == 1
            assert handler.calls[0] == ("success", "issuer", "subject", "provider")
        finally:
            unregister_event_handler(handler)

    def test_emit_verification_failure(self):
        """Test emitting verification failure."""
        from attestation.observability import (
            AttestationEventHandler,
            register_event_handler,
            unregister_event_handler,
            emit_verification_failure,
        )

        class TestHandler(AttestationEventHandler):
            def __init__(self):
                self.failures = []

            def on_verification_failure(self, issuer, error, error_code):
                self.failures.append((issuer, error, error_code))

        handler = TestHandler()
        register_event_handler(handler)

        try:
            emit_verification_failure("issuer", "token expired", 1001)
            assert len(handler.failures) == 1
            assert handler.failures[0] == ("issuer", "token expired", 1001)
        finally:
            unregister_event_handler(handler)

    def test_emit_replay_detected(self):
        """Test emitting replay detection."""
        from attestation.observability import (
            AttestationEventHandler,
            register_event_handler,
            unregister_event_handler,
            emit_replay_detected,
        )

        class TestHandler(AttestationEventHandler):
            def __init__(self):
                self.replays = []

            def on_replay_detected(self, issuer, jti):
                self.replays.append((issuer, jti))

        handler = TestHandler()
        register_event_handler(handler)

        try:
            emit_replay_detected("issuer", "jti123")
            assert len(handler.replays) == 1
        finally:
            unregister_event_handler(handler)

    def test_handler_error_isolation(self):
        """Test that handler errors don't propagate."""
        from attestation.observability import (
            AttestationEventHandler,
            register_event_handler,
            unregister_event_handler,
            emit_verification_success,
        )

        class BrokenHandler(AttestationEventHandler):
            def on_verification_success(self, issuer, subject, trust_level):
                raise RuntimeError("Handler crashed!")

        handler = BrokenHandler()
        register_event_handler(handler)

        try:
            # Should not raise
            emit_verification_success("issuer", "subject", "provider")
        finally:
            unregister_event_handler(handler)


class TestNoOpTracer:
    """Tests for no-op tracer when OpenTelemetry not available."""

    def test_noop_span(self):
        """Test NoOpSpan doesn't crash."""
        from attestation.observability import NoOpSpan

        span = NoOpSpan()
        span.set_attribute("key", "value")
        span.set_status("ok")
        span.record_exception(ValueError("test"))
        span.end()

        with span:
            pass

    def test_noop_tracer(self):
        """Test NoOpTracer doesn't crash."""
        from attestation.observability import NoOpTracer

        tracer = NoOpTracer()
        span = tracer.start_span("test")
        assert isinstance(span, type(tracer.start_as_current_span("test")))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
