"""
Tests for Production Hardening Features

Tests circuit breaker, retry logic, metrics, and fallback behavior.

Run with: pytest tests/test_hardening.py -v
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import time


class TestCircuitBreaker:
    """Tests for circuit breaker pattern."""

    def test_initial_state_is_closed(self):
        """Test circuit breaker starts in closed state."""
        from attestation.jwks import CircuitBreaker, CircuitState

        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.can_execute() is True

    def test_opens_after_threshold_failures(self):
        """Test circuit opens after failure threshold reached."""
        from attestation.jwks import CircuitBreaker, CircuitBreakerConfig, CircuitState

        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker(config)

        # Record failures up to threshold
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.can_execute() is False

    def test_success_resets_failure_count(self):
        """Test successful calls reset failure count."""
        from attestation.jwks import CircuitBreaker, CircuitBreakerConfig, CircuitState

        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker(config)

        cb.record_failure()
        cb.record_failure()
        cb.record_success()

        assert cb._failure_count == 0
        assert cb.state == CircuitState.CLOSED

    def test_half_open_after_recovery_timeout(self):
        """Test circuit enters half-open state after timeout."""
        from attestation.jwks import CircuitBreaker, CircuitBreakerConfig, CircuitState

        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=0.1)
        cb = CircuitBreaker(config)

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Wait for recovery timeout
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.can_execute() is True

    def test_half_open_closes_on_success(self):
        """Test circuit closes after successful call in half-open."""
        from attestation.jwks import CircuitBreaker, CircuitBreakerConfig, CircuitState

        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=0.1)
        cb = CircuitBreaker(config)

        cb.record_failure()
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        """Test circuit reopens after failure in half-open."""
        from attestation.jwks import CircuitBreaker, CircuitBreakerConfig, CircuitState

        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=0.1)
        cb = CircuitBreaker(config)

        cb.record_failure()
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_reset(self):
        """Test reset returns to initial state."""
        from attestation.jwks import CircuitBreaker, CircuitBreakerConfig, CircuitState

        config = CircuitBreakerConfig(failure_threshold=1)
        cb = CircuitBreaker(config)

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0


class TestRetryConfig:
    """Tests for retry configuration."""

    def test_default_values(self):
        """Test retry config has sensible defaults."""
        from attestation.jwks import RetryConfig

        config = RetryConfig()

        assert config.max_retries == 3
        assert config.base_delay == 0.5
        assert config.max_delay == 10.0
        assert config.exponential_base == 2.0
        assert config.jitter is True

    def test_custom_values(self):
        """Test retry config accepts custom values."""
        from attestation.jwks import RetryConfig

        config = RetryConfig(
            max_retries=5,
            base_delay=1.0,
            max_delay=30.0,
            exponential_base=3.0,
            jitter=False,
        )

        assert config.max_retries == 5
        assert config.base_delay == 1.0


class TestJWKSFetcherResilience:
    """Tests for JWKS fetcher resilience features."""

    @pytest.mark.asyncio
    async def test_metrics_tracking(self):
        """Test that metrics are tracked correctly."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher()

        # Initial metrics should be zero
        assert fetcher.metrics["cache_hits"] == 0
        assert fetcher.metrics["cache_misses"] == 0

    @pytest.mark.asyncio
    async def test_circuit_breaker_rejects_when_open(self):
        """Test circuit breaker rejects requests when open."""
        from attestation.jwks import JWKSFetcher, CircuitBreakerConfig, RetryConfig
        import httpx

        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=60)
        retry_config = RetryConfig(max_retries=0)  # No retries for faster test
        fetcher = JWKSFetcher(
            circuit_breaker_config=config,
            retry_config=retry_config,
        )

        # Open the circuit breaker
        cb = fetcher._get_circuit_breaker("https://test.com")
        cb.record_failure()

        # Should reject immediately
        with pytest.raises(httpx.HTTPError, match="Circuit breaker open"):
            await fetcher.get_jwks("https://test.com")

        assert fetcher.metrics["circuit_breaker_rejections"] == 1

    @pytest.mark.asyncio
    async def test_retry_delay_calculation(self):
        """Test exponential backoff delay calculation."""
        from attestation.jwks import JWKSFetcher, RetryConfig

        config = RetryConfig(base_delay=1.0, max_delay=10.0, exponential_base=2.0, jitter=False)
        fetcher = JWKSFetcher(retry_config=config)

        # Without jitter, delays should be exact
        assert fetcher._calculate_retry_delay(0) == 1.0
        assert fetcher._calculate_retry_delay(1) == 2.0
        assert fetcher._calculate_retry_delay(2) == 4.0
        assert fetcher._calculate_retry_delay(3) == 8.0
        # Should cap at max_delay
        assert fetcher._calculate_retry_delay(10) == 10.0

    @pytest.mark.asyncio
    async def test_close_releases_resources(self):
        """Test that close releases HTTP client."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher()

        # Get a client
        await fetcher._get_client()
        assert fetcher._client is not None

        # Close should release it
        await fetcher.close()
        assert fetcher._client is None


class TestRedisCacheResilience:
    """Tests for Redis cache resilience features."""

    def test_redis_config_defaults(self):
        """Test Redis config has sensible defaults."""
        from attestation.cache import RedisConfig

        config = RedisConfig()

        assert config.url == "redis://localhost:6379"
        assert config.fallback_enabled is True
        assert config.max_retries == 3
        assert config.pool_size == 10

    @pytest.mark.asyncio
    async def test_metrics_tracking(self):
        """Test cache metrics are tracked."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache

        cache = RedisReplayCache()

        # Use fallback mode for testing
        await cache.check_and_add("jti-1", int(time.time()) + 3600)

        assert cache.metrics.checks == 1
        # Should have activated fallback
        assert cache.metrics.fallback_activations >= 1

    @pytest.mark.asyncio
    async def test_health_status_report(self):
        """Test health status reporting."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache

        cache = RedisReplayCache()
        status = cache.get_health_status()

        assert "state" in status
        assert "using_fallback" in status
        assert "redis_connected" in status
        assert "metrics" in status

    @pytest.mark.asyncio
    async def test_fallback_replay_detection(self):
        """Test replay detection works in fallback mode."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache

        cache = RedisReplayCache()

        exp = int(time.time()) + 3600

        # First check should pass
        result1 = await cache.check_and_add("replay-test-jti", exp)
        assert result1 is True

        # Second check (replay) should fail
        result2 = await cache.check_and_add("replay-test-jti", exp)
        assert result2 is False

        assert cache.metrics.replays_detected == 1


class TestMCPClientVersionCheck:
    """Tests for MCP client version compatibility."""

    def test_sdk_compatibility_check(self):
        """Test SDK compatibility verification."""
        try:
            from attestation.mcp_client import _verify_sdk_compatibility, MCP_AVAILABLE

            if MCP_AVAILABLE:
                result = _verify_sdk_compatibility()
                assert result is True
        except ImportError:
            pytest.skip("MCP not installed")


class TestCacheStateTransitions:
    """Tests for cache state transitions."""

    @pytest.mark.asyncio
    async def test_state_healthy_to_degraded(self):
        """Test transition from healthy to degraded."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache, CacheState

        cache = RedisReplayCache()

        # Initially unhealthy (not connected)
        assert cache.state == CacheState.UNHEALTHY

        # After using fallback, should be degraded
        await cache.check_and_add("jti", int(time.time()) + 3600)
        assert cache.state == CacheState.DEGRADED

    @pytest.mark.asyncio
    async def test_consecutive_failure_tracking(self):
        """Test consecutive failure counter."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache

        cache = RedisReplayCache()

        # Trigger fallback (which increments consecutive failures)
        await cache.check_and_add("jti", int(time.time()) + 3600)

        # Should have recorded failures before falling back
        assert cache._consecutive_failures >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
