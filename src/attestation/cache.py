"""
MCP Agent Attestation - Distributed Cache

Provides Redis-based replay cache for distributed deployments
where multiple server instances need to share token state.

Production-hardened with:
- Circuit breaker for Redis failures
- Automatic fallback to in-memory cache
- Health checks and reconnection logic
- Comprehensive metrics

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class CacheState(Enum):
    """Cache health states."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"  # Fallback active
    UNHEALTHY = "unhealthy"  # Completely unavailable


@dataclass
class CacheMetrics:
    """Metrics for cache observability."""

    checks: int = 0
    hits: int = 0
    misses: int = 0
    replays_detected: int = 0
    redis_errors: int = 0
    fallback_activations: int = 0
    reconnections: int = 0

    def to_dict(self) -> dict[str, int]:
        """Convert to dictionary."""
        return {
            "checks": self.checks,
            "hits": self.hits,
            "misses": self.misses,
            "replays_detected": self.replays_detected,
            "redis_errors": self.redis_errors,
            "fallback_activations": self.fallback_activations,
            "reconnections": self.reconnections,
        }


@dataclass
class RedisConfig:
    """Configuration for Redis cache."""

    url: str = "redis://localhost:6379"
    key_prefix: str = "mcp_attestation:jti:"
    connection_timeout: float = 5.0
    socket_timeout: float = 2.0
    max_retries: int = 3
    retry_delay: float = 0.5
    health_check_interval: float = 30.0
    fallback_enabled: bool = True  # Fall back to in-memory on Redis failure
    pool_size: int = 10

# Try to import redis
try:
    import redis.asyncio as redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None  # type: ignore


class ReplayCacheProtocol(Protocol):
    """Protocol for replay cache implementations."""

    async def check_and_add(self, jti: str, exp: int) -> bool:
        """
        Check if JTI is new and add to cache.

        Args:
            jti: JWT ID to check
            exp: Expiration timestamp

        Returns:
            True if JTI is new (not a replay), False if seen before
        """
        ...

    async def clear(self) -> None:
        """Clear all cached tokens."""
        ...


class RedisReplayCache:
    """
    Distributed replay cache using Redis.

    This cache uses Redis to store seen JWT IDs, enabling replay
    protection across multiple server instances in a distributed
    deployment.

    Production-hardened with:
    - Automatic fallback to in-memory cache on Redis failure
    - Health checks and reconnection logic
    - Retry logic with exponential backoff
    - Comprehensive metrics

    Usage:
        cache = RedisReplayCache(redis_url="redis://localhost:6379")
        await cache.connect()

        # Check if token is new
        is_new = await cache.check_and_add(jti, exp_timestamp)
        if not is_new:
            raise ValueError("Token replay detected")

        # Cleanup
        await cache.close()

    The cache automatically expires entries based on the token's
    expiration time, so no manual cleanup is needed.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        key_prefix: str | None = None,
        connection_timeout: float | None = None,
        config: RedisConfig | None = None,
    ):
        """
        Initialize Redis replay cache.

        Args:
            redis_url: Redis connection URL (deprecated, use config)
            key_prefix: Prefix for all keys in Redis (deprecated, use config)
            connection_timeout: Connection timeout in seconds (deprecated, use config)
            config: Full configuration object (preferred)
        """
        if not REDIS_AVAILABLE:
            raise RuntimeError(
                "redis-py not installed. Install with: pip install redis"
            )

        # Support both old-style args and new config object
        if config:
            self._config = config
        else:
            self._config = RedisConfig(
                url=redis_url or "redis://localhost:6379",
                key_prefix=key_prefix or "mcp_attestation:jti:",
                connection_timeout=connection_timeout or 5.0,
            )

        self._client: redis.Redis | None = None
        self._fallback_cache: InMemoryReplayCache | None = None
        self._using_fallback = False
        self._last_health_check: float = 0
        self._consecutive_failures = 0
        self._metrics = CacheMetrics()
        self._state = CacheState.UNHEALTHY
        self._reconnect_task: asyncio.Task | None = None

    @property
    def state(self) -> CacheState:
        """Get current cache state."""
        return self._state

    @property
    def metrics(self) -> CacheMetrics:
        """Get cache metrics."""
        return self._metrics

    @property
    def is_using_fallback(self) -> bool:
        """Check if currently using fallback cache."""
        return self._using_fallback

    async def _init_fallback(self) -> None:
        """Initialize fallback in-memory cache."""
        if self._fallback_cache is None:
            self._fallback_cache = InMemoryReplayCache()
            logger.info("Initialized fallback in-memory cache")

    async def _activate_fallback(self) -> None:
        """Activate fallback cache mode."""
        if not self._config.fallback_enabled:
            return

        await self._init_fallback()
        if not self._using_fallback:
            self._using_fallback = True
            self._state = CacheState.DEGRADED
            self._metrics.fallback_activations += 1
            logger.warning("Activated fallback in-memory cache due to Redis failure")

            # Start background reconnection task
            if self._reconnect_task is None or self._reconnect_task.done():
                self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _deactivate_fallback(self) -> None:
        """Deactivate fallback and return to Redis."""
        if self._using_fallback:
            self._using_fallback = False
            self._state = CacheState.HEALTHY
            self._consecutive_failures = 0
            logger.info("Deactivated fallback, returned to Redis")

    async def _reconnect_loop(self) -> None:
        """Background task to attempt Redis reconnection."""
        while self._using_fallback:
            await asyncio.sleep(self._config.health_check_interval)
            try:
                if await self._health_check():
                    await self._deactivate_fallback()
                    break
            except Exception as e:
                logger.debug(f"Reconnection attempt failed: {e}")

    async def _health_check(self) -> bool:
        """Check Redis health."""
        try:
            if self._client is None:
                await self.connect()
            await self._client.ping()  # type: ignore
            self._last_health_check = time.time()
            return True
        except Exception as e:
            logger.debug(f"Health check failed: {e}")
            return False

    async def _execute_with_fallback(
        self,
        redis_op,
        fallback_op,
        *args,
        **kwargs,
    ):
        """
        Execute operation with Redis, falling back to in-memory on failure.

        Args:
            redis_op: Async function to call with Redis
            fallback_op: Async function to call with fallback cache
            *args, **kwargs: Arguments for the operations
        """
        if self._using_fallback:
            return await fallback_op(*args, **kwargs)

        for attempt in range(self._config.max_retries):
            try:
                result = await redis_op(*args, **kwargs)
                self._consecutive_failures = 0
                return result
            except Exception as e:
                self._consecutive_failures += 1
                self._metrics.redis_errors += 1
                logger.warning(
                    f"Redis operation failed (attempt {attempt + 1}): {e}"
                )

                if attempt < self._config.max_retries - 1:
                    await asyncio.sleep(
                        self._config.retry_delay * (2 ** attempt)
                    )

        # All retries failed, activate fallback
        await self._activate_fallback()
        if self._config.fallback_enabled and self._fallback_cache:
            return await fallback_op(*args, **kwargs)
        raise RuntimeError("Redis unavailable and fallback disabled")

    async def connect(self) -> None:
        """
        Connect to Redis.

        Raises:
            redis.ConnectionError: If connection fails and fallback disabled
        """
        try:
            self._client = redis.from_url(
                self._config.url,
                socket_timeout=self._config.socket_timeout,
                socket_connect_timeout=self._config.connection_timeout,
                max_connections=self._config.pool_size,
            )
            # Test connection
            await self._client.ping()
            self._state = CacheState.HEALTHY
            self._metrics.reconnections += 1
            logger.info(f"Connected to Redis at {self._config.url}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            if self._config.fallback_enabled:
                await self._activate_fallback()
            else:
                self._state = CacheState.UNHEALTHY
                raise

    async def close(self) -> None:
        """Close Redis connection and cleanup resources."""
        # Cancel reconnection task if running
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
            self._reconnect_task = None

        if self._client:
            await self._client.close()
            self._client = None
            logger.debug("Closed Redis connection")

        self._state = CacheState.UNHEALTHY

    async def check_and_add(self, jti: str, exp: int) -> bool:
        """
        Check if JTI is new and add to cache atomically.

        This uses Redis SETNX for atomic check-and-set to prevent
        race conditions in distributed deployments. Falls back to
        in-memory cache if Redis is unavailable.

        Args:
            jti: JWT ID to check
            exp: Expiration timestamp (Unix seconds)

        Returns:
            True if JTI is new (first time seen), False if replay

        Raises:
            RuntimeError: If not connected and fallback disabled
        """
        self._metrics.checks += 1

        async def redis_check_and_add(jti: str, exp: int) -> bool:
            if not self._client:
                raise RuntimeError("Not connected to Redis")

            key = f"{self._config.key_prefix}{jti}"

            # Use SETNX for atomic check-and-set
            was_set = await self._client.setnx(key, "1")

            if was_set:
                # Calculate TTL based on expiration
                ttl = max(1, exp - int(time.time()))
                await self._client.expire(key, ttl)
                self._metrics.misses += 1
                logger.debug(f"Added JTI {jti[:8]}... to cache with TTL {ttl}s")
                return True
            else:
                self._metrics.hits += 1
                self._metrics.replays_detected += 1
                logger.warning(f"Replay detected for JTI {jti[:8]}...")
                return False

        async def fallback_check_and_add(jti: str, exp: int) -> bool:
            if self._fallback_cache:
                result = await self._fallback_cache.check_and_add(jti, exp)
                if result:
                    self._metrics.misses += 1
                else:
                    self._metrics.hits += 1
                    self._metrics.replays_detected += 1
                return result
            raise RuntimeError("Fallback cache not initialized")

        return await self._execute_with_fallback(
            redis_check_and_add,
            fallback_check_and_add,
            jti,
            exp,
        )

    async def clear(self) -> None:
        """
        Clear all cached tokens.

        WARNING: This removes ALL attestation tokens from the cache.
        Use only for testing or administrative purposes.
        """
        # Clear fallback cache if active
        if self._fallback_cache:
            await self._fallback_cache.clear()

        if self._using_fallback or not self._client:
            return

        try:
            # Find and delete all keys with our prefix
            cursor = 0
            deleted_count = 0
            while True:
                cursor, keys = await self._client.scan(
                    cursor=cursor,
                    match=f"{self._config.key_prefix}*",
                    count=100,
                )
                if keys:
                    await self._client.delete(*keys)
                    deleted_count += len(keys)
                if cursor == 0:
                    break

            logger.info(f"Cleared {deleted_count} tokens from Redis cache")
        except Exception as e:
            logger.error(f"Failed to clear Redis cache: {e}")

    async def exists(self, jti: str) -> bool:
        """
        Check if JTI exists in cache without adding it.

        Args:
            jti: JWT ID to check

        Returns:
            True if JTI exists, False otherwise
        """
        if self._using_fallback and self._fallback_cache:
            return await self._fallback_cache.exists(jti)

        if not self._client:
            return False

        try:
            key = f"{self._config.key_prefix}{jti}"
            return bool(await self._client.exists(key))
        except Exception as e:
            logger.warning(f"Redis exists check failed: {e}")
            if self._fallback_cache:
                return await self._fallback_cache.exists(jti)
            return False

    async def count(self) -> int:
        """
        Count total cached tokens.

        Returns:
            Number of tokens in cache
        """
        if self._using_fallback and self._fallback_cache:
            return await self._fallback_cache.count()

        if not self._client:
            return 0

        try:
            cursor = 0
            count = 0
            while True:
                cursor, keys = await self._client.scan(
                    cursor=cursor,
                    match=f"{self._config.key_prefix}*",
                    count=100,
                )
                count += len(keys)
                if cursor == 0:
                    break

            return count
        except Exception as e:
            logger.warning(f"Redis count failed: {e}")
            if self._fallback_cache:
                return await self._fallback_cache.count()
            return 0

    @property
    def is_connected(self) -> bool:
        """Check if connected to Redis (or fallback is active)."""
        return self._client is not None or self._using_fallback

    def get_health_status(self) -> dict[str, Any]:
        """
        Get comprehensive health status.

        Returns:
            Dict with state, metrics, and connection info
        """
        return {
            "state": self._state.value,
            "using_fallback": self._using_fallback,
            "redis_connected": self._client is not None,
            "last_health_check": self._last_health_check,
            "consecutive_failures": self._consecutive_failures,
            "metrics": self._metrics.to_dict(),
        }

    async def __aenter__(self) -> "RedisReplayCache":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()


class InMemoryReplayCache:
    """
    In-memory replay cache for single-server deployments.

    This is a simpler alternative to RedisReplayCache for deployments
    where only one server instance handles all requests.

    Note: This cache will not work in distributed deployments!
    Use RedisReplayCache for multi-server setups.
    """

    def __init__(self):
        """Initialize in-memory cache."""
        self._seen: dict[str, int] = {}  # jti -> exp

    async def check_and_add(self, jti: str, exp: int) -> bool:
        """
        Check if JTI is new and add to cache.

        Args:
            jti: JWT ID to check
            exp: Expiration timestamp

        Returns:
            True if JTI is new, False if replay
        """
        # Clean up expired entries periodically
        self._cleanup_expired()

        if jti in self._seen:
            logger.warning(f"Replay detected for JTI {jti[:8]}...")
            return False

        self._seen[jti] = exp
        logger.debug(f"Added JTI {jti[:8]}... to in-memory cache")
        return True

    async def clear(self) -> None:
        """Clear all cached tokens."""
        count = len(self._seen)
        self._seen.clear()
        logger.info(f"Cleared {count} tokens from in-memory cache")

    async def exists(self, jti: str) -> bool:
        """Check if JTI exists in cache."""
        return jti in self._seen

    async def count(self) -> int:
        """Count cached tokens."""
        return len(self._seen)

    def _cleanup_expired(self) -> None:
        """Remove expired entries from cache."""
        now = int(time.time())
        expired = [jti for jti, exp in self._seen.items() if exp < now]
        for jti in expired:
            del self._seen[jti]
        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired tokens")
