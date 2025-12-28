"""
MCP Agent Attestation - Distributed Cache

Provides Redis-based replay cache for distributed deployments
where multiple server instances need to share token state.

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import logging
import time
from typing import Protocol

logger = logging.getLogger(__name__)

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
        redis_url: str = "redis://localhost:6379",
        key_prefix: str = "mcp_attestation:jti:",
        connection_timeout: float = 5.0,
    ):
        """
        Initialize Redis replay cache.

        Args:
            redis_url: Redis connection URL
            key_prefix: Prefix for all keys in Redis
            connection_timeout: Connection timeout in seconds
        """
        if not REDIS_AVAILABLE:
            raise RuntimeError(
                "redis-py not installed. Install with: pip install redis"
            )

        self._redis_url = redis_url
        self._key_prefix = key_prefix
        self._connection_timeout = connection_timeout
        self._client: redis.Redis | None = None

    async def connect(self) -> None:
        """
        Connect to Redis.

        Raises:
            redis.ConnectionError: If connection fails
        """
        self._client = redis.from_url(
            self._redis_url,
            socket_timeout=self._connection_timeout,
            socket_connect_timeout=self._connection_timeout,
        )
        # Test connection
        await self._client.ping()
        logger.info(f"Connected to Redis at {self._redis_url}")

    async def close(self) -> None:
        """Close Redis connection."""
        if self._client:
            await self._client.close()
            self._client = None
            logger.debug("Closed Redis connection")

    async def check_and_add(self, jti: str, exp: int) -> bool:
        """
        Check if JTI is new and add to cache atomically.

        This uses Redis SETNX for atomic check-and-set to prevent
        race conditions in distributed deployments.

        Args:
            jti: JWT ID to check
            exp: Expiration timestamp (Unix seconds)

        Returns:
            True if JTI is new (first time seen), False if replay

        Raises:
            RuntimeError: If not connected to Redis
        """
        if not self._client:
            raise RuntimeError("Not connected to Redis. Call connect() first.")

        key = f"{self._key_prefix}{jti}"

        # Use SETNX for atomic check-and-set
        was_set = await self._client.setnx(key, "1")

        if was_set:
            # Calculate TTL based on expiration
            ttl = max(1, exp - int(time.time()))
            await self._client.expire(key, ttl)
            logger.debug(f"Added JTI {jti[:8]}... to cache with TTL {ttl}s")
            return True
        else:
            logger.warning(f"Replay detected for JTI {jti[:8]}...")
            return False

    async def clear(self) -> None:
        """
        Clear all cached tokens.

        WARNING: This removes ALL attestation tokens from the cache.
        Use only for testing or administrative purposes.
        """
        if not self._client:
            raise RuntimeError("Not connected to Redis. Call connect() first.")

        # Find and delete all keys with our prefix
        cursor = 0
        deleted_count = 0
        while True:
            cursor, keys = await self._client.scan(
                cursor=cursor,
                match=f"{self._key_prefix}*",
                count=100,
            )
            if keys:
                await self._client.delete(*keys)
                deleted_count += len(keys)
            if cursor == 0:
                break

        logger.info(f"Cleared {deleted_count} tokens from Redis cache")

    async def exists(self, jti: str) -> bool:
        """
        Check if JTI exists in cache without adding it.

        Args:
            jti: JWT ID to check

        Returns:
            True if JTI exists, False otherwise
        """
        if not self._client:
            raise RuntimeError("Not connected to Redis. Call connect() first.")

        key = f"{self._key_prefix}{jti}"
        return bool(await self._client.exists(key))

    async def count(self) -> int:
        """
        Count total cached tokens.

        Returns:
            Number of tokens in cache
        """
        if not self._client:
            raise RuntimeError("Not connected to Redis. Call connect() first.")

        cursor = 0
        count = 0
        while True:
            cursor, keys = await self._client.scan(
                cursor=cursor,
                match=f"{self._key_prefix}*",
                count=100,
            )
            count += len(keys)
            if cursor == 0:
                break

        return count

    @property
    def is_connected(self) -> bool:
        """Check if connected to Redis."""
        return self._client is not None

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
