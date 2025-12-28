"""
Tests for Distributed Cache

Run with: pytest tests/test_cache.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import time


class TestInMemoryReplayCache:
    """Tests for InMemoryReplayCache class."""

    @pytest.mark.asyncio
    async def test_check_and_add_new_jti(self):
        """Test that new JTI returns True and is added."""
        from attestation.cache import InMemoryReplayCache

        cache = InMemoryReplayCache()
        exp = int(time.time()) + 300  # 5 min from now

        result = await cache.check_and_add("jti-123", exp)

        assert result is True
        assert await cache.exists("jti-123")

    @pytest.mark.asyncio
    async def test_check_and_add_duplicate_jti(self):
        """Test that duplicate JTI returns False."""
        from attestation.cache import InMemoryReplayCache

        cache = InMemoryReplayCache()
        exp = int(time.time()) + 300

        # First add
        result1 = await cache.check_and_add("jti-123", exp)
        assert result1 is True

        # Second add (replay)
        result2 = await cache.check_and_add("jti-123", exp)
        assert result2 is False

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        """Test that expired entries are cleaned up."""
        from attestation.cache import InMemoryReplayCache

        cache = InMemoryReplayCache()

        # Add expired entry
        cache._seen["old-jti"] = int(time.time()) - 100  # Already expired

        # Add valid entry
        cache._seen["new-jti"] = int(time.time()) + 300

        # Trigger cleanup
        cache._cleanup_expired()

        assert "old-jti" not in cache._seen
        assert "new-jti" in cache._seen

    @pytest.mark.asyncio
    async def test_clear(self):
        """Test clearing the cache."""
        from attestation.cache import InMemoryReplayCache

        cache = InMemoryReplayCache()
        exp = int(time.time()) + 300

        await cache.check_and_add("jti-1", exp)
        await cache.check_and_add("jti-2", exp)

        assert await cache.count() == 2

        await cache.clear()

        assert await cache.count() == 0

    @pytest.mark.asyncio
    async def test_count(self):
        """Test counting cached entries."""
        from attestation.cache import InMemoryReplayCache

        cache = InMemoryReplayCache()
        exp = int(time.time()) + 300

        assert await cache.count() == 0

        await cache.check_and_add("jti-1", exp)
        assert await cache.count() == 1

        await cache.check_and_add("jti-2", exp)
        assert await cache.count() == 2


class TestRedisReplayCache:
    """Tests for RedisReplayCache class."""

    @pytest.fixture
    def mock_redis(self):
        """Create mock Redis client."""
        mock = AsyncMock()
        mock.ping = AsyncMock()
        mock.setnx = AsyncMock(return_value=True)
        mock.expire = AsyncMock()
        mock.exists = AsyncMock(return_value=1)
        mock.scan = AsyncMock(return_value=(0, []))
        mock.delete = AsyncMock()
        mock.close = AsyncMock()
        return mock

    @pytest.mark.asyncio
    async def test_connect_success(self, mock_redis):
        """Test successful connection."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache

        cache = RedisReplayCache()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            await cache.connect()

        assert cache.is_connected
        mock_redis.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_close(self, mock_redis):
        """Test closing connection."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache

        cache = RedisReplayCache()
        cache._client = mock_redis

        await cache.close()

        assert cache._client is None
        mock_redis.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_and_add_new_jti(self, mock_redis):
        """Test adding new JTI."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache

        cache = RedisReplayCache()
        cache._client = mock_redis
        mock_redis.setnx.return_value = True

        exp = int(time.time()) + 300
        result = await cache.check_and_add("jti-123", exp)

        assert result is True
        mock_redis.setnx.assert_called_once()
        mock_redis.expire.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_and_add_duplicate_jti(self, mock_redis):
        """Test detecting duplicate JTI."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache

        cache = RedisReplayCache()
        cache._client = mock_redis
        mock_redis.setnx.return_value = False  # Key already exists

        exp = int(time.time()) + 300
        result = await cache.check_and_add("jti-123", exp)

        assert result is False
        mock_redis.expire.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_and_add_not_connected_uses_fallback(self):
        """Test that operations fall back to in-memory when not connected."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache, RedisConfig, CacheState

        # With fallback enabled (default), should succeed using in-memory
        cache = RedisReplayCache()
        result = await cache.check_and_add("jti", 12345)

        assert result is True  # New JTI accepted
        assert cache.is_using_fallback is True
        assert cache.state == CacheState.DEGRADED

    @pytest.mark.asyncio
    async def test_check_and_add_no_fallback_raises(self):
        """Test that operations raise when fallback disabled."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache, RedisConfig

        # With fallback disabled, should raise
        config = RedisConfig(fallback_enabled=False)
        cache = RedisReplayCache(config=config)

        with pytest.raises(RuntimeError, match="Redis unavailable"):
            await cache.check_and_add("jti", 12345)

    @pytest.mark.asyncio
    async def test_exists(self, mock_redis):
        """Test checking if JTI exists."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache, CacheState

        cache = RedisReplayCache()
        cache._client = mock_redis
        cache._state = CacheState.HEALTHY
        mock_redis.exists.return_value = 1

        result = await cache.exists("jti-123")

        assert result is True
        mock_redis.exists.assert_called_once()

    @pytest.mark.asyncio
    async def test_clear(self, mock_redis):
        """Test clearing cache."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache, CacheState

        cache = RedisReplayCache()
        cache._client = mock_redis
        cache._state = CacheState.HEALTHY

        # Simulate finding some keys
        mock_redis.scan.side_effect = [
            (1, [b"key1", b"key2"]),
            (0, [b"key3"]),
        ]

        await cache.clear()

        assert mock_redis.delete.call_count == 2

    @pytest.mark.asyncio
    async def test_count(self, mock_redis):
        """Test counting entries."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache, CacheState

        cache = RedisReplayCache()
        cache._client = mock_redis
        cache._state = CacheState.HEALTHY

        mock_redis.scan.side_effect = [
            (1, [b"key1", b"key2"]),
            (0, [b"key3"]),
        ]

        count = await cache.count()

        assert count == 3

    @pytest.mark.asyncio
    async def test_context_manager(self, mock_redis):
        """Test async context manager."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            async with RedisReplayCache() as cache:
                assert cache.is_connected

        mock_redis.close.assert_called_once()

    def test_key_prefix(self):
        """Test that custom key prefix is used."""
        from attestation.cache import REDIS_AVAILABLE

        if not REDIS_AVAILABLE:
            pytest.skip("Redis not installed")

        from attestation.cache import RedisReplayCache, RedisConfig

        # Test with legacy parameter
        cache = RedisReplayCache(key_prefix="custom:prefix:")
        assert cache._config.key_prefix == "custom:prefix:"

        # Test with new config object
        config = RedisConfig(key_prefix="config:prefix:")
        cache2 = RedisReplayCache(config=config)
        assert cache2._config.key_prefix == "config:prefix:"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
