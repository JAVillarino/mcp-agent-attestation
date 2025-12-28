"""
Tests for JWKS Fetcher

Run with: pytest tests/test_jwks.py -v
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import time


class TestJWKSFetcher:
    """Tests for JWKSFetcher class."""

    def test_build_jwks_url(self):
        """Test JWKS URL construction."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher()

        # Normal URL
        assert fetcher._get_jwks_url("https://api.anthropic.com") == \
            "https://api.anthropic.com/.well-known/jwks.json"

        # URL with trailing slash
        assert fetcher._get_jwks_url("https://api.anthropic.com/") == \
            "https://api.anthropic.com/.well-known/jwks.json"

    def test_cache_validity(self):
        """Test cache TTL checking."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher(cache_ttl_seconds=60)

        # No cache entry
        assert fetcher._is_cache_valid("https://example.com") is False

        # Fresh cache entry
        fetcher._cache["https://example.com"] = ({"keys": []}, time.time())
        assert fetcher._is_cache_valid("https://example.com") is True

        # Expired cache entry
        fetcher._cache["https://example.com"] = ({"keys": []}, time.time() - 120)
        assert fetcher._is_cache_valid("https://example.com") is False

    @pytest.mark.asyncio
    async def test_get_jwks_caches_result(self):
        """Test that JWKS responses are cached."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher()
        mock_jwks = {"keys": [{"kid": "test-key", "kty": "OKP", "crv": "Ed25519", "x": "abc"}]}

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            # First call should fetch
            result1 = await fetcher.get_jwks("https://api.anthropic.com")
            assert result1 == mock_jwks
            assert mock_instance.get.call_count == 1

            # Second call should use cache
            result2 = await fetcher.get_jwks("https://api.anthropic.com")
            assert result2 == mock_jwks
            assert mock_instance.get.call_count == 1  # Still 1, not 2

    @pytest.mark.asyncio
    async def test_get_jwks_validates_response(self):
        """Test that invalid JWKS responses are rejected."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher()

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            # Missing 'keys' field
            mock_response.json.return_value = {"not_keys": []}
            with pytest.raises(ValueError, match="missing 'keys' array"):
                await fetcher.get_jwks("https://example.com")

            # Clear cache for next test
            fetcher.clear_cache()

            # 'keys' is not an array
            mock_response.json.return_value = {"keys": "not-an-array"}
            with pytest.raises(ValueError, match="'keys' is not an array"):
                await fetcher.get_jwks("https://example.com")

    @pytest.mark.asyncio
    async def test_get_key_returns_none_for_missing_kid(self):
        """Test that get_key returns None for unknown key ID."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher()
        mock_jwks = {"keys": [{"kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "abc"}]}

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            # Existing key
            result = await fetcher.get_key("https://example.com", "key-1")
            assert result is not None

            # Non-existing key
            result = await fetcher.get_key("https://example.com", "key-2")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_key_handles_fetch_error(self):
        """Test that get_key returns None on fetch error."""
        from attestation.jwks import JWKSFetcher
        import httpx

        fetcher = JWKSFetcher()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.side_effect = httpx.HTTPError("Connection failed")
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            result = await fetcher.get_key("https://example.com", "any-key")
            assert result is None

    def test_clear_cache(self):
        """Test cache clearing."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher()
        fetcher._cache["https://example.com"] = ({"keys": []}, time.time())

        assert "https://example.com" in fetcher._cache
        fetcher.clear_cache()
        assert "https://example.com" not in fetcher._cache

    def test_invalidate_issuer(self):
        """Test invalidating specific issuer."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher()
        fetcher._cache["https://a.com"] = ({"keys": []}, time.time())
        fetcher._cache["https://b.com"] = ({"keys": []}, time.time())

        fetcher.invalidate("https://a.com")

        assert "https://a.com" not in fetcher._cache
        assert "https://b.com" in fetcher._cache

    def test_parse_ed25519_key(self):
        """Test Ed25519 key parsing."""
        from attestation.jwks import JWKSFetcher, CRYPTO_AVAILABLE

        fetcher = JWKSFetcher()

        # Valid Ed25519 JWK (32 bytes = 43 base64url chars)
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "test-key",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }

        result = fetcher._parse_key(jwk)

        if CRYPTO_AVAILABLE:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            assert isinstance(result, Ed25519PublicKey)
        else:
            # Returns raw JWK when crypto not available
            assert result == jwk

    def test_parse_unsupported_key_type(self):
        """Test that unsupported key types return raw JWK."""
        from attestation.jwks import JWKSFetcher

        fetcher = JWKSFetcher()

        # RSA key (not supported for attestation)
        jwk = {
            "kty": "RSA",
            "kid": "rsa-key",
            "n": "abc",
            "e": "AQAB",
        }

        result = fetcher._parse_key(jwk)
        assert result == jwk  # Returns raw JWK


class TestHTTPKeyResolver:
    """Tests for HTTPKeyResolver class."""

    @pytest.mark.asyncio
    async def test_get_key_delegates_to_fetcher(self):
        """Test that get_key delegates to underlying fetcher."""
        from attestation.jwks import HTTPKeyResolver, JWKSFetcher

        mock_fetcher = AsyncMock(spec=JWKSFetcher)
        mock_fetcher.get_key.return_value = "mock-key"

        resolver = HTTPKeyResolver(fetcher=mock_fetcher)
        result = await resolver.get_key("https://example.com", "key-1")

        assert result == "mock-key"
        mock_fetcher.get_key.assert_called_once_with("https://example.com", "key-1")

    def test_clear_cache_delegates(self):
        """Test that clear_cache delegates to fetcher."""
        from attestation.jwks import HTTPKeyResolver, JWKSFetcher

        mock_fetcher = MagicMock(spec=JWKSFetcher)
        resolver = HTTPKeyResolver(fetcher=mock_fetcher)

        resolver.clear_cache()
        mock_fetcher.clear_cache.assert_called_once()

    def test_invalidate_delegates(self):
        """Test that invalidate delegates to fetcher."""
        from attestation.jwks import HTTPKeyResolver, JWKSFetcher

        mock_fetcher = MagicMock(spec=JWKSFetcher)
        resolver = HTTPKeyResolver(fetcher=mock_fetcher)

        resolver.invalidate("https://example.com")
        mock_fetcher.invalidate.assert_called_once_with("https://example.com")

    def test_creates_default_fetcher(self):
        """Test that resolver creates fetcher if not provided."""
        from attestation.jwks import HTTPKeyResolver, JWKSFetcher

        resolver = HTTPKeyResolver(cache_ttl_seconds=1800)

        assert isinstance(resolver._fetcher, JWKSFetcher)
        assert resolver._fetcher._cache_ttl == 1800


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
