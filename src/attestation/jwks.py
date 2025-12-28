"""
MCP Agent Attestation - JWKS Fetcher

Fetches and caches JSON Web Key Sets (JWKS) from issuer endpoints
for verifying attestation token signatures.

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import base64
import logging
import time
from typing import Any, Protocol

import httpx

logger = logging.getLogger(__name__)

# Try to import cryptography for key parsing
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class KeyResolverProtocol(Protocol):
    """Protocol for resolving public keys from issuers."""

    async def get_key(self, issuer: str, kid: str) -> Any | None:
        """Resolve public key for issuer and key ID."""
        ...


class JWKSFetcher:
    """
    Fetches and caches JWKS from issuer well-known endpoints.

    Usage:
        fetcher = JWKSFetcher(cache_ttl_seconds=3600)
        jwks = await fetcher.get_jwks("https://api.anthropic.com")
        key = await fetcher.get_key("https://api.anthropic.com", "anthropic-2025-01")
    """

    def __init__(
        self,
        cache_ttl_seconds: int = 3600,
        request_timeout_seconds: float = 10.0,
    ):
        """
        Initialize JWKS fetcher.

        Args:
            cache_ttl_seconds: How long to cache JWKS responses (default: 1 hour)
            request_timeout_seconds: HTTP request timeout (default: 10 seconds)
        """
        self._cache: dict[str, tuple[dict[str, Any], float]] = {}
        self._cache_ttl = cache_ttl_seconds
        self._timeout = request_timeout_seconds

    def _is_cache_valid(self, issuer: str) -> bool:
        """Check if cached JWKS is still valid."""
        if issuer not in self._cache:
            return False
        _, cached_at = self._cache[issuer]
        return time.time() - cached_at < self._cache_ttl

    def _get_jwks_url(self, issuer: str) -> str:
        """Build JWKS endpoint URL from issuer."""
        return f"{issuer.rstrip('/')}/.well-known/jwks.json"

    async def get_jwks(self, issuer: str) -> dict[str, Any]:
        """
        Fetch JWKS from issuer's well-known endpoint.

        Args:
            issuer: Issuer URL (e.g., "https://api.anthropic.com")

        Returns:
            JWKS dictionary with "keys" array

        Raises:
            httpx.HTTPError: If request fails
            ValueError: If response is not valid JWKS
        """
        # Check cache first
        if self._is_cache_valid(issuer):
            jwks, _ = self._cache[issuer]
            logger.debug(f"JWKS cache hit for {issuer}")
            return jwks

        # Fetch from endpoint
        url = self._get_jwks_url(issuer)
        logger.info(f"Fetching JWKS from {url}")

        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=self._timeout)
            response.raise_for_status()
            jwks = response.json()

        # Validate structure
        if not isinstance(jwks, dict) or "keys" not in jwks:
            raise ValueError(f"Invalid JWKS response from {issuer}: missing 'keys' array")

        if not isinstance(jwks["keys"], list):
            raise ValueError(f"Invalid JWKS response from {issuer}: 'keys' is not an array")

        # Cache the result
        self._cache[issuer] = (jwks, time.time())
        logger.debug(f"Cached JWKS for {issuer} with {len(jwks['keys'])} keys")

        return jwks

    async def get_key(self, issuer: str, kid: str) -> Any | None:
        """
        Get a specific key from issuer's JWKS.

        Args:
            issuer: Issuer URL
            kid: Key ID to find

        Returns:
            Ed25519PublicKey if found and crypto available, raw JWK dict otherwise, None if not found
        """
        try:
            jwks = await self.get_jwks(issuer)
        except Exception as e:
            logger.warning(f"Failed to fetch JWKS from {issuer}: {e}")
            return None

        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return self._parse_key(key)

        logger.warning(f"Key {kid} not found in JWKS from {issuer}")
        return None

    def _parse_key(self, jwk: dict[str, Any]) -> Any:
        """
        Parse JWK to public key object.

        Args:
            jwk: JWK dictionary

        Returns:
            Ed25519PublicKey if crypto available, raw JWK dict otherwise
        """
        # Verify it's an Ed25519 key
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            logger.warning(f"Unsupported key type: kty={jwk.get('kty')}, crv={jwk.get('crv')}")
            return jwk  # Return raw JWK for caller to handle

        if not CRYPTO_AVAILABLE:
            logger.debug("Cryptography not available, returning raw JWK")
            return jwk

        # Parse Ed25519 public key
        try:
            x = jwk["x"]
            # Add padding if needed
            padding = 4 - len(x) % 4
            if padding != 4:
                x += "=" * padding
            key_bytes = base64.urlsafe_b64decode(x)
            return Ed25519PublicKey.from_public_bytes(key_bytes)
        except Exception as e:
            logger.error(f"Failed to parse Ed25519 key: {e}")
            return jwk

    def clear_cache(self):
        """Clear the JWKS cache."""
        self._cache.clear()
        logger.debug("JWKS cache cleared")

    def invalidate(self, issuer: str):
        """Invalidate cached JWKS for a specific issuer."""
        if issuer in self._cache:
            del self._cache[issuer]
            logger.debug(f"Invalidated JWKS cache for {issuer}")


class HTTPKeyResolver:
    """
    KeyResolver implementation that fetches keys via HTTP.

    This is the production-ready key resolver that fetches public keys
    from issuer JWKS endpoints.

    Usage:
        resolver = HTTPKeyResolver()
        key = await resolver.get_key("https://api.anthropic.com", "anthropic-2025-01")
    """

    def __init__(
        self,
        fetcher: JWKSFetcher | None = None,
        cache_ttl_seconds: int = 3600,
    ):
        """
        Initialize HTTP key resolver.

        Args:
            fetcher: Optional JWKSFetcher instance (creates one if not provided)
            cache_ttl_seconds: Cache TTL for JWKS (only used if fetcher not provided)
        """
        self._fetcher = fetcher or JWKSFetcher(cache_ttl_seconds=cache_ttl_seconds)

    async def get_key(self, issuer: str, kid: str) -> Any | None:
        """
        Resolve public key for issuer and key ID.

        Args:
            issuer: Issuer URL
            kid: Key ID

        Returns:
            Public key if found, None otherwise
        """
        return await self._fetcher.get_key(issuer, kid)

    def clear_cache(self):
        """Clear the underlying JWKS cache."""
        self._fetcher.clear_cache()

    def invalidate(self, issuer: str):
        """Invalidate cached JWKS for a specific issuer."""
        self._fetcher.invalidate(issuer)
