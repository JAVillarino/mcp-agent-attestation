"""
MCP Agent Attestation - JWKS Fetcher

Fetches and caches JSON Web Key Sets (JWKS) from issuer endpoints
for verifying attestation token signatures.

Production-hardened with:
- Retry logic with exponential backoff
- Circuit breaker pattern for failing endpoints
- Connection pooling
- Comprehensive error handling

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import asyncio
import base64
import logging
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

import httpx

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5  # Failures before opening
    recovery_timeout: float = 30.0  # Seconds before trying again
    half_open_max_calls: int = 1  # Calls to allow in half-open state


class CircuitBreaker:
    """
    Circuit breaker for protecting against cascading failures.

    When an endpoint fails repeatedly, the circuit opens and requests
    are rejected immediately until a recovery timeout passes.
    """

    def __init__(self, config: CircuitBreakerConfig | None = None):
        self._config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float | None = None
        self._half_open_calls = 0

    @property
    def state(self) -> CircuitState:
        """Get current circuit state, updating if needed."""
        if self._state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self._last_failure_time is not None:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self._config.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
                    logger.info("Circuit breaker entering half-open state")
        return self._state

    def can_execute(self) -> bool:
        """Check if a request can be executed."""
        state = self.state  # This may update state
        if state == CircuitState.CLOSED:
            return True
        elif state == CircuitState.OPEN:
            return False
        else:  # HALF_OPEN
            return self._half_open_calls < self._config.half_open_max_calls

    def record_success(self) -> None:
        """Record a successful call."""
        if self._state == CircuitState.HALF_OPEN:
            logger.info("Circuit breaker closing after successful call")
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_calls = 0

    def record_failure(self) -> None:
        """Record a failed call."""
        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._state == CircuitState.HALF_OPEN:
            logger.warning("Circuit breaker opening after half-open failure")
            self._state = CircuitState.OPEN
        elif self._failure_count >= self._config.failure_threshold:
            logger.warning(
                f"Circuit breaker opening after {self._failure_count} failures"
            )
            self._state = CircuitState.OPEN

        if self._state == CircuitState.HALF_OPEN:
            self._half_open_calls += 1

    def reset(self) -> None:
        """Reset circuit breaker to initial state."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = None
        self._half_open_calls = 0


@dataclass
class RetryConfig:
    """Configuration for retry logic."""

    max_retries: int = 3
    base_delay: float = 0.5  # Initial delay in seconds
    max_delay: float = 10.0  # Maximum delay between retries
    exponential_base: float = 2.0  # Exponential backoff multiplier
    jitter: bool = True  # Add randomness to prevent thundering herd


class RetryError(Exception):
    """Raised when all retries are exhausted."""

    def __init__(self, message: str, last_error: Exception | None = None):
        super().__init__(message)
        self.last_error = last_error

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

    Production-hardened with:
    - Automatic retries with exponential backoff
    - Circuit breaker to prevent hammering failed endpoints
    - Connection pooling for efficient HTTP connections
    - Configurable timeouts and caching

    Usage:
        fetcher = JWKSFetcher(cache_ttl_seconds=3600)
        jwks = await fetcher.get_jwks("https://api.anthropic.com")
        key = await fetcher.get_key("https://api.anthropic.com", "anthropic-2025-01")
    """

    def __init__(
        self,
        cache_ttl_seconds: int = 3600,
        request_timeout_seconds: float = 10.0,
        retry_config: RetryConfig | None = None,
        circuit_breaker_config: CircuitBreakerConfig | None = None,
        connection_pool_size: int = 10,
    ):
        """
        Initialize JWKS fetcher.

        Args:
            cache_ttl_seconds: How long to cache JWKS responses (default: 1 hour)
            request_timeout_seconds: HTTP request timeout (default: 10 seconds)
            retry_config: Configuration for retry behavior
            circuit_breaker_config: Configuration for circuit breaker
            connection_pool_size: Size of HTTP connection pool
        """
        self._cache: dict[str, tuple[dict[str, Any], float]] = {}
        self._cache_ttl = cache_ttl_seconds
        self._timeout = request_timeout_seconds
        self._retry_config = retry_config or RetryConfig()

        # Per-issuer circuit breakers
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._circuit_breaker_config = circuit_breaker_config or CircuitBreakerConfig()

        # Connection pool for efficient HTTP
        self._connection_pool_size = connection_pool_size
        self._client: httpx.AsyncClient | None = None

        # Metrics for observability
        self._metrics = {
            "cache_hits": 0,
            "cache_misses": 0,
            "fetch_success": 0,
            "fetch_failures": 0,
            "circuit_breaker_rejections": 0,
            "retries": 0,
        }

    def _get_circuit_breaker(self, issuer: str) -> CircuitBreaker:
        """Get or create circuit breaker for issuer."""
        if issuer not in self._circuit_breakers:
            self._circuit_breakers[issuer] = CircuitBreaker(self._circuit_breaker_config)
        return self._circuit_breakers[issuer]

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with connection pooling."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                limits=httpx.Limits(
                    max_connections=self._connection_pool_size,
                    max_keepalive_connections=self._connection_pool_size,
                ),
                timeout=httpx.Timeout(self._timeout),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _calculate_retry_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt with exponential backoff."""
        delay = self._retry_config.base_delay * (
            self._retry_config.exponential_base ** attempt
        )
        delay = min(delay, self._retry_config.max_delay)

        if self._retry_config.jitter:
            # Add random jitter to prevent thundering herd
            delay = delay * (0.5 + random.random())

        return delay

    async def _fetch_with_retry(self, url: str, issuer: str) -> dict[str, Any]:
        """
        Fetch JWKS with retry logic and circuit breaker.

        Args:
            url: JWKS endpoint URL
            issuer: Issuer identifier (for circuit breaker)

        Returns:
            JWKS dictionary

        Raises:
            RetryError: If all retries exhausted
            httpx.HTTPError: If circuit breaker is open
        """
        circuit_breaker = self._get_circuit_breaker(issuer)

        if not circuit_breaker.can_execute():
            self._metrics["circuit_breaker_rejections"] += 1
            raise httpx.HTTPError(
                f"Circuit breaker open for {issuer}. "
                f"Retry after {self._circuit_breaker_config.recovery_timeout}s"
            )

        last_error: Exception | None = None
        client = await self._get_client()

        for attempt in range(self._retry_config.max_retries + 1):
            try:
                response = await client.get(url)
                response.raise_for_status()
                jwks = response.json()

                circuit_breaker.record_success()
                self._metrics["fetch_success"] += 1
                return jwks

            except httpx.TimeoutException as e:
                last_error = e
                logger.warning(f"Timeout fetching JWKS from {url} (attempt {attempt + 1})")
            except httpx.HTTPStatusError as e:
                last_error = e
                # Don't retry client errors (4xx) except 429 (rate limit)
                if 400 <= e.response.status_code < 500 and e.response.status_code != 429:
                    circuit_breaker.record_failure()
                    self._metrics["fetch_failures"] += 1
                    raise
                logger.warning(
                    f"HTTP error {e.response.status_code} fetching JWKS from {url} "
                    f"(attempt {attempt + 1})"
                )
            except httpx.RequestError as e:
                last_error = e
                logger.warning(f"Request error fetching JWKS from {url}: {e} (attempt {attempt + 1})")
            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error fetching JWKS from {url}: {e}")
                circuit_breaker.record_failure()
                self._metrics["fetch_failures"] += 1
                raise

            # Don't sleep after last attempt
            if attempt < self._retry_config.max_retries:
                self._metrics["retries"] += 1
                delay = self._calculate_retry_delay(attempt)
                logger.debug(f"Retrying in {delay:.2f}s...")
                await asyncio.sleep(delay)

        # All retries exhausted
        circuit_breaker.record_failure()
        self._metrics["fetch_failures"] += 1
        raise RetryError(
            f"Failed to fetch JWKS from {url} after {self._retry_config.max_retries + 1} attempts",
            last_error=last_error,
        )

    @property
    def metrics(self) -> dict[str, int]:
        """Get fetcher metrics for observability."""
        return self._metrics.copy()

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
            httpx.HTTPError: If request fails after retries
            RetryError: If all retries exhausted
            ValueError: If response is not valid JWKS
        """
        # Check cache first
        if self._is_cache_valid(issuer):
            jwks, _ = self._cache[issuer]
            self._metrics["cache_hits"] += 1
            logger.debug(f"JWKS cache hit for {issuer}")
            return jwks

        self._metrics["cache_misses"] += 1

        # Fetch from endpoint with retry and circuit breaker
        url = self._get_jwks_url(issuer)
        logger.info(f"Fetching JWKS from {url}")

        jwks = await self._fetch_with_retry(url, issuer)

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
