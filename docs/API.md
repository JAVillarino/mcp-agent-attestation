# MCP Agent Attestation - API Reference

Complete API documentation for the MCP Agent Attestation library.

## Table of Contents

- [Core Classes](#core-classes)
- [MCP Integration](#mcp-integration)
- [Caching](#caching)
- [JWKS Fetching](#jwks-fetching)
- [Resilience Patterns](#resilience-patterns)

---

## Core Classes

### AgentIdentity

Identifies the AI model and its provider.

```python
from attestation import AgentIdentity

identity = AgentIdentity(
    model_family="claude-4",           # Required: Model family
    model_version="claude-sonnet-4",   # Required: Specific version
    provider="anthropic",              # Required: Provider name
    deployment_id="api-prod-us-east",  # Optional: Deployment identifier
)

# Generate SPIFFE ID
spiffe_id = identity.to_spiffe_id()  # spiffe://anthropic.com/model/claude-sonnet-4
```

### AgentIntegrity

Hashes for verifying agent configuration integrity.

```python
from attestation import AgentIntegrity

integrity = AgentIntegrity(
    config_hash=AgentIntegrity.compute_hash('{"temperature": 0.7}'),
    system_prompt_hash=AgentIntegrity.compute_hash("You are a helpful assistant"),
)
```

### AttestationMetadata

Metadata about the attestation itself.

```python
from attestation import AttestationMetadata, AttestationType, SafetyLevel

metadata = AttestationMetadata(
    attestation_version="0.1.0",
    attestation_type=AttestationType.PROVIDER.value,
    safety_level=SafetyLevel.STANDARD.value,
    capabilities_declared=["tool_use", "code_execution"],
)
```

### KeyPair

Ed25519 key pair for signing/verification.

```python
from attestation import KeyPair

# Generate new key pair
keypair = KeyPair.generate(kid="my-key-2025")

# Export as JWK
jwk = keypair.to_jwk()
# {"kty": "OKP", "crv": "Ed25519", "kid": "my-key-2025", "x": "..."}
```

### AttestationProvider

Creates signed attestation tokens.

```python
from attestation import AttestationProvider, KeyPair, AgentIdentity

keypair = KeyPair.generate("provider-key")
provider = AttestationProvider(
    issuer="https://api.anthropic.com",
    keypair=keypair,
    default_lifetime_seconds=300,  # 5 minutes (default)
)

identity = AgentIdentity(
    model_family="claude-4",
    model_version="claude-sonnet-4",
    provider="anthropic",
)

# Create token
token = provider.create_token(
    identity=identity,
    audience="https://my-mcp-server.com",
)
```

### AttestationVerifier

Verifies attestation tokens.

```python
from attestation import (
    AttestationVerifier,
    InMemoryKeyResolver,
    VerificationPolicy,
    TrustLevel,
)

# Setup key resolver
key_resolver = InMemoryKeyResolver()
key_resolver.add_key(
    issuer="https://api.anthropic.com",
    kid="provider-key",
    public_key=keypair.public_key,
)

# Create verifier
verifier = AttestationVerifier(
    trusted_issuers=["https://api.anthropic.com"],
    key_resolver=key_resolver,
    policy=VerificationPolicy.REQUIRED,
    audience="https://my-mcp-server.com",  # Optional: validate audience
)

# Verify token
result = await verifier.verify(token)

if result.verified:
    print(f"Verified: {result.subject}")
    print(f"Trust level: {result.trust_level}")
    print(f"Claims: {result.claims}")
else:
    print(f"Failed: {result.error} (code: {result.error_code})")
```

### VerificationResult

Result of attestation verification.

| Field | Type | Description |
|-------|------|-------------|
| `verified` | `bool` | Whether verification succeeded |
| `trust_level` | `TrustLevel` | PROVIDER, ENTERPRISE, or NONE |
| `issuer` | `str \| None` | Token issuer URL |
| `subject` | `str \| None` | SPIFFE ID of agent |
| `claims` | `AttestationClaims \| None` | Full decoded claims |
| `error` | `str \| None` | Error message if failed |
| `error_code` | `int \| None` | Error code if failed |

### Enums

```python
from attestation import AttestationType, SafetyLevel, VerificationPolicy, TrustLevel

# Attestation issuer type
AttestationType.PROVIDER    # Model provider (Anthropic, OpenAI)
AttestationType.ENTERPRISE  # Enterprise IdP (SPIFFE, Okta)

# Model safety configuration
SafetyLevel.STANDARD  # Default safety settings
SafetyLevel.ENHANCED  # Stricter safety
SafetyLevel.MINIMAL   # Reduced safety (enterprise only)

# Server verification policy
VerificationPolicy.REQUIRED   # Reject without valid attestation
VerificationPolicy.PREFERRED  # Accept but log missing
VerificationPolicy.OPTIONAL   # Accept any connection

# Resulting trust level
TrustLevel.PROVIDER    # Verified by model provider
TrustLevel.ENTERPRISE  # Verified by enterprise IdP
TrustLevel.NONE        # No verification
```

---

## MCP Integration

### AttestingClientSession

MCP ClientSession with automatic attestation injection.

```python
from mcp.client.stdio import stdio_client
from attestation import AttestationProvider, AgentIdentity, KeyPair
from attestation.mcp_client import AttestingClientSession

keypair = KeyPair.generate("my-key")
provider = AttestationProvider(issuer="https://api.anthropic.com", keypair=keypair)
identity = AgentIdentity(model_family="claude-4", model_version="claude-sonnet-4", provider="anthropic")

async with stdio_client(server_params) as (read, write):
    session = AttestingClientSession(
        read_stream=read,
        write_stream=write,
        attestation_provider=provider,
        agent_identity=identity,
        target_audience="https://my-mcp-server.com",
    )
    result = await session.initialize()

    # Check attestation status
    if session.attestation_verified:
        print(f"Trust level: {session.attestation_status['trust_level']}")
```

### AttestingServer

MCP Server with attestation verification.

```python
from attestation import AttestationVerifier, InMemoryKeyResolver, VerificationPolicy, TrustLevel
from attestation.mcp_server import create_attesting_server

key_resolver = InMemoryKeyResolver()
key_resolver.add_keypair("https://api.anthropic.com", trusted_keypair)

verifier = AttestationVerifier(
    trusted_issuers=["https://api.anthropic.com"],
    key_resolver=key_resolver,
    policy=VerificationPolicy.REQUIRED,
)

server = create_attesting_server("my-server", verifier, version="1.0.0")

@server.list_tools()
async def list_tools():
    return [...]

# Protect specific tools with trust level requirement
@server.call_tool()
@server.require_attestation(trust_level=TrustLevel.PROVIDER)
async def call_tool(name, arguments):
    return [...]
```

### Helper Function

```python
from attestation.mcp_client import create_attesting_session

# One-liner to create session and initialize
session, result = await create_attesting_session(
    read_stream=read,
    write_stream=write,
    attestation_provider=provider,
    agent_identity=identity,
    target_audience="https://server.com",
)
```

---

## Caching

### InMemoryReplayCache

Single-server replay protection cache.

```python
from attestation import InMemoryReplayCache

cache = InMemoryReplayCache()

# Check if JTI is new (returns True) or replay (returns False)
is_new = await cache.check_and_add(jti="token-id-123", exp=1735000000)

# Other operations
exists = await cache.exists("token-id-123")
count = await cache.count()
await cache.clear()
```

### RedisReplayCache

Distributed replay protection for multi-server deployments.

```python
from attestation import RedisReplayCache, RedisConfig, CacheState

# Configuration
config = RedisConfig(
    url="redis://localhost:6379",
    key_prefix="mcp_attestation:jti:",
    connection_timeout=5.0,
    socket_timeout=2.0,
    max_retries=3,
    retry_delay=0.5,
    health_check_interval=30.0,
    fallback_enabled=True,  # Fall back to in-memory on Redis failure
    pool_size=10,
)

# Usage with context manager
async with RedisReplayCache(config=config) as cache:
    is_new = await cache.check_and_add("jti", exp_timestamp)

# Manual lifecycle
cache = RedisReplayCache(config=config)
await cache.connect()
try:
    is_new = await cache.check_and_add("jti", exp_timestamp)
finally:
    await cache.close()

# Health monitoring
status = cache.get_health_status()
# {
#     "state": "healthy",
#     "using_fallback": False,
#     "redis_connected": True,
#     "metrics": {...}
# }

# Metrics
metrics = cache.metrics
# CacheMetrics(checks=100, hits=5, misses=95, replays_detected=5, ...)
```

### CacheState

```python
from attestation import CacheState

CacheState.HEALTHY    # Redis connected, operating normally
CacheState.DEGRADED   # Fallback active, Redis unavailable
CacheState.UNHEALTHY  # Completely unavailable
```

---

## JWKS Fetching

### JWKSFetcher

Fetches and caches JWKS from issuer endpoints.

```python
from attestation import JWKSFetcher, RetryConfig, CircuitBreakerConfig

fetcher = JWKSFetcher(
    cache_ttl_seconds=3600,      # Cache for 1 hour
    request_timeout_seconds=10.0,
    retry_config=RetryConfig(max_retries=3),
    circuit_breaker_config=CircuitBreakerConfig(failure_threshold=5),
    connection_pool_size=10,
)

# Fetch JWKS
jwks = await fetcher.get_jwks("https://api.anthropic.com")
# {"keys": [{"kty": "OKP", "crv": "Ed25519", ...}]}

# Get specific key
key = await fetcher.get_key("https://api.anthropic.com", "key-id-123")

# Metrics
metrics = fetcher.metrics
# {"cache_hits": 10, "cache_misses": 2, "fetch_success": 2, ...}

# Cache management
fetcher.invalidate("https://api.anthropic.com")  # Invalidate single issuer
fetcher.clear_cache()  # Clear all

# Cleanup
await fetcher.close()
```

### HTTPKeyResolver

Production key resolver using JWKS endpoints.

```python
from attestation import HTTPKeyResolver

resolver = HTTPKeyResolver(cache_ttl_seconds=3600)

key = await resolver.get_key("https://api.anthropic.com", "key-id-123")
```

---

## Resilience Patterns

### CircuitBreaker

Protects against cascading failures.

```python
from attestation import CircuitBreaker, CircuitBreakerConfig, CircuitState

config = CircuitBreakerConfig(
    failure_threshold=5,      # Open after 5 failures
    recovery_timeout=30.0,    # Try again after 30 seconds
    half_open_max_calls=1,    # Allow 1 test call in half-open
)

cb = CircuitBreaker(config)

# Check if request can proceed
if cb.can_execute():
    try:
        result = await make_request()
        cb.record_success()
    except Exception:
        cb.record_failure()
else:
    # Circuit is open, fail fast
    raise CircuitOpenError()

# States
cb.state  # CircuitState.CLOSED, OPEN, or HALF_OPEN

# Reset
cb.reset()
```

### RetryConfig

Configuration for exponential backoff retry logic.

```python
from attestation import RetryConfig

config = RetryConfig(
    max_retries=3,
    base_delay=0.5,        # Initial delay in seconds
    max_delay=10.0,        # Maximum delay cap
    exponential_base=2.0,  # Multiplier per retry
    jitter=True,           # Add randomness to prevent thundering herd
)
```

### RetryError

Raised when all retries are exhausted.

```python
from attestation import RetryError

try:
    await fetcher.get_jwks(issuer)
except RetryError as e:
    print(f"Failed after retries: {e}")
    print(f"Last error: {e.last_error}")
```

---

## Constants

```python
from attestation import ATTESTATION_VERSION, ATTESTATION_CAPABILITY_KEY

ATTESTATION_VERSION      # "0.1.0"
ATTESTATION_CAPABILITY_KEY  # "security.attestation"
```

## Feature Detection

```python
from attestation import REDIS_AVAILABLE, MCP_AVAILABLE

if REDIS_AVAILABLE:
    from attestation import RedisReplayCache

if MCP_AVAILABLE:
    from attestation import AttestingClientSession, AttestingServer
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 1001 | Token expired |
| 1002 | Token not yet valid |
| 1003 | Invalid signature |
| 1004 | Unknown issuer |
| 1005 | Invalid audience |
| 1006 | Replay detected |
| 1007 | Missing required claims |
| 1008 | Malformed token |

---

## Complete Example

```python
import asyncio
from attestation import (
    KeyPair,
    AgentIdentity,
    AttestationProvider,
    AttestationVerifier,
    InMemoryKeyResolver,
    VerificationPolicy,
)

async def main():
    # === Provider Side ===
    keypair = KeyPair.generate("anthropic-2025-01")
    provider = AttestationProvider(
        issuer="https://api.anthropic.com",
        keypair=keypair,
    )

    identity = AgentIdentity(
        model_family="claude-4",
        model_version="claude-sonnet-4-20250514",
        provider="anthropic",
    )

    token = provider.create_token(
        identity=identity,
        audience="https://my-mcp-server.com",
    )

    # === Server Side ===
    key_resolver = InMemoryKeyResolver()
    key_resolver.add_key(
        "https://api.anthropic.com",
        keypair.kid,
        keypair.public_key,
    )

    verifier = AttestationVerifier(
        trusted_issuers=["https://api.anthropic.com"],
        key_resolver=key_resolver,
        policy=VerificationPolicy.REQUIRED,
        audience="https://my-mcp-server.com",
    )

    result = await verifier.verify(token)

    if result.verified:
        print(f"✓ Verified agent: {result.subject}")
        print(f"  Trust level: {result.trust_level.value}")
        print(f"  Model: {result.claims.agent_identity.model_version}")
    else:
        print(f"✗ Verification failed: {result.error}")

asyncio.run(main())
```
