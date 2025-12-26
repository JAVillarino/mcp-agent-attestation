# MCP Agent Attestation - Implementation Plan

## Overview

This document outlines the detailed implementation plan for integrating the attestation system with the MCP SDK. Based on deep analysis of the MCP SDK source code, this plan identifies exact integration points, challenges, and implementation strategies.

---

## MCP SDK Analysis

### Key Classes and Integration Points

#### 1. ClientSession (`mcp/client/session.py`)

**Current Behavior:**
```python
# Line 148-197
async def initialize(self) -> types.InitializeResult:
    result = await self.send_request(
        types.ClientRequest(
            types.InitializeRequest(
                params=types.InitializeRequestParams(
                    protocolVersion=types.LATEST_PROTOCOL_VERSION,
                    capabilities=types.ClientCapabilities(
                        sampling=sampling,
                        elicitation=elicitation,
                        experimental=None,  # <-- ALWAYS None!
                        roots=roots,
                        tasks=self._task_handlers.build_capability(),
                    ),
                    clientInfo=self._client_info,
                ),
            )
        ),
        types.InitializeResult,
    )
    # ...
```

**Problem:** The `experimental` field is hardcoded to `None`. There's no way to inject attestation without modifying the SDK or subclassing.

**Integration Point:** Override `initialize()` to inject attestation token.

---

#### 2. ServerSession (`mcp/server/session.py`)

**Current Behavior:**
```python
# Line 163-187
async def _received_request(self, responder: RequestResponder[...]):
    match responder.request.root:
        case types.InitializeRequest(params=params):
            self._initialization_state = InitializationState.Initializing
            self._client_params = params  # <-- Client capabilities stored here
            with responder:
                await responder.respond(
                    types.ServerResult(
                        types.InitializeResult(
                            protocolVersion=...,
                            capabilities=self._init_options.capabilities,
                            serverInfo=...,
                        )
                    )
                )
            self._initialization_state = InitializationState.Initialized
```

**Available After Init:**
- `session._client_params.capabilities.experimental` - The attestation token location
- `session.check_client_capability()` - Can verify experimental capabilities

**Integration Point:** Access `client_params` after initialization to verify token.

---

#### 3. Low-Level Server (`mcp/server/lowlevel/server.py`)

**Current Behavior:**
```python
# Line 633-676
async def run(self, read_stream, write_stream, initialization_options, ...):
    async with AsyncExitStack() as stack:
        lifespan_context = await stack.enter_async_context(self.lifespan(self))
        session = await stack.enter_async_context(
            ServerSession(read_stream, write_stream, initialization_options, ...)
        )
        # ... message handling loop
```

**Key Methods:**
- `get_capabilities(notification_options, experimental_capabilities)` - Declares server capabilities
- `lifespan` context manager - Runs before/after server loop
- `_handle_request()` - Processes each request

**Integration Points:**
1. `experimental_capabilities` dict in `get_capabilities()`
2. Custom lifespan for post-init verification
3. Request handler wrapper for per-request checks

---

## Implementation Strategy

### Phase 1: Client-Side Integration

#### Option A: Subclass ClientSession (Recommended)

```python
class AttestingClientSession(ClientSession):
    """ClientSession with attestation support."""

    def __init__(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        attestation_provider: AttestationProvider,
        agent_identity: AgentIdentity,
        target_audience: str,
        **kwargs
    ):
        super().__init__(read_stream, write_stream, **kwargs)
        self._attestation_provider = attestation_provider
        self._agent_identity = agent_identity
        self._target_audience = target_audience

    async def initialize(self) -> types.InitializeResult:
        """Initialize with attestation token injected."""
        # Create attestation token
        token = self._attestation_provider.create_token(
            identity=self._agent_identity,
            audience=self._target_audience,
        )

        # Build capabilities with attestation
        sampling = self._build_sampling_capability()
        elicitation = self._build_elicitation_capability()
        roots = self._build_roots_capability()

        experimental = {
            "security.attestation": {
                "version": "0.1.0",
                "token": token,
                "supported_algorithms": ["EdDSA"],
                "attestation_types": ["provider", "enterprise"],
            }
        }

        result = await self.send_request(
            types.ClientRequest(
                types.InitializeRequest(
                    params=types.InitializeRequestParams(
                        protocolVersion=types.LATEST_PROTOCOL_VERSION,
                        capabilities=types.ClientCapabilities(
                            sampling=sampling,
                            elicitation=elicitation,
                            experimental=experimental,  # Attestation injected!
                            roots=roots,
                            tasks=self._task_handlers.build_capability(),
                        ),
                        clientInfo=self._client_info,
                    ),
                )
            ),
            types.InitializeResult,
        )

        if result.protocolVersion not in SUPPORTED_PROTOCOL_VERSIONS:
            raise RuntimeError(f"Unsupported protocol version: {result.protocolVersion}")

        self._server_capabilities = result.capabilities
        await self.send_notification(types.ClientNotification(types.InitializedNotification()))

        return result
```

**Complexity:** Medium
**Pros:** Clean, type-safe, follows SDK patterns
**Cons:** Duplicates some SDK code, may break with SDK updates

#### Option B: Wrapper Function (Alternative)

```python
async def create_attesting_client(
    read_stream,
    write_stream,
    attestation_provider: AttestationProvider,
    agent_identity: AgentIdentity,
    target_audience: str,
    **session_kwargs
) -> tuple[ClientSession, types.InitializeResult]:
    """Create a client session with attestation."""
    session = ClientSession(read_stream, write_stream, **session_kwargs)

    # Monkey-patch the experimental capabilities before init
    # This is fragile but avoids subclassing
    original_initialize = session.initialize

    async def patched_initialize():
        # We need to completely replace initialize() logic
        # because experimental is hardcoded
        ...

    session.initialize = patched_initialize
    result = await session.initialize()

    return session, result
```

**Complexity:** Low
**Pros:** No subclassing, less code
**Cons:** Fragile, monkey-patching is not type-safe

---

### Phase 2: Server-Side Integration

#### Option A: Attestation-Aware Server Wrapper

```python
class AttestingServer:
    """Wrapper around MCP Server with attestation verification."""

    def __init__(
        self,
        server: Server,
        verifier: AttestationVerifier,
        policy: VerificationPolicy = VerificationPolicy.REQUIRED,
    ):
        self.server = server
        self.verifier = verifier
        self.policy = policy
        self._attestation_contexts: dict[int, AttestationContext] = {}

    def get_capabilities(
        self,
        notification_options: NotificationOptions,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> types.ServerCapabilities:
        """Add attestation requirements to capabilities."""
        exp_caps = experimental_capabilities or {}
        exp_caps["security.attestation"] = {
            "version": "0.1.0",
            "policy": self.policy.value,
            "trusted_issuers": self.verifier.trusted_issuers,
            "required_claims": self.verifier.required_claims,
        }
        return self.server.get_capabilities(notification_options, exp_caps)

    async def run(self, read_stream, write_stream, init_options, **kwargs):
        """Run with attestation verification on init."""
        # Use custom lifespan that verifies attestation
        original_lifespan = self.server.lifespan

        @asynccontextmanager
        async def attesting_lifespan(server):
            async with original_lifespan(server) as ctx:
                # After init, verify attestation
                # Note: We need access to session here - this is tricky
                yield ctx

        self.server.lifespan = attesting_lifespan
        await self.server.run(read_stream, write_stream, init_options, **kwargs)
```

**Problem:** The lifespan runs before `ServerSession` is available, so we can't verify the token there.

#### Option B: Custom ServerSession Subclass (Better)

```python
class AttestingServerSession(ServerSession):
    """ServerSession with attestation verification."""

    def __init__(
        self,
        read_stream,
        write_stream,
        init_options: InitializationOptions,
        verifier: AttestationVerifier,
        **kwargs
    ):
        super().__init__(read_stream, write_stream, init_options, **kwargs)
        self._verifier = verifier
        self._attestation_context: AttestationContext | None = None

    async def _received_request(self, responder: RequestResponder[...]):
        """Override to verify attestation on init."""
        match responder.request.root:
            case types.InitializeRequest(params=params):
                # Verify attestation BEFORE responding
                token = self._extract_attestation_token(params)
                verification = await self._verifier.verify(token)

                if not verification.verified and self._verifier.policy == VerificationPolicy.REQUIRED:
                    # Reject connection
                    with responder:
                        await responder.respond(
                            types.ErrorData(
                                code=-32001,
                                message="attestation_required",
                                data={"policy": "required"},
                            )
                        )
                    return

                # Store attestation context
                self._attestation_context = AttestationContext.from_verification_result(verification)

                # Proceed with normal init
                await super()._received_request(responder)
            case _:
                await super()._received_request(responder)

    def _extract_attestation_token(self, params: types.InitializeRequestParams) -> str | None:
        """Extract token from capabilities."""
        try:
            return params.capabilities.experimental.get("security.attestation", {}).get("token")
        except (AttributeError, TypeError):
            return None

    @property
    def attestation(self) -> AttestationContext | None:
        """Get attestation context for this session."""
        return self._attestation_context
```

**Complexity:** Medium-High
**Pros:** Clean integration, proper error handling, context available throughout session
**Cons:** Requires modifying how Server creates sessions

#### Option C: Post-Init Verification Hook (Simplest)

```python
def create_attesting_server(
    name: str,
    verifier: AttestationVerifier,
    **server_kwargs
) -> Server:
    """Create a server with attestation verification."""
    server = Server(name, **server_kwargs)

    # Register a custom handler that verifies attestation
    @server.call_tool()
    async def call_tool_with_attestation(name: str, arguments: dict) -> ...:
        ctx = server.request_context
        session = ctx.session

        # Verify attestation from stored client params
        if session.client_params:
            token = session.client_params.capabilities.experimental.get(
                "security.attestation", {}
            ).get("token")

            result = await verifier.verify(token)
            if not result.verified and verifier.policy == VerificationPolicy.REQUIRED:
                raise PermissionError("Attestation required")

        # Proceed with actual tool call
        ...
```

**Complexity:** Low
**Pros:** Works with existing SDK, no subclassing
**Cons:** Verification happens per-request (inefficient), no way to reject during init

---

## Recommended Implementation Path

### Step 1: JWKS HTTP Fetcher (Prerequisite)

```python
# src/attestation/jwks.py

import httpx
from typing import Any
import asyncio

class JWKSFetcher:
    """Fetches and caches JWKS from issuer endpoints."""

    def __init__(self, cache_ttl_seconds: int = 3600):
        self._cache: dict[str, tuple[dict, float]] = {}
        self._cache_ttl = cache_ttl_seconds
        self._client: httpx.AsyncClient | None = None

    async def get_jwks(self, issuer: str) -> dict[str, Any]:
        """Fetch JWKS from issuer's well-known endpoint."""
        # Check cache
        if issuer in self._cache:
            jwks, cached_at = self._cache[issuer]
            if time.time() - cached_at < self._cache_ttl:
                return jwks

        # Fetch from endpoint
        url = f"{issuer.rstrip('/')}/.well-known/jwks.json"
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()
            jwks = response.json()

        # Cache
        self._cache[issuer] = (jwks, time.time())
        return jwks

    async def get_key(self, issuer: str, kid: str) -> Any:
        """Get specific key from JWKS."""
        jwks = await self.get_jwks(issuer)
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return self._parse_ed25519_key(key)
        return None

    def _parse_ed25519_key(self, jwk: dict) -> Any:
        """Parse JWK to Ed25519 public key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64

        x = jwk["x"]
        # Add padding
        x += "=" * (4 - len(x) % 4) if len(x) % 4 else ""
        key_bytes = base64.urlsafe_b64decode(x)
        return Ed25519PublicKey.from_public_bytes(key_bytes)


class HTTPKeyResolver:
    """KeyResolver that fetches keys via HTTP."""

    def __init__(self, fetcher: JWKSFetcher | None = None):
        self._fetcher = fetcher or JWKSFetcher()

    async def get_key(self, issuer: str, kid: str) -> Any | None:
        try:
            return await self._fetcher.get_key(issuer, kid)
        except Exception as e:
            logger.warning(f"Failed to fetch key {kid} from {issuer}: {e}")
            return None
```

**Effort:** ~1-2 hours
**Dependencies:** httpx

---

### Step 2: Client Integration Module

```python
# src/attestation/mcp_client.py

from mcp.client.session import ClientSession
from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS
import mcp.types as types

from .core import AttestationProvider, AgentIdentity, AgentIntegrity, AttestationMetadata
from .protocol import ATTESTATION_CAPABILITY_KEY

class AttestingClientSession(ClientSession):
    """MCP ClientSession with attestation support."""

    def __init__(
        self,
        read_stream,
        write_stream,
        attestation_provider: AttestationProvider,
        agent_identity: AgentIdentity,
        target_audience: str,
        agent_integrity: AgentIntegrity | None = None,
        attestation_metadata: AttestationMetadata | None = None,
        **kwargs
    ):
        super().__init__(read_stream, write_stream, **kwargs)
        self._attestation_provider = attestation_provider
        self._agent_identity = agent_identity
        self._target_audience = target_audience
        self._agent_integrity = agent_integrity
        self._attestation_metadata = attestation_metadata or AttestationMetadata()

    def _create_attestation_token(self) -> str:
        """Create attestation token for the target server."""
        return self._attestation_provider.create_token(
            identity=self._agent_identity,
            audience=self._target_audience,
            integrity=self._agent_integrity,
            metadata=self._attestation_metadata,
        )

    def _build_attestation_capability(self) -> dict:
        """Build attestation capability dict."""
        return {
            "version": "0.1.0",
            "token": self._create_attestation_token(),
            "supported_algorithms": ["EdDSA"],
            "attestation_types": ["provider", "enterprise"],
        }

    async def initialize(self) -> types.InitializeResult:
        """Initialize session with attestation."""
        # Build standard capabilities
        sampling = (
            (self._sampling_capabilities or types.SamplingCapability())
            if self._sampling_callback is not self._default_sampling_callback
            else None
        )
        elicitation = (
            types.ElicitationCapability(
                form=types.FormElicitationCapability(),
                url=types.UrlElicitationCapability(),
            )
            if self._elicitation_callback is not self._default_elicitation_callback
            else None
        )
        roots = (
            types.RootsCapability(listChanged=True)
            if self._list_roots_callback is not self._default_list_roots_callback
            else None
        )

        # Build experimental with attestation
        experimental = {
            ATTESTATION_CAPABILITY_KEY: self._build_attestation_capability()
        }

        # Send initialize request
        result = await self.send_request(
            types.ClientRequest(
                types.InitializeRequest(
                    params=types.InitializeRequestParams(
                        protocolVersion=types.LATEST_PROTOCOL_VERSION,
                        capabilities=types.ClientCapabilities(
                            sampling=sampling,
                            elicitation=elicitation,
                            experimental=experimental,
                            roots=roots,
                            tasks=self._task_handlers.build_capability(),
                        ),
                        clientInfo=self._client_info,
                    ),
                )
            ),
            types.InitializeResult,
        )

        if result.protocolVersion not in SUPPORTED_PROTOCOL_VERSIONS:
            raise RuntimeError(f"Unsupported protocol version: {result.protocolVersion}")

        self._server_capabilities = result.capabilities

        # Check attestation verification status in response
        self._check_attestation_response(result)

        await self.send_notification(
            types.ClientNotification(types.InitializedNotification())
        )

        return result

    def _check_attestation_response(self, result: types.InitializeResult):
        """Check server's attestation verification response."""
        if result.capabilities and result.capabilities.experimental:
            attestation_response = result.capabilities.experimental.get(
                ATTESTATION_CAPABILITY_KEY, {}
            )
            status = attestation_response.get("verification_status")
            if status == "failed":
                error = attestation_response.get("error", "Unknown error")
                raise RuntimeError(f"Attestation verification failed: {error}")
```

**Effort:** ~2-3 hours
**Dependencies:** MCP SDK

---

### Step 3: Server Integration Module

```python
# src/attestation/mcp_server.py

from contextlib import asynccontextmanager
from typing import Any, Callable, Awaitable
import logging

from mcp.server.lowlevel.server import Server, NotificationOptions
from mcp.server.session import ServerSession
from mcp.server.models import InitializationOptions
from mcp.shared.context import RequestContext
import mcp.types as types

from .core import AttestationVerifier, VerificationPolicy, TrustLevel
from .protocol import AttestationContext, ATTESTATION_CAPABILITY_KEY

logger = logging.getLogger(__name__)


def create_attesting_server(
    name: str,
    verifier: AttestationVerifier,
    version: str | None = None,
    instructions: str | None = None,
    **server_kwargs
) -> "AttestingMCPServer":
    """Create an MCP server with attestation verification."""
    return AttestingMCPServer(
        name=name,
        verifier=verifier,
        version=version,
        instructions=instructions,
        **server_kwargs
    )


class AttestingMCPServer:
    """MCP Server wrapper with attestation support."""

    def __init__(
        self,
        name: str,
        verifier: AttestationVerifier,
        version: str | None = None,
        instructions: str | None = None,
        **server_kwargs
    ):
        self._server = Server(name, version=version, instructions=instructions, **server_kwargs)
        self._verifier = verifier
        self._session_contexts: dict[int, AttestationContext] = {}

    @property
    def server(self) -> Server:
        """Access underlying Server for registering handlers."""
        return self._server

    def get_capabilities(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> types.ServerCapabilities:
        """Get capabilities with attestation requirements."""
        exp_caps = experimental_capabilities or {}
        exp_caps[ATTESTATION_CAPABILITY_KEY] = {
            "version": "0.1.0",
            "policy": self._verifier.policy.value,
            "trusted_issuers": self._verifier.trusted_issuers,
            "required_claims": self._verifier.required_claims,
        }
        return self._server.get_capabilities(
            notification_options or NotificationOptions(),
            exp_caps
        )

    def create_initialization_options(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        """Create init options with attestation requirements."""
        exp_caps = experimental_capabilities or {}
        exp_caps[ATTESTATION_CAPABILITY_KEY] = {
            "version": "0.1.0",
            "policy": self._verifier.policy.value,
            "trusted_issuers": self._verifier.trusted_issuers,
            "required_claims": self._verifier.required_claims,
        }
        return self._server.create_initialization_options(
            notification_options,
            exp_caps
        )

    async def verify_session_attestation(self, session: ServerSession) -> AttestationContext:
        """Verify attestation for a session after initialization."""
        token = None
        if session.client_params and session.client_params.capabilities.experimental:
            token = session.client_params.capabilities.experimental.get(
                ATTESTATION_CAPABILITY_KEY, {}
            ).get("token")

        result = await self._verifier.verify(token)
        context = AttestationContext.from_verification_result(result)

        # Store context keyed by session id
        self._session_contexts[id(session)] = context

        if not result.verified:
            if self._verifier.policy == VerificationPolicy.REQUIRED:
                raise PermissionError(f"Attestation required: {result.error}")
            elif self._verifier.policy == VerificationPolicy.PREFERRED:
                logger.warning(f"Attestation failed (preferred): {result.error}")

        return context

    def get_attestation_context(self, session: ServerSession) -> AttestationContext | None:
        """Get attestation context for a session."""
        return self._session_contexts.get(id(session))

    def require_attestation(
        self,
        trust_level: TrustLevel | None = None,
        issuer: str | None = None,
    ):
        """Decorator to require attestation for a tool/handler."""
        def decorator(func: Callable[..., Awaitable[Any]]):
            async def wrapper(*args, **kwargs):
                ctx = self._server.request_context
                attestation = self.get_attestation_context(ctx.session)

                if attestation is None or not attestation.verified:
                    raise PermissionError("Attestation required but not verified")

                if trust_level and attestation.trust_level.value < trust_level.value:
                    raise PermissionError(f"Insufficient trust level: {attestation.trust_level}")

                if issuer and attestation.issuer != issuer:
                    raise PermissionError(f"Required issuer: {issuer}")

                return await func(*args, **kwargs)

            wrapper.__name__ = func.__name__
            wrapper.__doc__ = func.__doc__
            return wrapper
        return decorator

    # Delegate common decorators to underlying server
    def list_tools(self):
        return self._server.list_tools()

    def call_tool(self, **kwargs):
        return self._server.call_tool(**kwargs)

    def list_resources(self):
        return self._server.list_resources()

    def read_resource(self):
        return self._server.read_resource()

    def list_prompts(self):
        return self._server.list_prompts()

    def get_prompt(self):
        return self._server.get_prompt()


# Lifespan helper for attestation verification
@asynccontextmanager
async def attesting_lifespan(
    server: AttestingMCPServer,
    session: ServerSession,
):
    """Lifespan that verifies attestation after init."""
    # Verify attestation
    await server.verify_session_attestation(session)
    yield {}
```

**Effort:** ~3-4 hours
**Dependencies:** MCP SDK

---

### Step 4: Redis Replay Cache (Production)

```python
# src/attestation/cache.py

import redis.asyncio as redis
from typing import Optional

class RedisReplayCache:
    """Distributed replay cache using Redis."""

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        key_prefix: str = "mcp_attestation:jti:",
    ):
        self._redis_url = redis_url
        self._key_prefix = key_prefix
        self._client: Optional[redis.Redis] = None

    async def connect(self):
        """Connect to Redis."""
        self._client = redis.from_url(self._redis_url)

    async def close(self):
        """Close Redis connection."""
        if self._client:
            await self._client.close()

    async def check_and_add(self, jti: str, exp: int) -> bool:
        """Check if JTI is new and add to cache."""
        if not self._client:
            raise RuntimeError("Not connected to Redis")

        key = f"{self._key_prefix}{jti}"

        # Use SETNX for atomic check-and-set
        was_set = await self._client.setnx(key, "1")

        if was_set:
            # Set expiration
            import time
            ttl = max(1, exp - int(time.time()))
            await self._client.expire(key, ttl)
            return True
        else:
            return False  # Replay detected

    async def clear(self):
        """Clear all cached tokens (for testing)."""
        if self._client:
            keys = await self._client.keys(f"{self._key_prefix}*")
            if keys:
                await self._client.delete(*keys)
```

**Effort:** ~1-2 hours
**Dependencies:** redis-py

---

## Implementation Timeline Estimates

| Phase | Component | Effort | Dependencies |
|-------|-----------|--------|--------------|
| 1 | JWKS HTTP Fetcher | 1-2 hours | httpx |
| 2 | Client Integration | 2-3 hours | MCP SDK, Phase 1 |
| 3 | Server Integration | 3-4 hours | MCP SDK, Phase 1 |
| 4 | Redis Replay Cache | 1-2 hours | redis-py |
| 5 | Integration Tests | 2-3 hours | All above |
| 6 | Documentation | 1-2 hours | - |

**Total Estimated Effort:** 10-16 hours

---

## Challenges and Mitigations

### Challenge 1: SDK Hardcoded Experimental = None

**Problem:** `ClientSession.initialize()` sets `experimental=None`.

**Mitigation:** Subclass `ClientSession` and override `initialize()`. This duplicates some SDK code but is the cleanest approach.

**Risk:** SDK updates may break our subclass.

**Alternative:** Contribute upstream to make `experimental` configurable.

---

### Challenge 2: No Server Middleware Hook

**Problem:** There's no official way to run code after `InitializeRequest` but before responding.

**Mitigation:**
1. Subclass `ServerSession` and override `_received_request()`
2. Or verify attestation after init in the lifespan/first request

**Risk:** Verification after init means the connection is already established.

---

### Challenge 3: Session Context Storage

**Problem:** Need to store `AttestationContext` per session for later access.

**Mitigation:** Use session ID as key in a dict, or add attribute to session.

**Risk:** Memory leaks if sessions aren't cleaned up properly.

---

### Challenge 4: Token Refresh

**Problem:** Tokens expire after 5 minutes, but MCP sessions can be long-lived.

**Mitigation:**
1. For short sessions: No action needed
2. For long sessions: Re-initialize connection (disconnect/reconnect)
3. Future: Add token refresh protocol extension

---

## Testing Strategy

### Unit Tests
- JWKS fetcher with mocked HTTP
- Client session attestation injection
- Server session attestation verification
- Redis cache operations

### Integration Tests
- Full client-server handshake with attestation
- Policy enforcement (required/preferred/optional)
- Attack scenarios (replay, tampering, etc.)

### End-to-End Tests
- Real MCP server with attestation
- Multiple concurrent connections
- Token expiration handling

---

## Files to Create

```
src/attestation/
├── __init__.py          # Update exports
├── core.py              # Existing
├── protocol.py          # Existing
├── attacks.py           # Existing
├── jwks.py              # NEW: JWKS HTTP fetcher
├── mcp_client.py        # NEW: Client integration
├── mcp_server.py        # NEW: Server integration
└── cache.py             # NEW: Redis cache

tests/
├── test_attestation.py  # Existing
├── test_jwks.py         # NEW
├── test_mcp_client.py   # NEW
├── test_mcp_server.py   # NEW
└── test_integration.py  # NEW
```

---

## Next Steps

1. **Implement JWKS Fetcher** - Prerequisite for production key resolution
2. **Implement Client Integration** - `AttestingClientSession` class
3. **Implement Server Integration** - `AttestingMCPServer` wrapper
4. **Add Redis Cache** - For production replay protection
5. **Integration Tests** - End-to-end testing
6. **Documentation** - Usage examples and API docs

---

## Questions for Review

1. **Should we contribute to MCP SDK?** Making `experimental` configurable would simplify client integration.

2. **How to handle long-lived sessions?** Token refresh vs. reconnection.

3. **Redis vs. other distributed caches?** Memcached, DynamoDB, etc.

4. **Error handling strategy?** How should servers behave when attestation fails?

5. **Backwards compatibility?** Should servers accept unattested connections during rollout?
