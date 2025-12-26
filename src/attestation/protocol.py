"""
MCP Agent Attestation - Protocol Extension

This module extends the MCP protocol with attestation capabilities,
integrating with the ClientSession and ServerSession initialization flow.

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from .core import (
    ATTESTATION_CAPABILITY_KEY,
    ATTESTATION_VERSION,
    AgentIdentity,
    AgentIntegrity,
    AttestationClaims,
    AttestationMetadata,
    AttestationProvider,
    AttestationVerifier,
    TrustLevel,
    VerificationPolicy,
    VerificationResult,
)

# =============================================================================
# CAPABILITY DECLARATIONS
# =============================================================================

@dataclass
class ClientAttestationCapability:
    """
    Client's attestation capability declaration.
    
    Included in initialize request under:
    capabilities.experimental.security.attestation
    """
    version: str = ATTESTATION_VERSION
    token: str | None = None  # The actual attestation JWT
    supported_algorithms: list[str] = field(default_factory=lambda: ["EdDSA"])
    attestation_types: list[str] = field(default_factory=lambda: ["provider", "enterprise"])

    def to_dict(self) -> dict[str, Any]:
        result = {
            "version": self.version,
            "supported_algorithms": self.supported_algorithms,
            "attestation_types": self.attestation_types,
        }
        if self.token:
            result["token"] = self.token
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClientAttestationCapability:
        return cls(
            version=data.get("version", ATTESTATION_VERSION),
            token=data.get("token"),
            supported_algorithms=data.get("supported_algorithms", ["EdDSA"]),
            attestation_types=data.get("attestation_types", ["provider", "enterprise"]),
        )


@dataclass
class ServerAttestationCapability:
    """
    Server's attestation capability declaration.
    
    Included in initialize response under:
    capabilities.experimental.security.attestation
    """
    version: str = ATTESTATION_VERSION
    policy: str = VerificationPolicy.REQUIRED.value
    trusted_issuers: list[str] = field(default_factory=list)
    required_claims: list[str] = field(default_factory=lambda: ["agent_identity", "attestation_metadata"])

    # Response fields (set after verification)
    verification_status: str | None = None  # "verified" | "failed" | "not_provided"
    trust_level: str | None = None
    verified_claims: list[str] | None = None
    error: str | None = None
    error_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "version": self.version,
            "policy": self.policy,
        }
        if self.trusted_issuers:
            result["trusted_issuers"] = self.trusted_issuers
        if self.required_claims:
            result["required_claims"] = self.required_claims

        # Include response fields if set
        if self.verification_status:
            result["verification_status"] = self.verification_status
        if self.trust_level:
            result["trust_level"] = self.trust_level
        if self.verified_claims:
            result["verified_claims"] = self.verified_claims
        if self.error:
            result["error"] = self.error
        if self.error_code:
            result["error_code"] = self.error_code

        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServerAttestationCapability:
        return cls(
            version=data.get("version", ATTESTATION_VERSION),
            policy=data.get("policy", VerificationPolicy.REQUIRED.value),
            trusted_issuers=data.get("trusted_issuers", []),
            required_claims=data.get("required_claims", ["agent_identity", "attestation_metadata"]),
            verification_status=data.get("verification_status"),
            trust_level=data.get("trust_level"),
            verified_claims=data.get("verified_claims"),
            error=data.get("error"),
            error_code=data.get("error_code"),
        )

    def with_verification_result(self, result: VerificationResult) -> ServerAttestationCapability:
        """Create a copy with verification result fields populated."""
        return ServerAttestationCapability(
            version=self.version,
            policy=self.policy,
            trusted_issuers=self.trusted_issuers,
            required_claims=self.required_claims,
            verification_status="verified" if result.verified else "failed",
            trust_level=result.trust_level.value if result.verified else None,
            verified_claims=result.verified_claims if result.verified else None,
            error=result.error if not result.verified else None,
            error_code=result.error_code if not result.verified else None,
        )


# =============================================================================
# SESSION CONTEXT
# =============================================================================

@dataclass
class AttestationContext:
    """
    Attestation state stored in session context after verification.
    """
    verified: bool
    trust_level: TrustLevel
    claims: AttestationClaims | None = None
    issuer: str | None = None
    subject: str | None = None

    @classmethod
    def from_verification_result(cls, result: VerificationResult) -> AttestationContext:
        return cls(
            verified=result.verified,
            trust_level=result.trust_level,
            claims=result.claims,
            issuer=result.issuer,
            subject=result.subject,
        )

    @classmethod
    def unverified(cls) -> AttestationContext:
        return cls(verified=False, trust_level=TrustLevel.NONE)


# =============================================================================
# CLIENT-SIDE: ATTESTATION AGENT
# =============================================================================

class AttestingAgent:
    """
    Client-side component that attaches attestation to MCP connections.
    
    Usage:
        agent = AttestingAgent(provider, identity)
        capabilities = agent.get_capabilities("https://server.example.com")
        # Include capabilities["experimental"] in initialize request
    """

    def __init__(
        self,
        provider: AttestationProvider,
        identity: AgentIdentity,
        integrity: AgentIntegrity | None = None,
        metadata: AttestationMetadata | None = None,
    ):
        self.provider = provider
        self.identity = identity
        self.integrity = integrity
        self.metadata = metadata or AttestationMetadata()

    def create_token(self, audience: str) -> str:
        """Create attestation token for a specific server."""
        return self.provider.create_token(
            identity=self.identity,
            audience=audience,
            integrity=self.integrity,
            metadata=self.metadata,
        )

    def get_capability(self, audience: str) -> ClientAttestationCapability:
        """Get attestation capability with token for a server."""
        token = self.create_token(audience)
        return ClientAttestationCapability(token=token)

    def get_experimental_capabilities(self, audience: str) -> dict[str, Any]:
        """
        Get experimental capabilities dict for MCP initialize request.
        
        Returns dict to be merged into capabilities.experimental
        """
        return {
            ATTESTATION_CAPABILITY_KEY: self.get_capability(audience).to_dict()
        }

    def inject_into_capabilities(
        self,
        capabilities: dict[str, Any],
        audience: str
    ) -> dict[str, Any]:
        """
        Inject attestation into existing capabilities dict.
        
        Args:
            capabilities: Existing ClientCapabilities dict
            audience: Target server URL
            
        Returns:
            Modified capabilities dict with attestation
        """
        result = capabilities.copy()

        if "experimental" not in result:
            result["experimental"] = {}
        elif result["experimental"] is None:
            result["experimental"] = {}

        result["experimental"][ATTESTATION_CAPABILITY_KEY] = \
            self.get_capability(audience).to_dict()

        return result


# =============================================================================
# SERVER-SIDE: ATTESTATION MIDDLEWARE
# =============================================================================

class AttestationMiddleware:
    """
    Server-side middleware for verifying attestation in initialize requests.
    
    Usage:
        middleware = AttestationMiddleware(verifier, server_capability)
        result = await middleware.process_initialize(request_params)
        
        if not result.should_proceed:
            return result.error_response
        
        # Store result.context in session
        session.attestation = result.context
        
        # Include result.response_capability in initialize response
    """

    def __init__(
        self,
        verifier: AttestationVerifier,
        capability: ServerAttestationCapability | None = None,
    ):
        self.verifier = verifier
        self.capability = capability or ServerAttestationCapability(
            policy=verifier.policy.value,
            trusted_issuers=verifier.trusted_issuers,
            required_claims=verifier.required_claims,
        )

    async def process_initialize(
        self,
        params: dict[str, Any]
    ) -> InitializeResult:
        """
        Process initialize request and verify attestation.
        
        Args:
            params: The InitializeRequestParams dict
            
        Returns:
            InitializeResult with verification outcome
        """
        # Extract attestation from capabilities
        capabilities = params.get("capabilities", {})
        experimental = capabilities.get("experimental", {})
        attestation_cap = experimental.get(ATTESTATION_CAPABILITY_KEY, {})

        token = attestation_cap.get("token")

        # Verify attestation
        verification = await self.verifier.verify(token)

        # Check if we should proceed based on policy
        should_proceed = self._should_proceed(verification)

        # Build response capability
        response_cap = self.capability.with_verification_result(verification)

        # Build context for session
        context = AttestationContext.from_verification_result(verification)

        return InitializeResult(
            should_proceed=should_proceed,
            verification=verification,
            context=context,
            response_capability=response_cap,
            error_response=self._build_error_response(verification) if not should_proceed else None,
        )

    def _should_proceed(self, verification: VerificationResult) -> bool:
        """Determine if connection should proceed based on policy."""
        if self.capability.policy == VerificationPolicy.REQUIRED.value:
            return verification.verified
        elif self.capability.policy == VerificationPolicy.PREFERRED.value:
            # Log but allow
            if not verification.verified:
                print(f"[WARN] Attestation failed but policy is preferred: {verification.error}")
            return True
        else:  # OPTIONAL
            return True

    def _build_error_response(self, verification: VerificationResult) -> dict[str, Any]:
        """Build JSON-RPC error response for failed attestation."""
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": verification.error_code or -32001,
                "message": verification.error or "attestation_required",
                "data": {
                    "policy": self.capability.policy,
                    "trusted_issuers": self.capability.trusted_issuers,
                }
            }
        }

    def get_response_capabilities(
        self,
        result: InitializeResult,
        base_capabilities: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Build capabilities dict for initialize response.
        
        Args:
            result: The InitializeResult from process_initialize
            base_capabilities: Existing ServerCapabilities dict
            
        Returns:
            Capabilities dict with attestation info
        """
        caps = base_capabilities.copy() if base_capabilities else {}

        if "experimental" not in caps:
            caps["experimental"] = {}

        caps["experimental"][ATTESTATION_CAPABILITY_KEY] = \
            result.response_capability.to_dict()

        return caps


@dataclass
class InitializeResult:
    """Result of processing an initialize request for attestation."""
    should_proceed: bool
    verification: VerificationResult
    context: AttestationContext
    response_capability: ServerAttestationCapability
    error_response: dict[str, Any] | None = None


# =============================================================================
# MCP SDK INTEGRATION HELPERS
# =============================================================================

def extract_attestation_from_request(params: dict[str, Any]) -> str | None:
    """
    Extract attestation token from initialize request params.
    
    Args:
        params: InitializeRequestParams dict
        
    Returns:
        JWT token string or None
    """
    try:
        return params.get("capabilities", {}) \
            .get("experimental", {}) \
            .get(ATTESTATION_CAPABILITY_KEY, {}) \
            .get("token")
    except (KeyError, AttributeError, TypeError):
        return None


def inject_attestation_into_response(
    result: dict[str, Any],
    verification: VerificationResult,
    capability: ServerAttestationCapability
) -> dict[str, Any]:
    """
    Inject attestation verification result into initialize response.
    
    Args:
        result: InitializeResult dict
        verification: The verification result
        capability: Server's attestation capability
        
    Returns:
        Modified result dict
    """
    result = result.copy()

    if "capabilities" not in result:
        result["capabilities"] = {}

    if "experimental" not in result["capabilities"]:
        result["capabilities"]["experimental"] = {}

    response_cap = capability.with_verification_result(verification)
    result["capabilities"]["experimental"][ATTESTATION_CAPABILITY_KEY] = \
        response_cap.to_dict()

    return result


# =============================================================================
# DECORATORS FOR FASTMCP INTEGRATION
# =============================================================================

# Type for attestation requirement check
AttestationCheck = Callable[[AttestationContext], Awaitable[bool]]


def require_attestation(
    trust_level: TrustLevel | None = None,
    issuer: str | None = None,
    custom_check: AttestationCheck | None = None,
):
    """
    Decorator to require attestation for a tool/resource.
    
    Usage:
        @mcp.tool()
        @require_attestation(trust_level=TrustLevel.PROVIDER)
        async def sensitive_tool(ctx: Context) -> str:
            ...
    
    Args:
        trust_level: Minimum required trust level
        issuer: Required issuer
        custom_check: Custom validation function
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get context from args/kwargs
            ctx = None
            for arg in args:
                if hasattr(arg, 'attestation'):
                    ctx = arg
                    break
            if ctx is None:
                ctx = kwargs.get('ctx')

            if ctx is None:
                raise ValueError("No context found - cannot check attestation")

            attestation: AttestationContext = getattr(ctx, 'attestation', None)
            if attestation is None:
                attestation = AttestationContext.unverified()

            # Check requirements
            if not attestation.verified:
                raise PermissionError("Attestation required but not verified")

            if trust_level and attestation.trust_level.value < trust_level.value:
                raise PermissionError(f"Insufficient trust level: {attestation.trust_level.value}")

            if issuer and attestation.issuer != issuer:
                raise PermissionError(f"Wrong issuer: {attestation.issuer}")

            if custom_check:
                if not await custom_check(attestation):
                    raise PermissionError("Custom attestation check failed")

            return await func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper

    return decorator


# =============================================================================
# DEMO
# =============================================================================

async def demo():
    """Demonstrate MCP protocol extension usage."""
    from .core import create_anthropic_provider, create_test_verifier

    print("=" * 60)
    print("MCP Attestation Protocol Extension Demo")
    print("=" * 60)

    # 1. Setup provider and verifier
    print("\n[1] Setting up provider and verifier...")
    provider, keypair = create_anthropic_provider()
    verifier = create_test_verifier(keypair, VerificationPolicy.REQUIRED)

    identity = AgentIdentity(
        model_family="claude-4",
        model_version="claude-sonnet-4-20250514",
        provider="anthropic",
    )

    # 2. Create attesting agent (client-side)
    print("\n[2] Creating attesting agent...")
    agent = AttestingAgent(
        provider=provider,
        identity=identity,
        metadata=AttestationMetadata(
            capabilities_declared=["tools", "resources"]
        )
    )

    # 3. Build initialize request with attestation
    print("\n[3] Building initialize request...")
    server_url = "https://mcp-server.example.com"

    client_capabilities = {
        "sampling": {},
        "roots": {"listChanged": True}
    }

    # Inject attestation
    client_capabilities = agent.inject_into_capabilities(
        client_capabilities,
        audience=server_url
    )

    initialize_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": client_capabilities,
            "clientInfo": {"name": "test-agent", "version": "1.0.0"}
        }
    }

    print(f"    Request capabilities keys: {list(client_capabilities.keys())}")
    print(f"    Has attestation: {ATTESTATION_CAPABILITY_KEY in client_capabilities.get('experimental', {})}")

    # 4. Process on server side
    print("\n[4] Server processing initialize request...")
    middleware = AttestationMiddleware(
        verifier=verifier,
        capability=ServerAttestationCapability(
            trusted_issuers=["https://api.anthropic.com"]
        )
    )

    result = await middleware.process_initialize(initialize_request["params"])

    print(f"    Should proceed: {result.should_proceed}")
    print(f"    Verified: {result.verification.verified}")
    print(f"    Trust level: {result.context.trust_level.value}")
    print(f"    Subject: {result.context.subject}")

    # 5. Build server response
    print("\n[5] Building server response...")
    server_capabilities = {"tools": {"listChanged": False}, "resources": {"subscribe": False}}

    server_capabilities = middleware.get_response_capabilities(result, server_capabilities)

    attestation_response = server_capabilities["experimental"][ATTESTATION_CAPABILITY_KEY]
    print(f"    Verification status: {attestation_response.get('verification_status')}")
    print(f"    Trust level: {attestation_response.get('trust_level')}")

    # 6. Test failed attestation
    print("\n[6] Testing request without attestation...")
    no_attestation_request = {
        "protocolVersion": "2025-06-18",
        "capabilities": {"sampling": {}},
        "clientInfo": {"name": "unauthenticated-agent", "version": "1.0.0"}
    }

    failed_result = await middleware.process_initialize(no_attestation_request)
    print(f"    Should proceed: {failed_result.should_proceed}")
    print(f"    Error: {failed_result.verification.error}")
    if failed_result.error_response:
        print(f"    Error code: {failed_result.error_response['error']['code']}")

    print("\n" + "=" * 60)
    print("Protocol extension demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    import asyncio
    asyncio.run(demo())
