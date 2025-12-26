"""
MCP Agent Attestation - Core Module

This module implements the attestation token creation and verification
using Ed25519 signatures and JWT format.

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Protocol

# For real crypto - install with: pip install cryptography PyJWT
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography not installed. Using mock crypto.")

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    print("Warning: PyJWT not installed. Using mock JWT.")


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class AttestationType(str, Enum):
    """Type of attestation issuer."""
    PROVIDER = "provider"      # Model provider (Anthropic, OpenAI)
    ENTERPRISE = "enterprise"  # Enterprise IdP (SPIFFE, Okta)


class SafetyLevel(str, Enum):
    """Model safety configuration level."""
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MINIMAL = "minimal"


class VerificationPolicy(str, Enum):
    """Server attestation policy."""
    REQUIRED = "required"    # Reject connections without valid attestation
    PREFERRED = "preferred"  # Accept but log missing attestation
    OPTIONAL = "optional"    # Accept any connection


class TrustLevel(str, Enum):
    """Resulting trust level after verification."""
    PROVIDER = "provider"    # Verified by model provider
    ENTERPRISE = "enterprise" # Verified by enterprise IdP
    NONE = "none"            # No verification


# Attestation protocol version
ATTESTATION_VERSION = "0.1.0"

# Default token lifetime (5 minutes)
DEFAULT_TOKEN_LIFETIME_SECONDS = 300

# Clock skew tolerance (30 seconds)
CLOCK_SKEW_SECONDS = 30

# MCP experimental capability key
ATTESTATION_CAPABILITY_KEY = "security.attestation"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AgentIdentity:
    """
    Identifies the AI model and its provider.
    
    Follows SPIFFE ID format for enterprise compatibility:
    spiffe://<trust-domain>/<workload-path>
    """
    model_family: str           # e.g., "claude-4", "gpt-4"
    model_version: str          # e.g., "claude-sonnet-4-20250514"
    provider: str               # e.g., "anthropic", "openai"
    deployment_id: str | None = None  # e.g., "api-prod-us-east-1"

    def to_spiffe_id(self, trust_domain: str | None = None) -> str:
        """Generate SPIFFE ID from identity."""
        domain = trust_domain or f"{self.provider}.com"
        return f"spiffe://{domain}/model/{self.model_version}"

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class AgentIntegrity:
    """
    Hashes for verifying agent configuration integrity.
    """
    config_hash: str | None = None        # SHA256 of config
    system_prompt_hash: str | None = None # SHA256 of system prompt

    @staticmethod
    def compute_hash(content: str) -> str:
        """Compute SHA256 hash of content."""
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class AttestationMetadata:
    """
    Metadata about the attestation itself.
    """
    attestation_version: str = ATTESTATION_VERSION
    attestation_type: str = AttestationType.PROVIDER.value
    safety_level: str = SafetyLevel.STANDARD.value
    capabilities_declared: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ConfirmationKey:
    """
    Proof-of-possession key (for future channel binding).
    """
    jwk: dict[str, str] | None = None
    tls_binding: dict[str, str] | None = None  # Reserved for future

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class AttestationClaims:
    """
    Complete JWT claims for an attestation token.
    """
    # Standard JWT claims
    iss: str                           # Issuer URL
    sub: str                           # Subject (SPIFFE ID)
    aud: str | list[str]         # Audience (target server)
    iat: int                           # Issued-at timestamp
    exp: int                           # Expiration timestamp
    jti: str                           # Unique token ID

    # Attestation-specific claims
    agent_identity: AgentIdentity
    attestation_metadata: AttestationMetadata

    # Optional claims
    nbf: int | None = None          # Not-before timestamp
    agent_integrity: AgentIntegrity | None = None
    cnf: ConfirmationKey | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JWT encoding."""
        result = {
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
            "agent_identity": self.agent_identity.to_dict(),
            "attestation_metadata": self.attestation_metadata.to_dict(),
        }

        if self.nbf is not None:
            result["nbf"] = self.nbf
        if self.agent_integrity is not None:
            result["agent_integrity"] = self.agent_integrity.to_dict()
        if self.cnf is not None:
            result["cnf"] = self.cnf.to_dict()

        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttestationClaims:
        """Create from dictionary (decoded JWT)."""
        return cls(
            iss=data["iss"],
            sub=data["sub"],
            aud=data["aud"],
            iat=data["iat"],
            exp=data["exp"],
            jti=data["jti"],
            agent_identity=AgentIdentity(**data["agent_identity"]),
            attestation_metadata=AttestationMetadata(**data["attestation_metadata"]),
            nbf=data.get("nbf"),
            agent_integrity=AgentIntegrity(**data["agent_integrity"]) if data.get("agent_integrity") else None,
            cnf=ConfirmationKey(**data["cnf"]) if data.get("cnf") else None,
        )


@dataclass
class VerificationResult:
    """
    Result of attestation verification.
    """
    verified: bool
    trust_level: TrustLevel
    issuer: str | None = None
    subject: str | None = None
    claims: AttestationClaims | None = None
    verified_claims: list[str] = field(default_factory=list)
    error: str | None = None
    error_code: int | None = None

    @classmethod
    def success(
        cls,
        claims: AttestationClaims,
        trust_level: TrustLevel = TrustLevel.PROVIDER
    ) -> VerificationResult:
        """Create successful verification result."""
        return cls(
            verified=True,
            trust_level=trust_level,
            issuer=claims.iss,
            subject=claims.sub,
            claims=claims,
            verified_claims=["agent_identity", "attestation_metadata"]
        )

    @classmethod
    def failure(cls, error: str, error_code: int) -> VerificationResult:
        """Create failed verification result."""
        return cls(
            verified=False,
            trust_level=TrustLevel.NONE,
            error=error,
            error_code=error_code
        )


# =============================================================================
# KEY MANAGEMENT
# =============================================================================

@dataclass
class KeyPair:
    """Ed25519 key pair for signing/verification."""
    private_key: Any  # Ed25519PrivateKey or mock
    public_key: Any   # Ed25519PublicKey or mock
    kid: str          # Key ID

    @classmethod
    def generate(cls, kid: str | None = None) -> KeyPair:
        """Generate a new Ed25519 key pair."""
        if CRYPTO_AVAILABLE:
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
        else:
            # Mock for when cryptography not installed
            private_key = secrets.token_bytes(32)
            public_key = secrets.token_bytes(32)

        key_id = kid or f"key-{uuid.uuid4().hex[:8]}"
        return cls(private_key=private_key, public_key=public_key, kid=key_id)

    def public_key_bytes(self) -> bytes:
        """Get raw public key bytes."""
        if CRYPTO_AVAILABLE:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        return self.public_key

    def to_jwk(self) -> dict[str, str]:
        """Export public key as JWK."""
        pk_bytes = self.public_key_bytes()
        x = base64.urlsafe_b64encode(pk_bytes).decode().rstrip("=")
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.kid,
            "x": x,
            "use": "sig",
            "alg": "EdDSA"
        }


class KeyResolver(Protocol):
    """Protocol for resolving public keys from issuers."""

    async def get_key(self, issuer: str, kid: str) -> Any | None:
        """Resolve public key for issuer and key ID."""
        ...


class InMemoryKeyResolver:
    """
    Simple in-memory key resolver for development/testing.
    
    In production, this would fetch from JWKS endpoints.
    """

    def __init__(self):
        self._keys: dict[str, dict[str, Any]] = {}

    def add_key(self, issuer: str, kid: str, public_key: Any):
        """Add a public key for an issuer."""
        if issuer not in self._keys:
            self._keys[issuer] = {}
        self._keys[issuer][kid] = public_key

    def add_keypair(self, issuer: str, keypair: KeyPair):
        """Add public key from a KeyPair."""
        self.add_key(issuer, keypair.kid, keypair.public_key)

    async def get_key(self, issuer: str, kid: str) -> Any | None:
        """Get public key for issuer and key ID."""
        issuer_keys = self._keys.get(issuer, {})
        return issuer_keys.get(kid)

    def to_jwks(self, issuer: str) -> dict[str, list[dict]]:
        """Export keys for issuer as JWKS."""
        issuer_keys = self._keys.get(issuer, {})
        keys = []
        for kid, pk in issuer_keys.items():
            if CRYPTO_AVAILABLE and hasattr(pk, 'public_bytes'):
                pk_bytes = pk.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:
                pk_bytes = pk
            x = base64.urlsafe_b64encode(pk_bytes).decode().rstrip("=")
            keys.append({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "x": x,
                "use": "sig",
                "alg": "EdDSA"
            })
        return {"keys": keys}


# =============================================================================
# ATTESTATION PROVIDER (TOKEN CREATION)
# =============================================================================

class AttestationProvider:
    """
    Creates attestation tokens for agents.
    
    In production, this runs on the model provider's infrastructure.
    For PoC, we simulate it locally.
    """

    def __init__(
        self,
        issuer: str,
        keypair: KeyPair,
        token_lifetime: int = DEFAULT_TOKEN_LIFETIME_SECONDS
    ):
        self.issuer = issuer
        self.keypair = keypair
        self.token_lifetime = token_lifetime

    def create_token(
        self,
        identity: AgentIdentity,
        audience: str | list[str],
        integrity: AgentIntegrity | None = None,
        metadata: AttestationMetadata | None = None,
    ) -> str:
        """
        Create a signed attestation token.
        
        Args:
            identity: The agent's identity information
            audience: Target server(s) the token is valid for
            integrity: Optional integrity hashes
            metadata: Optional attestation metadata
            
        Returns:
            Signed JWT token string
        """
        now = int(time.time())

        claims = AttestationClaims(
            iss=self.issuer,
            sub=identity.to_spiffe_id(),
            aud=audience,
            iat=now,
            exp=now + self.token_lifetime,
            nbf=now,
            jti=str(uuid.uuid4()),
            agent_identity=identity,
            agent_integrity=integrity,
            attestation_metadata=metadata or AttestationMetadata(),
        )

        return self._sign_token(claims)

    def _sign_token(self, claims: AttestationClaims) -> str:
        """Sign claims and return JWT."""
        if JWT_AVAILABLE and CRYPTO_AVAILABLE:
            # Use real JWT library with Ed25519
            return jwt.encode(
                claims.to_dict(),
                self.keypair.private_key,
                algorithm="EdDSA",
                headers={"kid": self.keypair.kid}
            )
        else:
            # Mock JWT for development
            return self._mock_sign(claims)

    def _mock_sign(self, claims: AttestationClaims) -> str:
        """Create mock JWT (for development without crypto libs)."""
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self.keypair.kid}

        def b64_encode(data: dict) -> str:
            json_bytes = json.dumps(data, separators=(',', ':')).encode()
            return base64.urlsafe_b64encode(json_bytes).decode().rstrip("=")

        header_b64 = b64_encode(header)
        payload_b64 = b64_encode(claims.to_dict())

        # Mock signature (NOT CRYPTOGRAPHICALLY SECURE - for demo only)
        signature_input = f"{header_b64}.{payload_b64}".encode()
        mock_sig = hashlib.sha256(signature_input).digest()[:32]
        sig_b64 = base64.urlsafe_b64encode(mock_sig).decode().rstrip("=")

        return f"{header_b64}.{payload_b64}.{sig_b64}"


# =============================================================================
# ATTESTATION VERIFIER (TOKEN VALIDATION)
# =============================================================================

# Error codes for attestation failures
class AttestationError:
    REQUIRED = -32001
    INVALID = -32002
    EXPIRED = -32003
    REPLAY = -32004
    UNTRUSTED_ISSUER = -32005
    INSUFFICIENT_CLAIMS = -32006


class ReplayCache:
    """
    Cache for tracking seen token IDs to prevent replay attacks.
    
    Uses in-memory storage. For production, use Redis or similar.
    """

    def __init__(self):
        self._seen: dict[str, int] = {}  # jti -> expiration time

    def _cleanup_expired(self):
        """Remove expired entries."""
        now = int(time.time())
        self._seen = {
            jti: exp for jti, exp in self._seen.items()
            if exp > now
        }

    def check_and_add(self, jti: str, exp: int) -> bool:
        """
        Check if token ID is new and add it to cache.
        
        Returns:
            True if token is new (not a replay)
            False if token was already seen (replay attack)
        """
        self._cleanup_expired()

        if jti in self._seen:
            return False

        self._seen[jti] = exp
        return True

    def clear(self):
        """Clear all cached tokens."""
        self._seen.clear()


class AttestationVerifier:
    """
    Verifies attestation tokens from agents.
    
    Runs on MCP server to validate incoming connections.
    """

    def __init__(
        self,
        trusted_issuers: list[str],
        key_resolver: KeyResolver,
        policy: VerificationPolicy = VerificationPolicy.REQUIRED,
        required_claims: list[str] | None = None,
        audience: str | None = None,
    ):
        self.trusted_issuers = trusted_issuers
        self.key_resolver = key_resolver
        self.policy = policy
        self.required_claims = required_claims or ["agent_identity", "attestation_metadata"]
        self.audience = audience
        self.replay_cache = ReplayCache()

    async def verify(self, token: str | None) -> VerificationResult:
        """
        Verify an attestation token.
        
        Args:
            token: JWT token string, or None if not provided
            
        Returns:
            VerificationResult with success/failure details
        """
        # Handle missing token based on policy
        if token is None:
            if self.policy == VerificationPolicy.REQUIRED:
                return VerificationResult.failure(
                    "Attestation required but not provided",
                    AttestationError.REQUIRED
                )
            return VerificationResult(
                verified=False,
                trust_level=TrustLevel.NONE,
                error="No attestation provided"
            )

        # Decode and validate token
        try:
            claims = await self._decode_and_verify(token)
            return VerificationResult.success(claims)
        except Exception as e:
            return VerificationResult.failure(str(e), AttestationError.INVALID)

    async def _decode_and_verify(self, token: str) -> AttestationClaims:
        """Decode token and verify all aspects."""
        # Parse JWT structure
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        # Decode header
        header_json = self._b64_decode(parts[0])
        header = json.loads(header_json)

        # Decode payload
        payload_json = self._b64_decode(parts[1])
        payload = json.loads(payload_json)

        # Verify issuer is trusted
        issuer = payload.get("iss")
        if issuer not in self.trusted_issuers:
            raise ValueError(f"Untrusted issuer: {issuer}")

        # Get public key
        kid = header.get("kid")
        public_key = await self.key_resolver.get_key(issuer, kid)
        if public_key is None:
            raise ValueError(f"Unknown key ID: {kid}")

        # Verify signature
        if JWT_AVAILABLE and CRYPTO_AVAILABLE:
            # Real verification
            try:
                jwt.decode(
                    token,
                    public_key,
                    algorithms=["EdDSA"],
                    audience=self.audience,
                    options={"verify_aud": self.audience is not None}
                )
            except jwt.ExpiredSignatureError as e:
                raise ValueError("Token expired") from e
            except jwt.InvalidAudienceError as e:
                raise ValueError("Invalid audience") from e
            except Exception as e:
                raise ValueError(f"Signature verification failed: {e}") from e
        else:
            # Mock verification for development
            self._mock_verify(token, parts, public_key)

        # Validate timestamps
        now = int(time.time())

        iat = payload.get("iat", 0)
        if abs(now - iat) > CLOCK_SKEW_SECONDS + DEFAULT_TOKEN_LIFETIME_SECONDS:
            raise ValueError("Token issued-at too far from current time")

        exp = payload.get("exp", 0)
        if now > exp + CLOCK_SKEW_SECONDS:
            raise ValueError("Token expired")

        nbf = payload.get("nbf")
        if nbf and now < nbf - CLOCK_SKEW_SECONDS:
            raise ValueError("Token not yet valid")

        # Check for replay
        jti = payload.get("jti")
        if not jti:
            raise ValueError("Missing token ID (jti)")

        if not self.replay_cache.check_and_add(jti, exp):
            raise ValueError("Token replay detected")

        # Validate audience if configured
        if self.audience:
            aud = payload.get("aud")
            if isinstance(aud, list):
                if self.audience not in aud:
                    raise ValueError("Invalid audience")
            elif aud != self.audience:
                raise ValueError("Invalid audience")

        # Check required claims
        for claim in self.required_claims:
            if claim not in payload:
                raise ValueError(f"Missing required claim: {claim}")

        return AttestationClaims.from_dict(payload)

    def _b64_decode(self, s: str) -> bytes:
        """Decode base64url with padding."""
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s)

    def _mock_verify(self, token: str, parts: list[str], public_key: Any):
        """Mock signature verification for development."""
        # Recompute mock signature and compare
        signature_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hashlib.sha256(signature_input).digest()[:32]
        expected_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")

        actual_b64 = parts[2]
        if expected_b64 != actual_b64:
            raise ValueError("Invalid signature (mock verification)")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_anthropic_provider(kid: str = "anthropic-2025-01") -> tuple[AttestationProvider, KeyPair]:
    """Create a mock Anthropic attestation provider for testing."""
    keypair = KeyPair.generate(kid)
    provider = AttestationProvider(
        issuer="https://api.anthropic.com",
        keypair=keypair
    )
    return provider, keypair


def create_test_verifier(
    provider_keypair: KeyPair,
    policy: VerificationPolicy = VerificationPolicy.REQUIRED
) -> AttestationVerifier:
    """Create a verifier configured to trust the test provider."""
    key_resolver = InMemoryKeyResolver()
    key_resolver.add_keypair("https://api.anthropic.com", provider_keypair)

    return AttestationVerifier(
        trusted_issuers=["https://api.anthropic.com"],
        key_resolver=key_resolver,
        policy=policy
    )


# =============================================================================
# DEMO / TEST
# =============================================================================

async def demo():
    """Demonstrate attestation creation and verification."""
    print("=" * 60)
    print("MCP Agent Attestation Demo")
    print("=" * 60)

    # 1. Create provider (simulating Anthropic)
    print("\n[1] Creating attestation provider...")
    provider, keypair = create_anthropic_provider()
    print(f"    Issuer: {provider.issuer}")
    print(f"    Key ID: {keypair.kid}")

    # 2. Create agent identity
    print("\n[2] Creating agent identity...")
    identity = AgentIdentity(
        model_family="claude-4",
        model_version="claude-sonnet-4-20250514",
        provider="anthropic",
        deployment_id="api-prod-us-east-1"
    )
    print(f"    Model: {identity.model_version}")
    print(f"    SPIFFE ID: {identity.to_spiffe_id()}")

    # 3. Create attestation token
    print("\n[3] Creating attestation token...")
    token = provider.create_token(
        identity=identity,
        audience="https://mcp-server.example.com",
        integrity=AgentIntegrity(
            config_hash=AgentIntegrity.compute_hash("test-config")
        ),
        metadata=AttestationMetadata(
            capabilities_declared=["tools", "resources"]
        )
    )
    print(f"    Token length: {len(token)} chars")
    print(f"    Token (first 80 chars): {token[:80]}...")

    # 4. Create verifier
    print("\n[4] Creating attestation verifier...")
    verifier = create_test_verifier(keypair)
    print(f"    Policy: {verifier.policy.value}")
    print(f"    Trusted issuers: {verifier.trusted_issuers}")

    # 5. Verify valid token
    print("\n[5] Verifying valid token...")
    result = await verifier.verify(token)
    print(f"    Verified: {result.verified}")
    print(f"    Trust level: {result.trust_level.value}")
    print(f"    Issuer: {result.issuer}")
    print(f"    Subject: {result.subject}")

    # 6. Test replay protection
    print("\n[6] Testing replay protection...")
    result2 = await verifier.verify(token)
    print(f"    Second verification: {result2.verified}")
    print(f"    Error: {result2.error}")

    # 7. Test missing token
    print("\n[7] Testing missing token (policy=required)...")
    result3 = await verifier.verify(None)
    print(f"    Verified: {result3.verified}")
    print(f"    Error: {result3.error}")

    # 8. Export JWKS
    print("\n[8] JWKS for provider...")
    key_resolver = InMemoryKeyResolver()
    key_resolver.add_keypair("https://api.anthropic.com", keypair)
    jwks = key_resolver.to_jwks("https://api.anthropic.com")
    print(f"    {json.dumps(jwks, indent=2)}")

    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    import asyncio
    asyncio.run(demo())
