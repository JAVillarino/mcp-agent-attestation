"""
MCP Agent Attestation Package

A cryptographic attestation extension for the Model Context Protocol
that enables servers to verify the identity and provenance of connecting agents.
"""

from .attacks import (
    AttackResult,
    AttackSimulator,
    AttackType,
    print_attack_report,
)
from .core import (
    ATTESTATION_CAPABILITY_KEY,
    # Constants
    ATTESTATION_VERSION,
    # Data classes
    AgentIdentity,
    AgentIntegrity,
    AttestationClaims,
    AttestationMetadata,
    # Providers and Verifiers
    AttestationProvider,
    # Enums
    AttestationType,
    AttestationVerifier,
    InMemoryKeyResolver,
    KeyPair,
    ReplayCache,
    SafetyLevel,
    TrustLevel,
    VerificationPolicy,
    VerificationResult,
    # Convenience functions
    create_anthropic_provider,
    create_test_verifier,
)
from .protocol import (
    # Session management
    AttestationContext,
    # Server-side
    AttestationMiddleware,
    # Client-side
    AttestingAgent,
    # Capability declarations
    ClientAttestationCapability,
    InitializeResult,
    ServerAttestationCapability,
    # Helpers
    extract_attestation_from_request,
    inject_attestation_into_response,
    # Decorators
    require_attestation,
)

__version__ = "0.1.0"
__author__ = "Joel Villarino"

__all__ = [
    # Core
    "AgentIdentity",
    "AgentIntegrity",
    "AttestationMetadata",
    "AttestationClaims",
    "VerificationResult",
    "KeyPair",
    "AttestationType",
    "SafetyLevel",
    "VerificationPolicy",
    "TrustLevel",
    "AttestationProvider",
    "AttestationVerifier",
    "InMemoryKeyResolver",
    "ReplayCache",
    "create_anthropic_provider",
    "create_test_verifier",
    "ATTESTATION_VERSION",
    "ATTESTATION_CAPABILITY_KEY",

    # Protocol
    "ClientAttestationCapability",
    "ServerAttestationCapability",
    "AttestationContext",
    "AttestingAgent",
    "AttestationMiddleware",
    "InitializeResult",
    "extract_attestation_from_request",
    "inject_attestation_into_response",
    "require_attestation",

    # Attacks
    "AttackType",
    "AttackResult",
    "AttackSimulator",
    "print_attack_report",
]
