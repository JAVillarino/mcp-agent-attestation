"""
MCP Agent Attestation Package

A cryptographic attestation extension for the Model Context Protocol
that enables servers to verify the identity and provenance of connecting agents.
"""

from .core import (
    # Data classes
    AgentIdentity,
    AgentIntegrity,
    AttestationMetadata,
    AttestationClaims,
    VerificationResult,
    KeyPair,
    
    # Enums
    AttestationType,
    SafetyLevel,
    VerificationPolicy,
    TrustLevel,
    
    # Providers and Verifiers
    AttestationProvider,
    AttestationVerifier,
    InMemoryKeyResolver,
    ReplayCache,
    
    # Convenience functions
    create_anthropic_provider,
    create_test_verifier,
    
    # Constants
    ATTESTATION_VERSION,
    ATTESTATION_CAPABILITY_KEY,
)

from .protocol import (
    # Capability declarations
    ClientAttestationCapability,
    ServerAttestationCapability,
    
    # Session management
    AttestationContext,
    
    # Client-side
    AttestingAgent,
    
    # Server-side
    AttestationMiddleware,
    InitializeResult,
    
    # Helpers
    extract_attestation_from_request,
    inject_attestation_into_response,
    
    # Decorators
    require_attestation,
)

from .attacks import (
    AttackType,
    AttackResult,
    AttackSimulator,
    print_attack_report,
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
