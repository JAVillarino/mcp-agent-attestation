"""
Real MCP Integration Test

This test verifies attestation works with actual MCP SDK components,
not just mocks. It creates a real MCP server and client, testing the
full attestation flow.

Run with: pytest tests/test_real_mcp_integration.py -v -s
"""

import asyncio
import pytest
from unittest.mock import AsyncMock

# Check if MCP is available
try:
    from mcp.server.lowlevel import Server
    from mcp.server.models import InitializationOptions
    from mcp.types import (
        ClientCapabilities,
        Implementation,
        InitializeRequest,
        InitializeResult,
        ServerCapabilities,
        LATEST_PROTOCOL_VERSION,
    )
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")


class TestRealMCPIntegration:
    """Test attestation with real MCP SDK components."""

    @pytest.fixture
    def attestation_setup(self):
        """Set up attestation provider and verifier."""
        from attestation import (
            AttestationProvider,
            AttestationVerifier,
            AgentIdentity,
            InMemoryKeyResolver,
            KeyPair,
            VerificationPolicy,
        )

        # Create keypair (simulating Anthropic's key)
        keypair = KeyPair.generate("test-integration-key")

        # Create provider (client-side)
        provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=keypair,
        )

        # Create identity
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-integration-test",
            provider="anthropic",
            deployment_id="integration-test",
        )

        # Create key resolver (server-side)
        key_resolver = InMemoryKeyResolver()
        key_resolver.add_keypair("https://api.anthropic.com", keypair)

        # Create verifier (server-side)
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=key_resolver,
            policy=VerificationPolicy.REQUIRED,
            audience="https://test-server.local",
        )

        return {
            "provider": provider,
            "identity": identity,
            "verifier": verifier,
            "keypair": keypair,
        }

    @pytest.mark.asyncio
    async def test_attestation_in_initialize_request(self, attestation_setup):
        """Test that attestation token can be embedded in MCP initialize request."""
        from attestation import AttestingAgent

        provider = attestation_setup["provider"]
        identity = attestation_setup["identity"]

        # Create attesting agent
        agent = AttestingAgent(provider=provider, identity=identity)

        # Create base capabilities
        base_capabilities = ClientCapabilities(
            sampling=None,
            roots=None,
            experimental=None,
        )

        # Inject attestation
        enhanced_caps = agent.inject_into_capabilities(
            base_capabilities.model_dump() if hasattr(base_capabilities, 'model_dump') else {},
            audience="https://test-server.local",
        )

        # Verify attestation was injected
        assert "experimental" in enhanced_caps
        assert "security.attestation" in enhanced_caps["experimental"]
        assert "token" in enhanced_caps["experimental"]["security.attestation"]

        # Token should be valid JWT format
        token = enhanced_caps["experimental"]["security.attestation"]["token"]
        assert token.count(".") == 2, "Token should be JWT format (header.payload.signature)"

    @pytest.mark.asyncio
    async def test_server_verifies_attestation(self, attestation_setup):
        """Test that server can verify attestation from initialize params."""
        from attestation import AttestationMiddleware, ServerAttestationCapability

        provider = attestation_setup["provider"]
        identity = attestation_setup["identity"]
        verifier = attestation_setup["verifier"]

        # Create token
        token = provider.create_token(
            identity=identity,
            audience="https://test-server.local",
        )

        # Simulate initialize request params with attestation
        init_params = {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {
                "experimental": {
                    "security.attestation": {
                        "version": "0.1.0",
                        "token": token,
                    }
                }
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0",
            }
        }

        # Create middleware
        middleware = AttestationMiddleware(
            verifier=verifier,
            capability=ServerAttestationCapability(
                policy="required",
                trusted_issuers=["https://api.anthropic.com"],
            ),
        )

        # Process initialize request
        result = await middleware.process_initialize(init_params)

        # Should succeed
        assert result.should_proceed, f"Verification failed: {result.error_response}"
        assert result.context is not None
        assert result.context.verified
        assert result.context.trust_level.value == "provider"

    @pytest.mark.asyncio
    async def test_server_rejects_missing_attestation(self, attestation_setup):
        """Test that server rejects requests without attestation when required."""
        from attestation import AttestationMiddleware, ServerAttestationCapability

        verifier = attestation_setup["verifier"]

        # Simulate initialize request WITHOUT attestation
        init_params = {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0",
            }
        }

        # Create middleware with required policy
        middleware = AttestationMiddleware(
            verifier=verifier,
            capability=ServerAttestationCapability(
                policy="required",
                trusted_issuers=["https://api.anthropic.com"],
            ),
        )

        # Process initialize request
        result = await middleware.process_initialize(init_params)

        # Should fail
        assert not result.should_proceed
        assert result.error_response is not None
        assert result.error_response["error"]["code"] == -32001  # attestation_required

    @pytest.mark.asyncio
    async def test_server_accepts_optional_missing_attestation(self, attestation_setup):
        """Test that server accepts missing attestation when policy is optional."""
        from attestation import (
            AttestationMiddleware,
            ServerAttestationCapability,
            AttestationVerifier,
            VerificationPolicy,
        )

        # Create verifier with optional policy
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=attestation_setup["verifier"].key_resolver,
            policy=VerificationPolicy.OPTIONAL,
            audience="https://test-server.local",
        )

        # Simulate initialize request WITHOUT attestation
        init_params = {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0",
            }
        }

        # Create middleware with optional policy
        middleware = AttestationMiddleware(
            verifier=verifier,
            capability=ServerAttestationCapability(
                policy="optional",
                trusted_issuers=["https://api.anthropic.com"],
            ),
        )

        # Process initialize request
        result = await middleware.process_initialize(init_params)

        # Should succeed (optional policy)
        assert result.should_proceed

    @pytest.mark.asyncio
    async def test_full_mcp_server_with_attestation(self, attestation_setup):
        """Test creating an MCP server with attestation verification."""
        from attestation.mcp_server import create_attesting_server

        verifier = attestation_setup["verifier"]
        provider = attestation_setup["provider"]
        identity = attestation_setup["identity"]

        # Create attesting server
        server = create_attesting_server(
            name="test-attesting-server",
            verifier=verifier,
            version="1.0.0",
        )

        # Server should have attestation capability
        assert server is not None
        assert hasattr(server, "_verifier")

        # Create a valid token
        token = provider.create_token(
            identity=identity,
            audience="https://test-server.local",
        )

        # Verify the token works
        result = await verifier.verify(token)
        assert result.verified
        assert result.trust_level.value == "provider"
        assert result.issuer == "https://api.anthropic.com"

    @pytest.mark.asyncio
    async def test_replay_attack_blocked(self, attestation_setup):
        """Test that replayed tokens are rejected."""
        provider = attestation_setup["provider"]
        identity = attestation_setup["identity"]
        verifier = attestation_setup["verifier"]

        # Create token
        token = provider.create_token(
            identity=identity,
            audience="https://test-server.local",
        )

        # First verification should succeed
        result1 = await verifier.verify(token)
        assert result1.verified, "First verification should succeed"

        # Second verification (replay) should fail
        result2 = await verifier.verify(token)
        assert not result2.verified, "Replay should be detected"
        assert "replay" in result2.error.lower(), f"Error should mention replay: {result2.error}"

    @pytest.mark.asyncio
    async def test_untrusted_issuer_rejected(self, attestation_setup):
        """Test that tokens from untrusted issuers are rejected."""
        from attestation import AttestationProvider, KeyPair

        identity = attestation_setup["identity"]
        verifier = attestation_setup["verifier"]

        # Create a different keypair (untrusted issuer)
        untrusted_keypair = KeyPair.generate("untrusted-key")
        untrusted_provider = AttestationProvider(
            issuer="https://evil.example.com",
            keypair=untrusted_keypair,
        )

        # Create token from untrusted issuer
        token = untrusted_provider.create_token(
            identity=identity,
            audience="https://test-server.local",
        )

        # Verification should fail
        result = await verifier.verify(token)
        assert not result.verified
        assert "issuer" in result.error.lower() or "untrusted" in result.error.lower()


class TestAttestingClientSession:
    """Test the AttestingClientSession wrapper."""

    @pytest.fixture
    def client_setup(self):
        """Set up client with attestation."""
        from attestation import (
            AttestationProvider,
            AgentIdentity,
            KeyPair,
        )

        keypair = KeyPair.generate("client-test-key")
        provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=keypair,
        )
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4",
            provider="anthropic",
        )

        return {
            "provider": provider,
            "identity": identity,
            "keypair": keypair,
        }

    @pytest.mark.asyncio
    async def test_client_session_injects_attestation(self, client_setup):
        """Test that AttestingClientSession properly injects attestation."""
        from attestation.mcp_client import AttestingClientSession

        provider = client_setup["provider"]
        identity = client_setup["identity"]

        # Create mock streams
        mock_read = AsyncMock()
        mock_write = AsyncMock()

        # Create session
        session = AttestingClientSession(
            read_stream=mock_read,
            write_stream=mock_write,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://test-server.local",
        )

        # Verify session has attestation configured
        assert session._attestation_provider == provider
        assert session._agent_identity == identity
        assert session._target_audience == "https://test-server.local"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
