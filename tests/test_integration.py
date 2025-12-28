"""
Integration Tests for MCP Agent Attestation

These tests verify end-to-end flows between client and server
with attestation.

Run with: pytest tests/test_integration.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import sys

# Skip all tests if MCP not available
pytestmark = pytest.mark.skipif(
    "mcp" not in sys.modules and not pytest.importorskip("mcp", reason="MCP SDK not installed"),
    reason="MCP SDK not installed"
)


class TestClientServerIntegration:
    """End-to-end tests for client-server attestation flow."""

    @pytest.fixture
    def keypair(self):
        """Generate a keypair for testing."""
        from attestation import KeyPair

        return KeyPair.generate("integration-test-key")

    @pytest.fixture
    def provider_setup(self, keypair):
        """Set up attestation provider."""
        from attestation import AttestationProvider, AgentIdentity

        provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=keypair,
        )
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-20250514",
            provider="anthropic",
        )
        return provider, identity

    @pytest.fixture
    def verifier_setup(self, keypair):
        """Set up attestation verifier."""
        from attestation import AttestationVerifier, InMemoryKeyResolver, VerificationPolicy

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
        return verifier

    @pytest.mark.asyncio
    async def test_full_attestation_flow(self, provider_setup, verifier_setup, keypair):
        """Test complete attestation flow from token creation to verification."""
        from attestation import ATTESTATION_CAPABILITY_KEY

        provider, identity = provider_setup
        verifier = verifier_setup

        # Client creates token
        token = provider.create_token(
            identity=identity,
            audience="https://my-mcp-server.com",
        )

        assert token is not None
        assert len(token) > 0

        # Server verifies token
        result = await verifier.verify(token)

        assert result.verified is True
        assert result.trust_level.value == "provider"
        assert result.claims is not None
        assert result.claims.iss == "https://api.anthropic.com"
        assert "claude" in result.claims.sub.lower()

    @pytest.mark.asyncio
    async def test_client_session_creates_valid_token(self, provider_setup, verifier_setup):
        """Test that AttestingClientSession creates tokens the server can verify."""
        from attestation.mcp_client import AttestingClientSession
        from attestation import ATTESTATION_CAPABILITY_KEY
        import mcp.types as types

        provider, identity = provider_setup
        verifier = verifier_setup

        # Create client session
        read_stream = AsyncMock()
        write_stream = AsyncMock()

        session = AttestingClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://my-mcp-server.com",
        )

        # Get the token from capability
        capability = session._build_attestation_capability()
        token = capability["token"]

        # Verify with server verifier
        result = await verifier.verify(token)

        assert result.verified is True

    @pytest.mark.asyncio
    async def test_server_extracts_and_verifies_token(self, provider_setup, verifier_setup):
        """Test that AttestingServer can extract and verify tokens from sessions."""
        from attestation.mcp_server import AttestingServer
        from attestation import ATTESTATION_CAPABILITY_KEY, TrustLevel
        from mcp.server.lowlevel.server import Server
        import mcp.types as types

        provider, identity = provider_setup
        verifier = verifier_setup

        # Create attesting server
        base_server = Server("test-server")
        attesting_server = AttestingServer(base_server, verifier)

        # Create mock session with attestation token
        token = provider.create_token(
            identity=identity,
            audience="https://my-mcp-server.com",
        )

        session = MagicMock()
        session.client_params = MagicMock()
        session.client_params.capabilities = types.ClientCapabilities(
            experimental={
                ATTESTATION_CAPABILITY_KEY: {"token": token}
            }
        )

        # Verify attestation
        context = await attesting_server.verify_session_attestation(session)

        assert context.verified is True
        assert context.trust_level == TrustLevel.PROVIDER

    @pytest.mark.asyncio
    async def test_server_rejects_invalid_token(self, verifier_setup):
        """Test that server rejects tokens signed by unknown keys."""
        from attestation.mcp_server import AttestingServer
        from attestation import (
            KeyPair, AttestationProvider, AgentIdentity,
            ATTESTATION_CAPABILITY_KEY
        )
        from mcp.server.lowlevel.server import Server
        import mcp.types as types

        verifier = verifier_setup

        # Create token with DIFFERENT keypair (unknown to server)
        unknown_keypair = KeyPair.generate("unknown-key")
        evil_provider = AttestationProvider(
            issuer="https://evil.example.com",
            keypair=unknown_keypair,
        )
        identity = AgentIdentity(
            model_family="fake-claude",
            model_version="fake-version",
            provider="evil-corp",
        )

        evil_token = evil_provider.create_token(
            identity=identity,
            audience="https://my-mcp-server.com",
        )

        # Create attesting server
        base_server = Server("test-server")
        attesting_server = AttestingServer(base_server, verifier)

        # Create mock session with evil token
        session = MagicMock()
        session.client_params = MagicMock()
        session.client_params.capabilities = types.ClientCapabilities(
            experimental={
                ATTESTATION_CAPABILITY_KEY: {"token": evil_token}
            }
        )

        # Should raise PermissionError (REQUIRED policy)
        with pytest.raises(PermissionError, match="Attestation required"):
            await attesting_server.verify_session_attestation(session)

    @pytest.mark.asyncio
    async def test_server_rejects_wrong_audience(self, provider_setup, keypair):
        """Test that server rejects tokens for wrong audience."""
        from attestation.mcp_server import AttestingServer
        from attestation import (
            AttestationVerifier, InMemoryKeyResolver, VerificationPolicy,
            ATTESTATION_CAPABILITY_KEY
        )
        from mcp.server.lowlevel.server import Server
        import mcp.types as types

        provider, identity = provider_setup

        # Set up verifier expecting specific audience
        key_resolver = InMemoryKeyResolver()
        key_resolver.add_key("https://api.anthropic.com", keypair.kid, keypair.public_key)
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=key_resolver,
            policy=VerificationPolicy.REQUIRED,
            audience="https://correct-server.com",  # Expects this audience
        )

        # Create token for WRONG audience
        token = provider.create_token(
            identity=identity,
            audience="https://wrong-server.com",  # Wrong audience!
        )

        base_server = Server("test-server")
        attesting_server = AttestingServer(base_server, verifier)

        session = MagicMock()
        session.client_params = MagicMock()
        session.client_params.capabilities = types.ClientCapabilities(
            experimental={
                ATTESTATION_CAPABILITY_KEY: {"token": token}
            }
        )

        with pytest.raises(PermissionError, match="Attestation required"):
            await attesting_server.verify_session_attestation(session)

    @pytest.mark.asyncio
    async def test_replay_protection(self, provider_setup, keypair):
        """Test that replayed tokens are rejected."""
        from attestation import (
            AttestationVerifier, InMemoryKeyResolver, VerificationPolicy
        )

        provider, identity = provider_setup

        key_resolver = InMemoryKeyResolver()
        key_resolver.add_key("https://api.anthropic.com", keypair.kid, keypair.public_key)
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=key_resolver,
            policy=VerificationPolicy.REQUIRED,
            audience="https://my-mcp-server.com",
        )

        # Create a token
        token = provider.create_token(
            identity=identity,
            audience="https://my-mcp-server.com",
        )

        # First verification should succeed
        result1 = await verifier.verify(token)
        assert result1.verified is True

        # Second verification (replay) should fail
        result2 = await verifier.verify(token)
        assert result2.verified is False
        assert "replay" in result2.error.lower()

    @pytest.mark.asyncio
    async def test_capabilities_include_attestation_requirements(self, verifier_setup):
        """Test that server capabilities include attestation requirements."""
        from attestation.mcp_server import AttestingServer
        from attestation import ATTESTATION_CAPABILITY_KEY
        from mcp.server.lowlevel.server import Server

        verifier = verifier_setup
        base_server = Server("test-server")
        attesting_server = AttestingServer(base_server, verifier)

        caps = attesting_server.get_capabilities()

        assert caps.experimental is not None
        assert ATTESTATION_CAPABILITY_KEY in caps.experimental

        attestation_cap = caps.experimental[ATTESTATION_CAPABILITY_KEY]
        assert attestation_cap["version"] == "0.1.0"
        assert attestation_cap["policy"] == "required"
        assert "https://api.anthropic.com" in attestation_cap["trusted_issuers"]


class TestHTTPKeyResolverIntegration:
    """Integration tests for JWKS HTTP key resolution."""

    @pytest.mark.asyncio
    async def test_jwks_fetcher_with_verifier(self):
        """Test that HTTPKeyResolver works with AttestationVerifier."""
        from attestation import KeyPair, AttestationProvider, AgentIdentity
        from attestation.jwks import HTTPKeyResolver, JWKSFetcher

        # Create a keypair and provider
        keypair = KeyPair.generate("http-test-key")
        provider = AttestationProvider(
            issuer="https://test.example.com",
            keypair=keypair,
        )
        identity = AgentIdentity(
            model_family="test",
            model_version="1.0",
            provider="test",
        )

        # Create token
        token = provider.create_token(
            identity=identity,
            audience="https://server.example.com",
        )

        # Export JWKS
        jwks = keypair.to_jwk()

        # Mock fetcher to return our JWKS
        fetcher = JWKSFetcher()

        with patch.object(fetcher, "get_jwks") as mock_get:
            mock_get.return_value = {"keys": [jwks]}

            resolver = HTTPKeyResolver(fetcher=fetcher)
            key = await resolver.get_key("https://test.example.com", keypair.kid)

            assert key is not None
            mock_get.assert_called_once_with("https://test.example.com")


class TestCacheIntegration:
    """Integration tests for cache with verification."""

    @pytest.mark.asyncio
    async def test_verifier_has_builtin_replay_cache(self):
        """Test that verifier's built-in replay cache works."""
        from attestation import (
            KeyPair, AttestationProvider, AgentIdentity,
            AttestationVerifier, InMemoryKeyResolver, VerificationPolicy
        )

        # Set up
        keypair = KeyPair.generate("cache-test")
        provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=keypair,
        )
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="test",
            provider="anthropic",
        )

        key_resolver = InMemoryKeyResolver()
        key_resolver.add_key("https://api.anthropic.com", keypair.kid, keypair.public_key)

        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=key_resolver,
            policy=VerificationPolicy.REQUIRED,
            audience="https://server.com",
        )

        # Create and verify token
        token = provider.create_token(identity=identity, audience="https://server.com")

        result1 = await verifier.verify(token)
        assert result1.verified is True

        # Replay should be detected by built-in cache
        result2 = await verifier.verify(token)
        assert result2.verified is False
        assert "replay" in result2.error.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
