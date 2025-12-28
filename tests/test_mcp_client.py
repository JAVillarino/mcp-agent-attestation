"""
Tests for MCP Client Integration

Run with: pytest tests/test_mcp_client.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import sys

# Skip all tests if MCP not available
pytestmark = pytest.mark.skipif(
    "mcp" not in sys.modules and not pytest.importorskip("mcp", reason="MCP SDK not installed"),
    reason="MCP SDK not installed"
)


class TestAttestingClientSession:
    """Tests for AttestingClientSession class."""

    @pytest.fixture
    def mock_streams(self):
        """Create mock read/write streams."""
        read_stream = AsyncMock()
        write_stream = AsyncMock()
        return read_stream, write_stream

    @pytest.fixture
    def attestation_setup(self):
        """Set up attestation provider and identity."""
        from attestation import AttestationProvider, AgentIdentity, KeyPair

        keypair = KeyPair.generate("test-key")
        provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=keypair,
        )
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-20250514",
            provider="anthropic",
        )
        return provider, identity, keypair

    def test_create_attestation_token(self, mock_streams, attestation_setup):
        """Test that attestation token is created correctly."""
        from attestation.mcp_client import AttestingClientSession

        read_stream, write_stream = mock_streams
        provider, identity, _ = attestation_setup

        session = AttestingClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://my-mcp-server.com",
        )

        token = session._create_attestation_token()

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
        # JWT format: header.payload.signature
        parts = token.split(".")
        assert len(parts) == 3

    def test_build_attestation_capability(self, mock_streams, attestation_setup):
        """Test attestation capability dict structure."""
        from attestation.mcp_client import AttestingClientSession

        read_stream, write_stream = mock_streams
        provider, identity, _ = attestation_setup

        session = AttestingClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://my-mcp-server.com",
        )

        capability = session._build_attestation_capability()

        assert capability["version"] == "0.1.0"
        assert "token" in capability
        assert capability["supported_algorithms"] == ["EdDSA"]
        assert capability["attestation_types"] == ["provider", "enterprise"]

    def test_attestation_status_initially_none(self, mock_streams, attestation_setup):
        """Test that attestation status is None before initialization."""
        from attestation.mcp_client import AttestingClientSession

        read_stream, write_stream = mock_streams
        provider, identity, _ = attestation_setup

        session = AttestingClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://my-mcp-server.com",
        )

        assert session.attestation_status is None
        assert session.attestation_verified is False

    @pytest.mark.asyncio
    async def test_initialize_injects_attestation(self, mock_streams, attestation_setup):
        """Test that initialize() injects attestation into capabilities."""
        from attestation.mcp_client import AttestingClientSession
        from attestation import ATTESTATION_CAPABILITY_KEY
        import mcp.types as types

        read_stream, write_stream = mock_streams
        provider, identity, _ = attestation_setup

        session = AttestingClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://my-mcp-server.com",
        )

        # Track the request that was sent
        sent_request = None

        async def mock_send_request(request, result_type, **kwargs):
            nonlocal sent_request
            sent_request = request
            # Return mock result
            return types.InitializeResult(
                protocolVersion="2025-03-26",
                capabilities=types.ServerCapabilities(
                    experimental={
                        ATTESTATION_CAPABILITY_KEY: {
                            "verification_status": "verified",
                            "trust_level": "provider",
                        }
                    }
                ),
                serverInfo=types.Implementation(name="test-server", version="1.0.0"),
            )

        session.send_request = mock_send_request
        session.send_notification = AsyncMock()

        result = await session.initialize()

        # Verify attestation was included in request
        assert sent_request is not None
        params = sent_request.root.params
        assert params.capabilities.experimental is not None
        assert ATTESTATION_CAPABILITY_KEY in params.capabilities.experimental
        attestation_cap = params.capabilities.experimental[ATTESTATION_CAPABILITY_KEY]
        assert "token" in attestation_cap
        assert attestation_cap["version"] == "0.1.0"

        # Verify status was parsed
        assert session.attestation_verified is True
        assert session.attestation_status["verification_status"] == "verified"

    @pytest.mark.asyncio
    async def test_initialize_handles_rejected_attestation(self, mock_streams, attestation_setup):
        """Test that rejected attestation raises error when required."""
        from attestation.mcp_client import AttestingClientSession
        from attestation import ATTESTATION_CAPABILITY_KEY
        import mcp.types as types

        read_stream, write_stream = mock_streams
        provider, identity, _ = attestation_setup

        session = AttestingClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://my-mcp-server.com",
        )

        async def mock_send_request(request, result_type, **kwargs):
            return types.InitializeResult(
                protocolVersion="2025-03-26",
                capabilities=types.ServerCapabilities(
                    experimental={
                        ATTESTATION_CAPABILITY_KEY: {
                            "verification_status": "failed",
                            "policy": "required",
                            "error": "Invalid signature",
                        }
                    }
                ),
                serverInfo=types.Implementation(name="test-server", version="1.0.0"),
            )

        session.send_request = mock_send_request

        with pytest.raises(RuntimeError, match="Attestation verification failed"):
            await session.initialize()

    @pytest.mark.asyncio
    async def test_initialize_warns_on_preferred_failure(self, mock_streams, attestation_setup):
        """Test that preferred policy failure logs warning but continues."""
        from attestation.mcp_client import AttestingClientSession
        from attestation import ATTESTATION_CAPABILITY_KEY
        import mcp.types as types

        read_stream, write_stream = mock_streams
        provider, identity, _ = attestation_setup

        session = AttestingClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://my-mcp-server.com",
        )

        async def mock_send_request(request, result_type, **kwargs):
            return types.InitializeResult(
                protocolVersion="2025-03-26",
                capabilities=types.ServerCapabilities(
                    experimental={
                        ATTESTATION_CAPABILITY_KEY: {
                            "verification_status": "failed",
                            "policy": "preferred",
                            "error": "Unknown issuer",
                        }
                    }
                ),
                serverInfo=types.Implementation(name="test-server", version="1.0.0"),
            )

        session.send_request = mock_send_request
        session.send_notification = AsyncMock()

        # Should not raise, just warn
        result = await session.initialize()

        assert result is not None
        assert session.attestation_verified is False

    @pytest.mark.asyncio
    async def test_initialize_sends_initialized_notification(self, mock_streams, attestation_setup):
        """Test that InitializedNotification is sent after successful init."""
        from attestation.mcp_client import AttestingClientSession
        import mcp.types as types

        read_stream, write_stream = mock_streams
        provider, identity, _ = attestation_setup

        session = AttestingClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://my-mcp-server.com",
        )

        async def mock_send_request(request, result_type, **kwargs):
            return types.InitializeResult(
                protocolVersion="2025-03-26",
                capabilities=types.ServerCapabilities(),
                serverInfo=types.Implementation(name="test-server", version="1.0.0"),
            )

        session.send_request = mock_send_request
        session.send_notification = AsyncMock()

        await session.initialize()

        # Verify InitializedNotification was sent
        session.send_notification.assert_called_once()
        notification = session.send_notification.call_args[0][0]
        assert isinstance(notification.root, types.InitializedNotification)


class TestCreateAttestingSession:
    """Tests for create_attesting_session convenience function."""

    @pytest.fixture
    def mock_streams(self):
        """Create mock read/write streams."""
        read_stream = AsyncMock()
        write_stream = AsyncMock()
        return read_stream, write_stream

    @pytest.fixture
    def attestation_setup(self):
        """Set up attestation provider and identity."""
        from attestation import AttestationProvider, AgentIdentity, KeyPair

        keypair = KeyPair.generate("test-key")
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

    @pytest.mark.asyncio
    async def test_create_attesting_session_returns_tuple(self, mock_streams, attestation_setup):
        """Test that function returns (session, result) tuple."""
        from attestation.mcp_client import create_attesting_session, AttestingClientSession
        import mcp.types as types

        read_stream, write_stream = mock_streams
        provider, identity = attestation_setup

        # Patch AttestingClientSession to mock initialize
        with patch.object(AttestingClientSession, "initialize") as mock_init:
            mock_result = types.InitializeResult(
                protocolVersion="2025-03-26",
                capabilities=types.ServerCapabilities(),
                serverInfo=types.Implementation(name="test-server", version="1.0.0"),
            )
            mock_init.return_value = mock_result

            session, result = await create_attesting_session(
                read_stream=read_stream,
                write_stream=write_stream,
                attestation_provider=provider,
                agent_identity=identity,
                target_audience="https://my-mcp-server.com",
            )

            assert isinstance(session, AttestingClientSession)
            assert result == mock_result
            mock_init.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
