"""
Tests for MCP Server Integration

Run with: pytest tests/test_mcp_server.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import sys

# Skip all tests if MCP not available
pytestmark = pytest.mark.skipif(
    "mcp" not in sys.modules and not pytest.importorskip("mcp", reason="MCP SDK not installed"),
    reason="MCP SDK not installed"
)


class TestAttestingServer:
    """Tests for AttestingServer class."""

    @pytest.fixture
    def mock_verifier(self):
        """Create mock verifier."""
        from attestation import VerificationPolicy, TrustLevel, VerificationResult

        verifier = MagicMock()
        verifier.policy = VerificationPolicy.REQUIRED
        verifier.trusted_issuers = ["https://api.anthropic.com"]
        verifier.required_claims = ["iss", "sub"]

        # Default to successful verification
        async def mock_verify(token):
            if token:
                return VerificationResult(
                    verified=True,
                    trust_level=TrustLevel.PROVIDER,
                    claims=MagicMock(iss="https://api.anthropic.com", sub="test-sub"),
                    error=None,
                )
            else:
                return VerificationResult(
                    verified=False,
                    trust_level=TrustLevel.NONE,
                    claims=None,
                    error="No token provided",
                )

        verifier.verify = mock_verify
        return verifier

    @pytest.fixture
    def mock_server(self):
        """Create mock MCP Server."""
        from mcp.server.lowlevel.server import Server, NotificationOptions
        import mcp.types as types

        server = MagicMock(spec=Server)
        server.get_capabilities.return_value = types.ServerCapabilities()
        server.create_initialization_options.return_value = MagicMock()
        return server

    def test_init_stores_server_and_verifier(self, mock_server, mock_verifier):
        """Test that init stores server and verifier."""
        from attestation.mcp_server import AttestingServer

        attesting = AttestingServer(mock_server, mock_verifier)

        assert attesting.server is mock_server
        assert attesting.verifier is mock_verifier

    def test_get_capabilities_includes_attestation(self, mock_server, mock_verifier):
        """Test that capabilities include attestation requirements."""
        from attestation.mcp_server import AttestingServer
        from attestation import ATTESTATION_CAPABILITY_KEY

        attesting = AttestingServer(mock_server, mock_verifier)
        attesting.get_capabilities()

        # Check that get_capabilities was called with attestation in experimental
        call_args = mock_server.get_capabilities.call_args
        exp_caps = call_args[0][1]  # Second positional arg

        assert ATTESTATION_CAPABILITY_KEY in exp_caps
        attestation_cap = exp_caps[ATTESTATION_CAPABILITY_KEY]
        assert attestation_cap["version"] == "0.1.0"
        assert attestation_cap["policy"] == "required"
        assert "https://api.anthropic.com" in attestation_cap["trusted_issuers"]

    def test_create_initialization_options_includes_attestation(self, mock_server, mock_verifier):
        """Test that init options include attestation requirements."""
        from attestation.mcp_server import AttestingServer
        from attestation import ATTESTATION_CAPABILITY_KEY

        attesting = AttestingServer(mock_server, mock_verifier)
        attesting.create_initialization_options()

        call_args = mock_server.create_initialization_options.call_args
        exp_caps = call_args[0][1]

        assert ATTESTATION_CAPABILITY_KEY in exp_caps

    def test_extract_attestation_token_from_session(self, mock_server, mock_verifier):
        """Test extracting token from session client params."""
        from attestation.mcp_server import AttestingServer
        from attestation import ATTESTATION_CAPABILITY_KEY
        import mcp.types as types

        attesting = AttestingServer(mock_server, mock_verifier)

        # Create mock session with attestation token
        session = MagicMock()
        session.client_params = MagicMock()
        session.client_params.capabilities = types.ClientCapabilities(
            experimental={
                ATTESTATION_CAPABILITY_KEY: {
                    "token": "test-token-123",
                }
            }
        )

        token = attesting._extract_attestation_token(session)
        assert token == "test-token-123"

    def test_extract_attestation_token_returns_none_when_missing(self, mock_server, mock_verifier):
        """Test that None is returned when no token present."""
        from attestation.mcp_server import AttestingServer

        attesting = AttestingServer(mock_server, mock_verifier)

        # Session without attestation
        session = MagicMock()
        session.client_params = MagicMock()
        session.client_params.capabilities = MagicMock()
        session.client_params.capabilities.experimental = None

        token = attesting._extract_attestation_token(session)
        assert token is None

    @pytest.mark.asyncio
    async def test_verify_session_attestation_success(self, mock_server, mock_verifier):
        """Test successful attestation verification."""
        from attestation.mcp_server import AttestingServer
        from attestation import ATTESTATION_CAPABILITY_KEY, TrustLevel
        import mcp.types as types

        attesting = AttestingServer(mock_server, mock_verifier)

        session = MagicMock()
        session.client_params = MagicMock()
        session.client_params.capabilities = types.ClientCapabilities(
            experimental={
                ATTESTATION_CAPABILITY_KEY: {"token": "valid-token"}
            }
        )

        context = await attesting.verify_session_attestation(session)

        assert context is not None
        assert context.verified is True
        assert context.trust_level == TrustLevel.PROVIDER

        # Context should be stored
        assert attesting.get_attestation_context(session) is context

    @pytest.mark.asyncio
    async def test_verify_session_attestation_required_policy_raises(self, mock_server, mock_verifier):
        """Test that REQUIRED policy raises on failure."""
        from attestation.mcp_server import AttestingServer
        import mcp.types as types

        attesting = AttestingServer(mock_server, mock_verifier)

        # Session without token
        session = MagicMock()
        session.client_params = MagicMock()
        session.client_params.capabilities = types.ClientCapabilities(experimental=None)

        with pytest.raises(PermissionError, match="Attestation required"):
            await attesting.verify_session_attestation(session)

    @pytest.mark.asyncio
    async def test_verify_session_attestation_preferred_policy_warns(self, mock_server, mock_verifier):
        """Test that PREFERRED policy warns but continues."""
        from attestation.mcp_server import AttestingServer
        from attestation import VerificationPolicy
        import mcp.types as types

        mock_verifier.policy = VerificationPolicy.PREFERRED
        attesting = AttestingServer(mock_server, mock_verifier)

        session = MagicMock()
        session.client_params = MagicMock()
        session.client_params.capabilities = types.ClientCapabilities(experimental=None)

        # Should not raise
        context = await attesting.verify_session_attestation(session)
        assert context.verified is False

    def test_cleanup_session_removes_context(self, mock_server, mock_verifier):
        """Test that cleanup removes session context."""
        from attestation.mcp_server import AttestingServer
        from attestation.protocol import AttestationContext
        from attestation import TrustLevel

        attesting = AttestingServer(mock_server, mock_verifier)

        session = MagicMock()
        context = AttestationContext(
            verified=True,
            trust_level=TrustLevel.PROVIDER,
            issuer="test",
        )
        attesting._session_contexts[id(session)] = context

        assert attesting.get_attestation_context(session) is context

        attesting.cleanup_session(session)

        assert attesting.get_attestation_context(session) is None

    def test_build_attestation_response_verified(self, mock_server, mock_verifier):
        """Test building response for verified attestation."""
        from attestation.mcp_server import AttestingServer
        from attestation import VerificationResult, TrustLevel

        attesting = AttestingServer(mock_server, mock_verifier)

        result = VerificationResult(
            verified=True,
            trust_level=TrustLevel.PROVIDER,
            claims=MagicMock(iss="https://api.anthropic.com", sub="test-sub"),
            error=None,
        )

        response = attesting.build_attestation_response(result)

        assert response["verification_status"] == "verified"
        assert response["trust_level"] == "provider"
        assert response["verified_claims"]["issuer"] == "https://api.anthropic.com"

    def test_build_attestation_response_failed(self, mock_server, mock_verifier):
        """Test building response for failed attestation."""
        from attestation.mcp_server import AttestingServer
        from attestation import VerificationResult, TrustLevel

        attesting = AttestingServer(mock_server, mock_verifier)

        result = VerificationResult(
            verified=False,
            trust_level=TrustLevel.NONE,
            claims=None,
            error="Invalid signature",
        )

        response = attesting.build_attestation_response(result)

        assert response["verification_status"] == "failed"
        assert response["error"] == "Invalid signature"


class TestRequireAttestationDecorator:
    """Tests for the require_attestation decorator."""

    @pytest.fixture
    def mock_verifier(self):
        """Create mock verifier."""
        from attestation import VerificationPolicy

        verifier = MagicMock()
        verifier.policy = VerificationPolicy.REQUIRED
        verifier.trusted_issuers = []
        verifier.required_claims = []
        return verifier

    @pytest.fixture
    def mock_server(self):
        """Create mock MCP Server."""
        from mcp.server.lowlevel.server import Server

        server = MagicMock(spec=Server)
        return server

    @pytest.mark.asyncio
    async def test_require_attestation_passes_when_verified(self, mock_server, mock_verifier):
        """Test that decorated function runs when attestation verified."""
        from attestation.mcp_server import AttestingServer
        from attestation.protocol import AttestationContext
        from attestation import TrustLevel

        attesting = AttestingServer(mock_server, mock_verifier)

        # Set up verified context
        session = MagicMock()
        context = AttestationContext(
            verified=True,
            trust_level=TrustLevel.PROVIDER,
            issuer="https://api.anthropic.com",
        )
        attesting._session_contexts[id(session)] = context

        # Mock request context
        mock_server.request_context = MagicMock()
        mock_server.request_context.session = session

        @attesting.require_attestation()
        async def my_handler():
            return "success"

        result = await my_handler()
        assert result == "success"

    @pytest.mark.asyncio
    async def test_require_attestation_fails_when_not_verified(self, mock_server, mock_verifier):
        """Test that decorated function raises when not verified."""
        from attestation.mcp_server import AttestingServer

        attesting = AttestingServer(mock_server, mock_verifier)

        session = MagicMock()
        # No context stored = not verified

        mock_server.request_context = MagicMock()
        mock_server.request_context.session = session

        @attesting.require_attestation()
        async def my_handler():
            return "success"

        with pytest.raises(PermissionError, match="not verified"):
            await my_handler()

    @pytest.mark.asyncio
    async def test_require_attestation_checks_trust_level(self, mock_server, mock_verifier):
        """Test trust level checking."""
        from attestation.mcp_server import AttestingServer
        from attestation.protocol import AttestationContext
        from attestation import TrustLevel

        attesting = AttestingServer(mock_server, mock_verifier)

        session = MagicMock()
        # Enterprise trust level (lower than provider)
        context = AttestationContext(
            verified=True,
            trust_level=TrustLevel.ENTERPRISE,
            issuer="https://enterprise.example.com",
        )
        attesting._session_contexts[id(session)] = context

        mock_server.request_context = MagicMock()
        mock_server.request_context.session = session

        @attesting.require_attestation(trust_level=TrustLevel.PROVIDER)
        async def my_handler():
            return "success"

        with pytest.raises(PermissionError, match="Insufficient trust level"):
            await my_handler()

    @pytest.mark.asyncio
    async def test_require_attestation_checks_issuer(self, mock_server, mock_verifier):
        """Test issuer checking."""
        from attestation.mcp_server import AttestingServer
        from attestation.protocol import AttestationContext
        from attestation import TrustLevel

        attesting = AttestingServer(mock_server, mock_verifier)

        session = MagicMock()
        context = AttestationContext(
            verified=True,
            trust_level=TrustLevel.PROVIDER,
            issuer="https://other-issuer.com",
        )
        attesting._session_contexts[id(session)] = context

        mock_server.request_context = MagicMock()
        mock_server.request_context.session = session

        @attesting.require_attestation(issuer="https://api.anthropic.com")
        async def my_handler():
            return "success"

        with pytest.raises(PermissionError, match="Required issuer"):
            await my_handler()

    @pytest.mark.asyncio
    async def test_require_attestation_custom_check(self, mock_server, mock_verifier):
        """Test custom check function."""
        from attestation.mcp_server import AttestingServer
        from attestation.protocol import AttestationContext
        from attestation import TrustLevel

        attesting = AttestingServer(mock_server, mock_verifier)

        session = MagicMock()
        context = AttestationContext(
            verified=True,
            trust_level=TrustLevel.PROVIDER,
            issuer="https://api.anthropic.com",
        )
        attesting._session_contexts[id(session)] = context

        mock_server.request_context = MagicMock()
        mock_server.request_context.session = session

        # Custom check that always fails
        @attesting.require_attestation(check=lambda ctx: False)
        async def my_handler():
            return "success"

        with pytest.raises(PermissionError, match="Custom attestation check failed"):
            await my_handler()


class TestCreateAttestingServer:
    """Tests for create_attesting_server function."""

    def test_creates_server_with_verifier(self):
        """Test that function creates properly configured server."""
        from attestation.mcp_server import create_attesting_server, AttestingServer
        from attestation import VerificationPolicy

        verifier = MagicMock()
        verifier.policy = VerificationPolicy.REQUIRED
        verifier.trusted_issuers = []
        verifier.required_claims = []

        attesting = create_attesting_server(
            name="test-server",
            verifier=verifier,
            version="1.0.0",
        )

        assert isinstance(attesting, AttestingServer)
        assert attesting.server.name == "test-server"
        assert attesting.verifier is verifier


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
