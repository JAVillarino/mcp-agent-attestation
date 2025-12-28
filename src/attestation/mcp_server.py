"""
MCP Agent Attestation - Server Integration

Provides AttestingServer wrapper that verifies attestation tokens
from connecting clients during the MCP initialize handshake.

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from functools import wraps
from typing import Any, AsyncIterator, Callable, Awaitable, TypeVar

try:
    import mcp.types as types
    from mcp.server.lowlevel.server import Server, NotificationOptions
    from mcp.server.session import ServerSession
    from mcp.server.models import InitializationOptions

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    Server = object  # type: ignore
    types = None  # type: ignore

from .core import (
    ATTESTATION_CAPABILITY_KEY,
    AttestationVerifier,
    TrustLevel,
    VerificationPolicy,
    VerificationResult,
)
from .protocol import AttestationContext

logger = logging.getLogger(__name__)

T = TypeVar("T")


class AttestingServer:
    """
    MCP Server wrapper with attestation verification.

    This class wraps an MCP Server instance to add attestation verification
    during the initialize handshake. It stores attestation contexts per session
    and provides decorators for protecting tools/resources.

    Usage:
        from mcp.server.lowlevel.server import Server
        from attestation import AttestationVerifier, InMemoryKeyResolver, VerificationPolicy
        from attestation.mcp_server import AttestingServer

        # Create base server
        server = Server("my-server")

        # Set up verifier
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=key_resolver,
            policy=VerificationPolicy.REQUIRED,
        )

        # Wrap with attestation
        attesting_server = AttestingServer(server, verifier)

        # Register handlers on the attesting server
        @attesting_server.list_tools()
        async def list_tools():
            return [...]

        # Protect specific tools
        @attesting_server.call_tool()
        @attesting_server.require_attestation(trust_level=TrustLevel.PROVIDER)
        async def call_tool(name, arguments):
            return [...]
    """

    def __init__(
        self,
        server: Server,
        verifier: AttestationVerifier,
    ):
        """
        Initialize attestation server wrapper.

        Args:
            server: Base MCP Server instance
            verifier: AttestationVerifier for validating tokens
        """
        if not MCP_AVAILABLE:
            raise RuntimeError(
                "MCP SDK not installed. Install with: pip install mcp-agent-attestation[mcp]"
            )

        self._server = server
        self._verifier = verifier
        self._session_contexts: dict[int, AttestationContext] = {}

    @property
    def server(self) -> Server:
        """Access the underlying MCP Server instance."""
        return self._server

    @property
    def verifier(self) -> AttestationVerifier:
        """Access the attestation verifier."""
        return self._verifier

    def get_capabilities(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> types.ServerCapabilities:
        """
        Get server capabilities with attestation requirements.

        This injects the server's attestation requirements into the
        experimental capabilities so clients know what's expected.

        Args:
            notification_options: Standard notification options
            experimental_capabilities: Additional experimental caps

        Returns:
            ServerCapabilities with attestation requirements
        """
        exp_caps = experimental_capabilities.copy() if experimental_capabilities else {}
        exp_caps[ATTESTATION_CAPABILITY_KEY] = {
            "version": "0.1.0",
            "policy": self._verifier.policy.value,
            "trusted_issuers": list(self._verifier.trusted_issuers),
            "required_claims": list(self._verifier.required_claims),
        }
        return self._server.get_capabilities(
            notification_options or NotificationOptions(),
            exp_caps,
        )

    def create_initialization_options(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        """
        Create initialization options with attestation requirements.

        Args:
            notification_options: Standard notification options
            experimental_capabilities: Additional experimental caps

        Returns:
            InitializationOptions for server.run()
        """
        exp_caps = experimental_capabilities.copy() if experimental_capabilities else {}
        exp_caps[ATTESTATION_CAPABILITY_KEY] = {
            "version": "0.1.0",
            "policy": self._verifier.policy.value,
            "trusted_issuers": list(self._verifier.trusted_issuers),
            "required_claims": list(self._verifier.required_claims),
        }
        return self._server.create_initialization_options(
            notification_options,
            exp_caps,
        )

    async def verify_session_attestation(
        self,
        session: ServerSession,
    ) -> AttestationContext:
        """
        Verify attestation for a session after initialization.

        This should be called after the session's initialize request
        has been processed, when client_params is available.

        Args:
            session: ServerSession to verify

        Returns:
            AttestationContext with verification results

        Raises:
            PermissionError: If policy is REQUIRED and verification fails
        """
        token = self._extract_attestation_token(session)
        result = await self._verifier.verify(token)

        context = AttestationContext.from_verification_result(result)

        # Store context keyed by session id
        self._session_contexts[id(session)] = context

        if not result.verified:
            if self._verifier.policy == VerificationPolicy.REQUIRED:
                error_msg = f"Attestation required: {result.error}"
                logger.error(error_msg)
                raise PermissionError(error_msg)
            elif self._verifier.policy == VerificationPolicy.PREFERRED:
                logger.warning(f"Attestation failed (preferred policy): {result.error}")
            else:
                logger.debug(f"Attestation not provided (optional policy)")
        else:
            logger.info(
                f"Attestation verified: trust_level={result.trust_level.value}, "
                f"issuer={result.claims.iss if result.claims else 'unknown'}"
            )

        return context

    def _extract_attestation_token(self, session: ServerSession) -> str | None:
        """
        Extract attestation token from session's client params.

        Args:
            session: ServerSession with client_params

        Returns:
            Token string or None if not present
        """
        try:
            if session.client_params and session.client_params.capabilities.experimental:
                attestation_cap = session.client_params.capabilities.experimental.get(
                    ATTESTATION_CAPABILITY_KEY, {}
                )
                return attestation_cap.get("token")
        except (AttributeError, TypeError) as e:
            logger.debug(f"Failed to extract attestation token: {e}")
        return None

    def get_attestation_context(self, session: ServerSession) -> AttestationContext | None:
        """
        Get attestation context for a session.

        Args:
            session: ServerSession to look up

        Returns:
            AttestationContext or None if not verified
        """
        return self._session_contexts.get(id(session))

    def cleanup_session(self, session: ServerSession):
        """
        Clean up attestation context for a session.

        Call this when a session ends to prevent memory leaks.

        Args:
            session: ServerSession that has ended
        """
        session_id = id(session)
        if session_id in self._session_contexts:
            del self._session_contexts[session_id]
            logger.debug(f"Cleaned up attestation context for session {session_id}")

    def require_attestation(
        self,
        trust_level: TrustLevel | None = None,
        issuer: str | None = None,
        check: Callable[[AttestationContext], bool] | None = None,
    ):
        """
        Decorator to require attestation for a handler.

        Args:
            trust_level: Minimum required trust level
            issuer: Required issuer
            check: Custom validation function

        Returns:
            Decorator function

        Usage:
            @attesting_server.require_attestation(trust_level=TrustLevel.PROVIDER)
            async def my_handler(name, arguments):
                return [...]
        """

        def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Get current session from request context
                ctx = self._server.request_context
                session = ctx.session

                attestation = self.get_attestation_context(session)

                if attestation is None or not attestation.verified:
                    raise PermissionError("Attestation required but not verified")

                if trust_level is not None:
                    if attestation.trust_level.value < trust_level.value:
                        raise PermissionError(
                            f"Insufficient trust level: {attestation.trust_level.value} < {trust_level.value}"
                        )

                if issuer is not None:
                    if attestation.issuer != issuer:
                        raise PermissionError(
                            f"Required issuer '{issuer}', got '{attestation.issuer}'"
                        )

                if check is not None:
                    if not check(attestation):
                        raise PermissionError("Custom attestation check failed")

                return await func(*args, **kwargs)

            return wrapper

        return decorator

    def build_attestation_response(
        self,
        result: VerificationResult,
    ) -> dict[str, Any]:
        """
        Build attestation response for include in server capabilities.

        Args:
            result: Verification result

        Returns:
            Dict to include in experimental capabilities response
        """
        response: dict[str, Any] = {
            "version": "0.1.0",
            "policy": self._verifier.policy.value,
        }

        if result.verified:
            response["verification_status"] = "verified"
            response["trust_level"] = result.trust_level.value
            if result.claims:
                response["verified_claims"] = {
                    "issuer": result.claims.iss,
                    "subject": result.claims.sub,
                }
        else:
            response["verification_status"] = "failed"
            response["error"] = result.error or "Unknown error"

        return response

    # Delegate common decorators to underlying server
    def list_tools(self):
        """Decorator for listing tools."""
        return self._server.list_tools()

    def call_tool(self, **kwargs):
        """Decorator for handling tool calls."""
        return self._server.call_tool(**kwargs)

    def list_resources(self):
        """Decorator for listing resources."""
        return self._server.list_resources()

    def read_resource(self):
        """Decorator for reading resources."""
        return self._server.read_resource()

    def list_prompts(self):
        """Decorator for listing prompts."""
        return self._server.list_prompts()

    def get_prompt(self):
        """Decorator for getting prompts."""
        return self._server.get_prompt()

    def list_resource_templates(self):
        """Decorator for listing resource templates."""
        return self._server.list_resource_templates()

    def completion(self):
        """Decorator for completions."""
        return self._server.completion()


@asynccontextmanager
async def attesting_lifespan(
    attesting_server: AttestingServer,
) -> AsyncIterator[dict[str, Any]]:
    """
    Lifespan context manager for attestation verification.

    This is a factory that creates a lifespan for use with MCP servers.
    The actual verification happens when verify_session_attestation is called.

    Usage:
        server = Server("my-server", lifespan=lambda s: attesting_lifespan(attesting_server))

    Args:
        attesting_server: AttestingServer instance

    Yields:
        Empty context dict
    """
    # Lifespan runs before session is available
    # Actual verification happens in verify_session_attestation
    yield {"attesting_server": attesting_server}


def create_attesting_server(
    name: str,
    verifier: AttestationVerifier,
    version: str | None = None,
    instructions: str | None = None,
    **server_kwargs,
) -> AttestingServer:
    """
    Convenience function to create an attesting server.

    Args:
        name: Server name
        verifier: AttestationVerifier instance
        version: Server version
        instructions: Server instructions
        **server_kwargs: Additional arguments for Server

    Returns:
        AttestingServer instance

    Usage:
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=key_resolver,
            policy=VerificationPolicy.REQUIRED,
        )

        attesting_server = create_attesting_server(
            name="my-server",
            verifier=verifier,
            version="1.0.0",
        )
    """
    if not MCP_AVAILABLE:
        raise RuntimeError(
            "MCP SDK not installed. Install with: pip install mcp-agent-attestation[mcp]"
        )

    server = Server(
        name=name,
        version=version,
        instructions=instructions,
        **server_kwargs,
    )
    return AttestingServer(server, verifier)
