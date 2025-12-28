"""
MCP Agent Attestation - Client Integration

Provides AttestingClientSession, a subclass of MCP SDK's ClientSession
that automatically injects attestation tokens during initialization.

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

try:
    import mcp.types as types
    from mcp.client.session import (
        ClientSession,
        ElicitationFnT,
        ListRootsFnT,
        LoggingFnT,
        MessageHandlerFnT,
        SamplingFnT,
        _default_elicitation_callback,
        _default_list_roots_callback,
        _default_logging_callback,
        _default_message_handler,
        _default_sampling_callback,
    )
    from mcp.client.experimental.task_handlers import ExperimentalTaskHandlers
    from mcp.shared.message import SessionMessage
    from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    # Provide stubs for type hints when MCP not installed
    ClientSession = object  # type: ignore
    types = None  # type: ignore

from .core import (
    ATTESTATION_CAPABILITY_KEY,
    AgentIdentity,
    AgentIntegrity,
    AttestationMetadata,
    AttestationProvider,
)

logger = logging.getLogger(__name__)


class AttestingClientSession(ClientSession):  # type: ignore[misc]
    """
    MCP ClientSession with automatic attestation token injection.

    This subclass extends the standard MCP ClientSession to inject
    attestation tokens into the experimental capabilities during
    the initialize handshake.

    Usage:
        from attestation import AttestationProvider, AgentIdentity, KeyPair
        from attestation.mcp_client import AttestingClientSession

        # Set up attestation
        keypair = KeyPair.generate("my-key")
        provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=keypair,
        )
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-20250514",
            provider="anthropic",
        )

        # Create session with attestation
        session = AttestingClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            attestation_provider=provider,
            agent_identity=identity,
            target_audience="https://my-mcp-server.com",
        )

        # Initialize will automatically include attestation
        result = await session.initialize()
    """

    def __init__(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        attestation_provider: AttestationProvider,
        agent_identity: AgentIdentity,
        target_audience: str,
        agent_integrity: AgentIntegrity | None = None,
        attestation_metadata: AttestationMetadata | None = None,
        # Standard ClientSession args
        read_timeout_seconds: timedelta | None = None,
        sampling_callback: SamplingFnT | None = None,
        elicitation_callback: ElicitationFnT | None = None,
        list_roots_callback: ListRootsFnT | None = None,
        logging_callback: LoggingFnT | None = None,
        message_handler: MessageHandlerFnT | None = None,
        client_info: types.Implementation | None = None,
        sampling_capabilities: types.SamplingCapability | None = None,
        experimental_task_handlers: ExperimentalTaskHandlers | None = None,
    ):
        """
        Initialize an attesting client session.

        Args:
            read_stream: Stream to read messages from server
            write_stream: Stream to write messages to server
            attestation_provider: Provider for creating attestation tokens
            agent_identity: Identity claims for the agent
            target_audience: URL of the target MCP server (used as audience claim)
            agent_integrity: Optional integrity hashes
            attestation_metadata: Optional attestation metadata
            **kwargs: Additional arguments passed to ClientSession
        """
        if not MCP_AVAILABLE:
            raise RuntimeError(
                "MCP SDK not installed. Install with: pip install mcp-agent-attestation[mcp]"
            )

        super().__init__(
            read_stream=read_stream,
            write_stream=write_stream,
            read_timeout_seconds=read_timeout_seconds,
            sampling_callback=sampling_callback,
            elicitation_callback=elicitation_callback,
            list_roots_callback=list_roots_callback,
            logging_callback=logging_callback,
            message_handler=message_handler,
            client_info=client_info,
            sampling_capabilities=sampling_capabilities,
            experimental_task_handlers=experimental_task_handlers,
        )

        self._attestation_provider = attestation_provider
        self._agent_identity = agent_identity
        self._target_audience = target_audience
        self._agent_integrity = agent_integrity
        self._attestation_metadata = attestation_metadata or AttestationMetadata()

        # Track server's attestation verification response
        self._server_attestation_status: dict[str, Any] | None = None

    def _create_attestation_token(self) -> str:
        """Create attestation token for the target server."""
        return self._attestation_provider.create_token(
            identity=self._agent_identity,
            audience=self._target_audience,
            integrity=self._agent_integrity,
            metadata=self._attestation_metadata,
        )

    def _build_attestation_capability(self) -> dict[str, Any]:
        """Build attestation capability dict for experimental capabilities."""
        return {
            "version": "0.1.0",
            "token": self._create_attestation_token(),
            "supported_algorithms": ["EdDSA"],
            "attestation_types": ["provider", "enterprise"],
        }

    async def initialize(self) -> types.InitializeResult:
        """
        Initialize the session with attestation token.

        This overrides the parent initialize() to inject attestation
        into the experimental capabilities.

        Returns:
            InitializeResult from the server

        Raises:
            RuntimeError: If protocol version not supported or attestation fails
        """
        # Build standard capabilities (same logic as parent)
        sampling = (
            (self._sampling_capabilities or types.SamplingCapability())
            if self._sampling_callback is not _default_sampling_callback
            else None
        )
        elicitation = (
            types.ElicitationCapability(
                form=types.FormElicitationCapability(),
                url=types.UrlElicitationCapability(),
            )
            if self._elicitation_callback is not _default_elicitation_callback
            else None
        )
        roots = (
            types.RootsCapability(listChanged=True)
            if self._list_roots_callback is not _default_list_roots_callback
            else None
        )

        # Build experimental capabilities with attestation
        experimental: dict[str, dict[str, Any]] = {
            ATTESTATION_CAPABILITY_KEY: self._build_attestation_capability()
        }

        logger.info(f"Initializing with attestation for audience: {self._target_audience}")

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

        # Verify protocol version
        if result.protocolVersion not in SUPPORTED_PROTOCOL_VERSIONS:
            raise RuntimeError(
                f"Unsupported protocol version from server: {result.protocolVersion}"
            )

        self._server_capabilities = result.capabilities

        # Check attestation verification status in server response
        self._check_attestation_response(result)

        # Send initialized notification
        await self.send_notification(
            types.ClientNotification(types.InitializedNotification())
        )

        return result

    def _check_attestation_response(self, result: types.InitializeResult):
        """
        Check server's attestation verification response.

        Args:
            result: Initialize result from server

        Raises:
            RuntimeError: If attestation was rejected by server
        """
        if result.capabilities and result.capabilities.experimental:
            attestation_response = result.capabilities.experimental.get(
                ATTESTATION_CAPABILITY_KEY, {}
            )
            self._server_attestation_status = attestation_response

            status = attestation_response.get("verification_status")
            if status == "failed":
                error = attestation_response.get("error", "Unknown error")
                policy = attestation_response.get("policy", "unknown")
                logger.error(f"Attestation verification failed: {error}")
                if policy == "required":
                    raise RuntimeError(f"Attestation verification failed: {error}")
                else:
                    logger.warning(f"Attestation failed but policy is '{policy}', continuing")
            elif status == "verified":
                trust_level = attestation_response.get("trust_level", "unknown")
                logger.info(f"Attestation verified with trust level: {trust_level}")

    @property
    def attestation_status(self) -> dict[str, Any] | None:
        """
        Get the server's attestation verification status.

        Returns:
            Dict with verification_status, trust_level, etc. or None if not initialized
        """
        return self._server_attestation_status

    @property
    def attestation_verified(self) -> bool:
        """
        Check if attestation was verified by the server.

        Returns:
            True if verified, False otherwise
        """
        if not self._server_attestation_status:
            return False
        return self._server_attestation_status.get("verification_status") == "verified"


# Convenience function for creating attesting sessions
async def create_attesting_session(
    read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
    write_stream: MemoryObjectSendStream[SessionMessage],
    attestation_provider: AttestationProvider,
    agent_identity: AgentIdentity,
    target_audience: str,
    **kwargs,
) -> tuple[AttestingClientSession, types.InitializeResult]:
    """
    Create and initialize an attesting client session.

    This is a convenience function that creates an AttestingClientSession
    and calls initialize() on it.

    Args:
        read_stream: Stream to read messages from server
        write_stream: Stream to write messages to server
        attestation_provider: Provider for creating attestation tokens
        agent_identity: Identity claims for the agent
        target_audience: URL of the target MCP server
        **kwargs: Additional arguments for AttestingClientSession

    Returns:
        Tuple of (session, initialize_result)

    Usage:
        async with create_attesting_session(...) as (session, result):
            # Use session
            tools = await session.list_tools()
    """
    session = AttestingClientSession(
        read_stream=read_stream,
        write_stream=write_stream,
        attestation_provider=attestation_provider,
        agent_identity=agent_identity,
        target_audience=target_audience,
        **kwargs,
    )
    result = await session.initialize()
    return session, result
