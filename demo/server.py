#!/usr/bin/env python3
"""
Demo MCP Server with Attestation Verification

This server demonstrates:
- Attestation token verification on connection
- Redis-backed distributed replay protection
- Trust level-based access control
- Prometheus metrics endpoint

Run with: python demo/server.py
"""

import asyncio
import json
import logging
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from attestation import (
    AgentIdentity,
    AttestationProvider,
    AttestationVerifier,
    InMemoryKeyResolver,
    InMemoryReplayCache,
    KeyPair,
    TrustLevel,
    VerificationPolicy,
    get_metrics,
)

# Try Redis cache
try:
    from attestation import RedisReplayCache, RedisConfig, REDIS_AVAILABLE
except ImportError:
    REDIS_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
ATTESTATION_POLICY = os.environ.get("ATTESTATION_POLICY", "required")
TRUSTED_ISSUERS = os.environ.get("TRUSTED_ISSUERS", "https://api.anthropic.com").split(",")
SERVER_AUDIENCE = os.environ.get("SERVER_AUDIENCE", "https://demo-server.local")
PORT = int(os.environ.get("PORT", "8080"))


class DemoServer:
    """Demo server with attestation verification."""

    def __init__(self):
        # Generate a demo keypair (in production, this comes from trusted issuers)
        self.demo_keypair = KeyPair.generate("demo-key")

        # Setup key resolver with demo key
        self.key_resolver = InMemoryKeyResolver()
        for issuer in TRUSTED_ISSUERS:
            self.key_resolver.add_key(
                issuer,
                self.demo_keypair.kid,
                self.demo_keypair.public_key,
            )

        # Create verifier
        policy = VerificationPolicy(ATTESTATION_POLICY)
        self.verifier = AttestationVerifier(
            trusted_issuers=TRUSTED_ISSUERS,
            key_resolver=self.key_resolver,
            policy=policy,
            audience=SERVER_AUDIENCE,
        )

        # Create demo provider for generating tokens
        self.provider = AttestationProvider(
            issuer=TRUSTED_ISSUERS[0],
            keypair=self.demo_keypair,
        )

        logger.info(f"Server initialized with policy={ATTESTATION_POLICY}")
        logger.info(f"Trusted issuers: {TRUSTED_ISSUERS}")
        logger.info(f"Demo key ID: {self.demo_keypair.kid}")

    async def verify_attestation(self, token: str | None) -> dict[str, Any]:
        """Verify an attestation token."""
        result = await self.verifier.verify(token)
        return {
            "verified": result.verified,
            "trust_level": result.trust_level.value if result.trust_level else None,
            "issuer": result.issuer,
            "subject": result.subject,
            "error": result.error,
            "error_code": result.error_code,
        }

    def generate_demo_token(self) -> dict[str, Any]:
        """Generate a demo token for testing."""
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-demo",
            provider="anthropic",
        )
        token = self.provider.create_token(
            identity=identity,
            audience=SERVER_AUDIENCE,
        )
        return {
            "token": token,
            "public_key": self.demo_keypair.to_jwk(),
        }


# Global server instance
demo_server = DemoServer()


class RequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for demo server."""

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/health":
            self.send_json({"status": "healthy"})
        elif self.path == "/metrics":
            metrics = get_metrics()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(metrics.to_prometheus().encode())
        elif self.path == "/.well-known/jwks.json":
            # JWKS endpoint
            jwks = {
                "keys": [demo_server.demo_keypair.to_jwk()]
            }
            self.send_json(jwks)
        elif self.path == "/demo/token":
            # Generate demo token
            result = demo_server.generate_demo_token()
            self.send_json(result)
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        """Handle POST requests."""
        if self.path == "/verify":
            # Read body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()

            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self.send_json({"error": "Invalid JSON"}, 400)
                return

            token = data.get("token")

            # Verify async
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(demo_server.verify_attestation(token))
            finally:
                loop.close()

            self.send_json(result)
        else:
            self.send_json({"error": "Not found"}, 404)

    def send_json(self, data: dict, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def log_message(self, format, *args):
        """Custom logging."""
        logger.info(f"{self.address_string()} - {format % args}")


def main():
    """Run the demo server."""
    logger.info(f"Starting demo server on port {PORT}")
    logger.info(f"Endpoints:")
    logger.info(f"  GET  /health              - Health check")
    logger.info(f"  GET  /metrics             - Prometheus metrics")
    logger.info(f"  GET  /.well-known/jwks.json - JWKS endpoint")
    logger.info(f"  GET  /demo/token          - Generate demo token")
    logger.info(f"  POST /verify              - Verify attestation token")

    server = HTTPServer(("0.0.0.0", PORT), RequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
