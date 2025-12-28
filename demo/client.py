#!/usr/bin/env python3
"""
Demo MCP Client with Attestation

This client demonstrates:
- Creating attestation tokens
- Sending tokens to server for verification
- Handling verification responses

Run with: python demo/client.py
"""

import json
import logging
import os
import time
import urllib.request
import urllib.error

from attestation import (
    AgentIdentity,
    AttestationProvider,
    KeyPair,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:8080")
ISSUER_URL = os.environ.get("ISSUER_URL", "https://demo-issuer.local")
TARGET_AUDIENCE = os.environ.get("TARGET_AUDIENCE", "https://demo-server.local")


def fetch_json(url: str, method: str = "GET", data: dict = None) -> dict:
    """Fetch JSON from URL."""
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")

    body = json.dumps(data).encode() if data else None

    try:
        with urllib.request.urlopen(req, body, timeout=10) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())
    except urllib.error.URLError as e:
        return {"error": str(e.reason)}


def wait_for_server(url: str, max_attempts: int = 30):
    """Wait for server to be ready."""
    logger.info(f"Waiting for server at {url}...")
    for i in range(max_attempts):
        try:
            result = fetch_json(f"{url}/health")
            if result.get("status") == "healthy":
                logger.info("Server is ready!")
                return True
        except Exception:
            pass
        time.sleep(1)
    logger.error("Server not ready after timeout")
    return False


def main():
    """Run the demo client."""
    print("=" * 60)
    print("MCP Agent Attestation - Demo Client")
    print("=" * 60)
    print()

    # Wait for server
    if not wait_for_server(SERVER_URL):
        return

    # Step 1: Get server's public key (JWKS)
    print("1. Fetching server's JWKS...")
    jwks = fetch_json(f"{SERVER_URL}/.well-known/jwks.json")
    print(f"   Server public key: {json.dumps(jwks, indent=2)}")
    print()

    # Step 2: Generate our own attestation (simulating provider)
    print("2. Generating attestation token...")

    # Create keypair (in production, this would be the provider's key)
    keypair = KeyPair.generate("client-demo-key")

    provider = AttestationProvider(
        issuer=ISSUER_URL,
        keypair=keypair,
    )

    identity = AgentIdentity(
        model_family="claude-4",
        model_version="claude-sonnet-4",
        provider="anthropic",
        deployment_id="demo-client",
    )

    token = provider.create_token(
        identity=identity,
        audience=TARGET_AUDIENCE,
    )

    print(f"   Token generated: {token[:50]}...")
    print()

    # Step 3: Get demo token from server (using server's key)
    print("3. Getting demo token from server...")
    demo_result = fetch_json(f"{SERVER_URL}/demo/token")
    demo_token = demo_result.get("token")
    print(f"   Demo token: {demo_token[:50]}...")
    print()

    # Step 4: Verify our token (will fail - unknown issuer)
    print("4. Verifying our token (expect failure - unknown issuer)...")
    result = fetch_json(f"{SERVER_URL}/verify", method="POST", data={"token": token})
    print(f"   Result: {json.dumps(result, indent=2)}")
    print()

    # Step 5: Verify demo token (should succeed)
    print("5. Verifying demo token (expect success)...")
    result = fetch_json(f"{SERVER_URL}/verify", method="POST", data={"token": demo_token})
    print(f"   Result: {json.dumps(result, indent=2)}")
    print()

    # Step 6: Replay attack (should fail)
    print("6. Attempting replay attack (expect failure)...")
    result = fetch_json(f"{SERVER_URL}/verify", method="POST", data={"token": demo_token})
    print(f"   Result: {json.dumps(result, indent=2)}")
    print()

    # Step 7: Check metrics
    print("7. Server metrics...")
    metrics_url = f"{SERVER_URL}/metrics"
    try:
        req = urllib.request.Request(metrics_url)
        with urllib.request.urlopen(req, timeout=5) as response:
            metrics = response.read().decode()
            # Show just key metrics
            for line in metrics.split("\n"):
                if line and not line.startswith("#"):
                    if any(k in line for k in ["verification", "replay", "total"]):
                        print(f"   {line}")
    except Exception as e:
        print(f"   Error fetching metrics: {e}")

    print()
    print("=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
