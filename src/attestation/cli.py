#!/usr/bin/env python3
"""
MCP Agent Attestation - CLI Tools

Command-line interface for generating, verifying, and inspecting attestation tokens.

Usage:
    python -m attestation.cli generate --issuer URL --audience URL
    python -m attestation.cli verify TOKEN
    python -m attestation.cli inspect TOKEN
    python -m attestation.cli keygen [--kid KEY_ID]

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
from datetime import datetime
from typing import Any

from .core import (
    ATTESTATION_VERSION,
    AgentIdentity,
    AgentIntegrity,
    AttestationMetadata,
    AttestationProvider,
    AttestationVerifier,
    InMemoryKeyResolver,
    KeyPair,
    SafetyLevel,
    TrustLevel,
    VerificationPolicy,
)


def decode_jwt_unsafe(token: str) -> dict[str, Any]:
    """Decode JWT without verification (for inspection only)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format: expected 3 parts")

    # Decode header
    header_b64 = parts[0]
    # Add padding
    header_b64 += "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))

    # Decode payload
    payload_b64 = parts[1]
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))

    return {"header": header, "payload": payload}


def format_timestamp(ts: int) -> str:
    """Format Unix timestamp as human-readable string."""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")


def cmd_generate(args: argparse.Namespace) -> int:
    """Generate an attestation token."""
    # Generate or load key
    if args.key_file:
        print(f"Loading key from {args.key_file}...", file=sys.stderr)
        with open(args.key_file) as f:
            jwk = json.load(f)
        kid = jwk.get("kid", "loaded-key")
        keypair = KeyPair.generate(kid)  # TODO: Import from JWK
        print("Warning: Key loading not fully implemented, generating new key", file=sys.stderr)
    else:
        kid = args.kid or f"cli-key-{datetime.now().strftime('%Y%m%d')}"
        keypair = KeyPair.generate(kid)

    # Create provider
    provider = AttestationProvider(
        issuer=args.issuer,
        keypair=keypair,
        token_lifetime=args.lifetime,
    )

    # Create identity
    identity = AgentIdentity(
        model_family=args.model_family,
        model_version=args.model_version,
        provider=args.provider_name,
        deployment_id=args.deployment_id,
    )

    # Create integrity if provided
    integrity = None
    if args.system_prompt:
        integrity = AgentIntegrity(
            system_prompt_hash=AgentIntegrity.compute_hash(args.system_prompt)
        )

    # Create metadata
    metadata = AttestationMetadata(
        attestation_version=ATTESTATION_VERSION,
        safety_level=args.safety_level,
        capabilities_declared=args.capabilities.split(",") if args.capabilities else [],
    )

    # Generate token
    token = provider.create_token(
        identity=identity,
        audience=args.audience,
        integrity=integrity,
        metadata=metadata,
    )

    if args.output == "token":
        print(token)
    elif args.output == "json":
        decoded = decode_jwt_unsafe(token)
        output = {
            "token": token,
            "decoded": decoded,
            "public_key": keypair.to_jwk(),
        }
        print(json.dumps(output, indent=2))
    elif args.output == "full":
        decoded = decode_jwt_unsafe(token)
        print("=" * 60)
        print("ATTESTATION TOKEN GENERATED")
        print("=" * 60)
        print(f"\nToken ({len(token)} chars):")
        print(token)
        print(f"\nPublic Key (JWK):")
        print(json.dumps(keypair.to_jwk(), indent=2))
        print(f"\nDecoded Header:")
        print(json.dumps(decoded["header"], indent=2))
        print(f"\nDecoded Payload:")
        print(json.dumps(decoded["payload"], indent=2))
        print(f"\nTimestamps:")
        print(f"  Issued:  {format_timestamp(decoded['payload']['iat'])}")
        print(f"  Expires: {format_timestamp(decoded['payload']['exp'])}")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify an attestation token."""
    token = args.token
    if token == "-":
        token = sys.stdin.read().strip()

    # For verification, we need the public key
    if not args.public_key:
        print("Error: --public-key is required for verification", file=sys.stderr)
        print("Use 'inspect' command to view token without verification", file=sys.stderr)
        return 1

    # Load public key
    with open(args.public_key) as f:
        jwk = json.load(f)

    # Decode token to get issuer
    try:
        decoded = decode_jwt_unsafe(token)
    except Exception as e:
        print(f"Error: Invalid token format: {e}", file=sys.stderr)
        return 1

    issuer = decoded["payload"].get("iss", "unknown")
    kid = decoded["header"].get("kid", "unknown")

    # Create key resolver with the provided key
    key_resolver = InMemoryKeyResolver()
    # For now, we'll regenerate a keypair and use its public key
    # In production, this would parse the JWK properly
    keypair = KeyPair.generate(kid)
    key_resolver.add_key(issuer, kid, keypair.public_key)

    # Create verifier
    verifier = AttestationVerifier(
        trusted_issuers=[issuer] if not args.trusted_issuers else args.trusted_issuers.split(","),
        key_resolver=key_resolver,
        policy=VerificationPolicy.REQUIRED,
        audience=args.audience,
    )

    # Verify
    result = asyncio.run(verifier.verify(token))

    if args.output == "json":
        output = {
            "verified": result.verified,
            "trust_level": result.trust_level.value if result.trust_level else None,
            "issuer": result.issuer,
            "subject": result.subject,
            "error": result.error,
            "error_code": result.error_code,
        }
        print(json.dumps(output, indent=2))
    else:
        if result.verified:
            print("✓ Token verified successfully")
            print(f"  Trust Level: {result.trust_level.value}")
            print(f"  Issuer: {result.issuer}")
            print(f"  Subject: {result.subject}")
            if result.claims:
                print(f"  Model: {result.claims.agent_identity.model_version}")
        else:
            print(f"✗ Verification failed: {result.error}")
            if result.error_code:
                print(f"  Error code: {result.error_code}")
            return 1

    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """Inspect a token without verification."""
    token = args.token
    if token == "-":
        token = sys.stdin.read().strip()

    try:
        decoded = decode_jwt_unsafe(token)
    except Exception as e:
        print(f"Error: Invalid token format: {e}", file=sys.stderr)
        return 1

    payload = decoded["payload"]

    if args.output == "json":
        print(json.dumps(decoded, indent=2))
    else:
        print("=" * 60)
        print("ATTESTATION TOKEN INSPECTION")
        print("=" * 60)
        print("\n⚠️  WARNING: Token signature NOT verified\n")

        print("Header:")
        print(json.dumps(decoded["header"], indent=2))

        print("\nStandard Claims:")
        print(f"  Issuer (iss):   {payload.get('iss', 'N/A')}")
        print(f"  Subject (sub):  {payload.get('sub', 'N/A')}")
        print(f"  Audience (aud): {payload.get('aud', 'N/A')}")
        print(f"  Token ID (jti): {payload.get('jti', 'N/A')}")

        print("\nTimestamps:")
        if "iat" in payload:
            print(f"  Issued At:  {format_timestamp(payload['iat'])}")
        if "exp" in payload:
            print(f"  Expires:    {format_timestamp(payload['exp'])}")
            # Check if expired
            import time
            if payload["exp"] < time.time():
                print("  ⚠️  TOKEN EXPIRED")
        if "nbf" in payload:
            print(f"  Not Before: {format_timestamp(payload['nbf'])}")

        if "agent_identity" in payload:
            ai = payload["agent_identity"]
            print("\nAgent Identity:")
            print(f"  Model Family:   {ai.get('model_family', 'N/A')}")
            print(f"  Model Version:  {ai.get('model_version', 'N/A')}")
            print(f"  Provider:       {ai.get('provider', 'N/A')}")
            if ai.get("deployment_id"):
                print(f"  Deployment ID:  {ai['deployment_id']}")

        if "attestation_metadata" in payload:
            am = payload["attestation_metadata"]
            print("\nAttestation Metadata:")
            print(f"  Version:      {am.get('attestation_version', 'N/A')}")
            print(f"  Type:         {am.get('attestation_type', 'N/A')}")
            print(f"  Safety Level: {am.get('safety_level', 'N/A')}")
            if am.get("capabilities_declared"):
                print(f"  Capabilities: {', '.join(am['capabilities_declared'])}")

        if "agent_integrity" in payload:
            ai = payload["agent_integrity"]
            print("\nAgent Integrity:")
            if ai.get("config_hash"):
                print(f"  Config Hash:        {ai['config_hash'][:40]}...")
            if ai.get("system_prompt_hash"):
                print(f"  System Prompt Hash: {ai['system_prompt_hash'][:40]}...")

    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a new Ed25519 key pair."""
    kid = args.kid or f"key-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    keypair = KeyPair.generate(kid)

    jwk = keypair.to_jwk()

    if args.output == "json":
        print(json.dumps(jwk, indent=2))
    else:
        print("=" * 60)
        print("ED25519 KEY PAIR GENERATED")
        print("=" * 60)
        print(f"\nKey ID: {kid}")
        print(f"\nPublic Key (JWK):")
        print(json.dumps(jwk, indent=2))
        print("\n⚠️  Store private key securely - it cannot be recovered!")

        if args.out_file:
            with open(args.out_file, "w") as f:
                json.dump(jwk, f, indent=2)
            print(f"\nPublic key saved to: {args.out_file}")

    return 0


def cmd_attack(args: argparse.Namespace) -> int:
    """Run attack simulation suite."""
    from .attacks import AttackSimulator, print_attack_report

    print("Running attack simulation suite...")
    print("=" * 60)

    simulator = AttackSimulator()
    results = asyncio.run(simulator.run_all_attacks())
    print_attack_report(results)

    # Return non-zero if any attack succeeded (which would be bad)
    attacks_blocked = sum(1 for r in results if not r.success)
    attacks_total = len(results)

    if attacks_blocked == attacks_total:
        print(f"\n✓ All {attacks_total} attacks blocked successfully")
        return 0
    else:
        print(f"\n⚠️  {attacks_total - attacks_blocked}/{attacks_total} attacks succeeded (security issue!)")
        return 1


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="attestation",
        description="MCP Agent Attestation CLI Tools",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate an attestation token")
    gen_parser.add_argument("--issuer", "-i", required=True, help="Issuer URL")
    gen_parser.add_argument("--audience", "-a", required=True, help="Target audience URL")
    gen_parser.add_argument("--model-family", default="claude-4", help="Model family (default: claude-4)")
    gen_parser.add_argument("--model-version", default="claude-sonnet-4", help="Model version")
    gen_parser.add_argument("--provider-name", default="anthropic", help="Provider name")
    gen_parser.add_argument("--deployment-id", help="Deployment identifier")
    gen_parser.add_argument("--lifetime", type=int, default=300, help="Token lifetime in seconds (default: 300)")
    gen_parser.add_argument("--safety-level", default="standard", choices=["standard", "enhanced", "minimal"])
    gen_parser.add_argument("--capabilities", help="Comma-separated capabilities")
    gen_parser.add_argument("--system-prompt", help="System prompt to hash for integrity")
    gen_parser.add_argument("--kid", help="Key ID for generated key")
    gen_parser.add_argument("--key-file", help="Path to private key JWK file")
    gen_parser.add_argument("--output", "-o", default="token", choices=["token", "json", "full"])

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify an attestation token")
    verify_parser.add_argument("token", help="Token to verify (or - for stdin)")
    verify_parser.add_argument("--public-key", "-k", help="Path to public key JWK file")
    verify_parser.add_argument("--audience", "-a", help="Expected audience")
    verify_parser.add_argument("--trusted-issuers", help="Comma-separated trusted issuers")
    verify_parser.add_argument("--output", "-o", default="text", choices=["text", "json"])

    # Inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a token without verification")
    inspect_parser.add_argument("token", help="Token to inspect (or - for stdin)")
    inspect_parser.add_argument("--output", "-o", default="text", choices=["text", "json"])

    # Keygen command
    keygen_parser = subparsers.add_parser("keygen", help="Generate Ed25519 key pair")
    keygen_parser.add_argument("--kid", help="Key ID (default: auto-generated)")
    keygen_parser.add_argument("--out-file", "-o", help="Output file for public key JWK")
    keygen_parser.add_argument("--output", default="text", choices=["text", "json"])

    # Attack command
    attack_parser = subparsers.add_parser("attack", help="Run attack simulation suite")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "generate": cmd_generate,
        "verify": cmd_verify,
        "inspect": cmd_inspect,
        "keygen": cmd_keygen,
        "attack": cmd_attack,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
