"""
MCP Agent Attestation - Attack Simulations

This module demonstrates various attack scenarios and how
attestation prevents them.

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .core import (
    AgentIdentity,
    AttestationMetadata,
    AttestationProvider,
    AttestationVerifier,
    KeyPair,
    VerificationPolicy,
    create_anthropic_provider,
    create_test_verifier,
)

# =============================================================================
# ATTACK TYPES
# =============================================================================


class AttackType(str, Enum):
    """Categories of attacks the attestation system defends against."""

    MODEL_SPOOFING = "model_spoofing"
    PROVENANCE_FORGERY = "provenance_forgery"
    TOKEN_REPLAY = "token_replay"
    TOKEN_TAMPERING = "token_tampering"
    ISSUER_SPOOFING = "issuer_spoofing"
    DOWNGRADE_ATTACK = "downgrade_attack"
    AUDIENCE_MISMATCH = "audience_mismatch"
    SAFETY_DOWNGRADE = "safety_downgrade"


@dataclass
class AttackResult:
    """Result of an attack simulation."""

    attack_type: AttackType
    attack_name: str
    description: str
    blocked: bool
    error_message: str | None
    details: dict[str, Any]


# =============================================================================
# ATTACK SIMULATOR
# =============================================================================


class AttackSimulator:
    """
    Simulates various attack scenarios against the attestation system.
    """

    def __init__(self):
        self.provider, self.keypair = create_anthropic_provider()
        self.verifier = create_test_verifier(self.keypair, VerificationPolicy.REQUIRED)

        self.legit_identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-20250514",
            provider="anthropic",
        )

        self.server_url = "https://mcp-server.example.com"

    async def run_all_attacks(self) -> list[AttackResult]:
        """Run all attack simulations."""
        attacks = [
            self.attack_model_spoofing,
            self.attack_provenance_forgery,
            self.attack_token_replay,
            self.attack_token_tampering,
            self.attack_issuer_spoofing,
            self.attack_downgrade,
            self.attack_audience_mismatch,
            self.attack_safety_downgrade,
        ]

        results = []
        for attack in attacks:
            result = await attack()
            results.append(result)

        return results

    async def attack_model_spoofing(self) -> AttackResult:
        """
        Attack: Attacker claims to be Claude but uses their own signing key.
        Defense: Signature verification fails - unknown key.
        """
        attacker_keypair = KeyPair.generate("attacker-key")
        attacker_provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=attacker_keypair,
        )

        fake_identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-20250514",
            provider="anthropic",
        )

        fake_token = attacker_provider.create_token(
            identity=fake_identity,
            audience=self.server_url,
        )

        result = await self.verifier.verify(fake_token)

        return AttackResult(
            attack_type=AttackType.MODEL_SPOOFING,
            attack_name="Model Spoofing",
            description="Attacker claims to be Claude using forged token",
            blocked=not result.verified,
            error_message=result.error,
            details={"attacker_claimed": "claude-sonnet-4", "reason": "Unknown signing key"},
        )

    async def attack_provenance_forgery(self) -> AttackResult:
        """
        Attack: Token from untrusted issuer.
        Defense: Issuer not in trusted list.
        """
        attacker_keypair = KeyPair.generate("malicious-provider")
        attacker_provider = AttestationProvider(
            issuer="https://evil-llm-provider.com",
            keypair=attacker_keypair,
        )

        fake_token = attacker_provider.create_token(
            identity=self.legit_identity,
            audience=self.server_url,
        )

        result = await self.verifier.verify(fake_token)

        return AttackResult(
            attack_type=AttackType.PROVENANCE_FORGERY,
            attack_name="Provenance Forgery",
            description="Token from untrusted issuer",
            blocked=not result.verified,
            error_message=result.error,
            details={
                "attacker_issuer": "https://evil-llm-provider.com",
                "trusted_issuers": self.verifier.trusted_issuers,
            },
        )

    async def attack_token_replay(self) -> AttackResult:
        """
        Attack: Replay captured token.
        Defense: JTI cache detects replay.
        """
        legit_token = self.provider.create_token(
            identity=self.legit_identity,
            audience=self.server_url,
        )

        first_result = await self.verifier.verify(legit_token)
        first_success = first_result.verified

        replay_result = await self.verifier.verify(legit_token)
        replay_blocked = not replay_result.verified

        return AttackResult(
            attack_type=AttackType.TOKEN_REPLAY,
            attack_name="Token Replay",
            description="Attacker replays intercepted token",
            blocked=replay_blocked,
            error_message=replay_result.error if replay_blocked else None,
            details={
                "first_use_success": first_success,
                "replay_blocked": replay_blocked,
            },
        )

    async def attack_token_tampering(self) -> AttackResult:
        """
        Attack: Modify token claims after signing.
        Defense: Signature verification fails.
        """
        legit_token = self.provider.create_token(
            identity=self.legit_identity,
            audience=self.server_url,
        )

        parts = legit_token.split(".")
        payload_json = base64.urlsafe_b64decode(parts[1] + "==")
        payload = json.loads(payload_json)

        # Extend expiration
        payload["exp"] = int(time.time()) + 86400 * 365

        tampered_payload = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )

        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        result = await self.verifier.verify(tampered_token)

        return AttackResult(
            attack_type=AttackType.TOKEN_TAMPERING,
            attack_name="Token Tampering",
            description="Attacker modifies token claims without re-signing",
            blocked=not result.verified,
            error_message=result.error,
            details={
                "modification": "Extended expiration by 1 year",
            },
        )

    async def attack_issuer_spoofing(self) -> AttackResult:
        """
        Attack: Typosquatted issuer domain.
        Defense: Strict issuer allowlist.
        """
        attacker_keypair = KeyPair.generate("typosquat-key")
        attacker_provider = AttestationProvider(
            issuer="https://api.anthropic.org",  # .org instead of .com
            keypair=attacker_keypair,
        )

        fake_token = attacker_provider.create_token(
            identity=self.legit_identity,
            audience=self.server_url,
        )

        result = await self.verifier.verify(fake_token)

        return AttackResult(
            attack_type=AttackType.ISSUER_SPOOFING,
            attack_name="Issuer Typosquatting",
            description="Attacker uses similar-looking issuer domain",
            blocked=not result.verified,
            error_message=result.error,
            details={
                "fake_issuer": "https://api.anthropic.org",
                "real_issuer": "https://api.anthropic.com",
            },
        )

    async def attack_downgrade(self) -> AttackResult:
        """
        Attack: Omit attestation entirely.
        Defense: REQUIRED policy rejects.
        """
        required_verifier = create_test_verifier(self.keypair, VerificationPolicy.REQUIRED)
        result = await required_verifier.verify(None)

        return AttackResult(
            attack_type=AttackType.DOWNGRADE_ATTACK,
            attack_name="Downgrade Attack",
            description="Attacker omits attestation entirely",
            blocked=not result.verified,
            error_message=result.error,
            details={
                "policy": "REQUIRED",
                "token_provided": False,
            },
        )

    async def attack_audience_mismatch(self) -> AttackResult:
        """
        Attack: Use token for different server.
        Defense: Audience validation.
        """
        audience_verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=self.verifier.key_resolver,
            policy=VerificationPolicy.REQUIRED,
            audience="https://server-b.example.com",
        )

        token_for_server_a = self.provider.create_token(
            identity=self.legit_identity,
            audience="https://server-a.example.com",
        )

        result = await audience_verifier.verify(token_for_server_a)

        return AttackResult(
            attack_type=AttackType.AUDIENCE_MISMATCH,
            attack_name="Audience Mismatch",
            description="Token intended for different server",
            blocked=not result.verified,
            error_message=result.error,
            details={
                "token_audience": "https://server-a.example.com",
                "server_identity": "https://server-b.example.com",
            },
        )

    async def attack_safety_downgrade(self) -> AttackResult:
        """
        Attack: Modify safety level in token.
        Defense: Signature verification (reduces to tampering).
        """
        legit_token = self.provider.create_token(
            identity=self.legit_identity,
            audience=self.server_url,
            metadata=AttestationMetadata(safety_level="enhanced"),
        )

        parts = legit_token.split(".")
        payload_json = base64.urlsafe_b64decode(parts[1] + "==")
        payload = json.loads(payload_json)
        payload["attestation_metadata"]["safety_level"] = "minimal"

        tampered_payload = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        result = await self.verifier.verify(tampered_token)

        return AttackResult(
            attack_type=AttackType.SAFETY_DOWNGRADE,
            attack_name="Safety Level Downgrade",
            description="Attacker modifies safety level claim",
            blocked=not result.verified,
            error_message=result.error,
            details={
                "original_safety": "enhanced",
                "attempted_safety": "minimal",
            },
        )


# =============================================================================
# REPORT GENERATION
# =============================================================================


def print_attack_report(results: list[AttackResult]):
    """Print formatted attack simulation report."""
    print("\n" + "=" * 70)
    print("MCP AGENT ATTESTATION - ATTACK SIMULATION REPORT")
    print("=" * 70)

    blocked_count = sum(1 for r in results if r.blocked)
    total_count = len(results)

    print(f"\nSummary: {blocked_count}/{total_count} attacks blocked")
    print("-" * 70)

    for i, result in enumerate(results, 1):
        status = "✅ BLOCKED" if result.blocked else "❌ NOT BLOCKED"
        print(f"\n[{i}] {result.attack_name}")
        print(f"    Type: {result.attack_type.value}")
        print(f"    Status: {status}")
        print(f"    Description: {result.description}")

        if result.error_message:
            print(f"    Error: {result.error_message}")

        if result.details:
            print("    Details:")
            for key, value in result.details.items():
                print(f"      - {key}: {value}")

    print("\n" + "-" * 70)
    print(f"Detection Rate: {blocked_count/total_count*100:.1f}%")
    print("=" * 70)


# =============================================================================
# MAIN
# =============================================================================


async def main():
    """Run attack simulations."""
    print("Initializing attack simulator...")
    simulator = AttackSimulator()

    print("Running attack simulations...")
    results = await simulator.run_all_attacks()
    print_attack_report(results)

    return results


def run():
    """Entry point."""
    return asyncio.run(main())


if __name__ == "__main__":
    run()
