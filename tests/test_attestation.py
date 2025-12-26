"""
Tests for MCP Agent Attestation

Run with: pytest tests/ -v
"""

import pytest
import asyncio


# =============================================================================
# CORE MODULE TESTS
# =============================================================================

class TestAgentIdentity:
    """Tests for AgentIdentity dataclass."""
    
    def test_create_identity(self):
        from attestation import AgentIdentity
        
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-20250514",
            provider="anthropic",
        )
        
        assert identity.model_family == "claude-4"
        assert identity.provider == "anthropic"
    
    def test_spiffe_id_generation(self):
        from attestation import AgentIdentity
        
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-20250514",
            provider="anthropic",
        )
        
        spiffe_id = identity.to_spiffe_id()
        assert spiffe_id.startswith("spiffe://")
        assert "anthropic" in spiffe_id
        assert "claude-sonnet-4" in spiffe_id


class TestKeyPair:
    """Tests for key generation."""
    
    def test_generate_keypair(self):
        from attestation import KeyPair
        
        keypair = KeyPair.generate("test-key-001")
        
        assert keypair.kid == "test-key-001"
        assert keypair.private_key is not None
        assert keypair.public_key is not None
    
    def test_export_jwk(self):
        from attestation import KeyPair
        
        keypair = KeyPair.generate("test-key")
        jwk = keypair.to_jwk()
        
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["kid"] == "test-key"
        assert "x" in jwk


class TestAttestationProvider:
    """Tests for token creation."""
    
    def test_create_token(self):
        from attestation import (
            AttestationProvider,
            AgentIdentity,
            KeyPair,
        )
        
        keypair = KeyPair.generate("test-key")
        provider = AttestationProvider(
            issuer="https://test.example.com",
            keypair=keypair,
        )
        
        identity = AgentIdentity(
            model_family="test-model",
            model_version="v1.0",
            provider="test",
        )
        
        token = provider.create_token(
            identity=identity,
            audience="https://server.example.com",
        )
        
        assert token is not None
        assert len(token.split(".")) == 3  # JWT format


class TestAttestationVerifier:
    """Tests for token verification."""
    
    @pytest.mark.asyncio
    async def test_verify_valid_token(self):
        from attestation import (
            create_anthropic_provider,
            create_test_verifier,
            AgentIdentity,
        )
        
        provider, keypair = create_anthropic_provider()
        verifier = create_test_verifier(keypair)
        
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4",
            provider="anthropic",
        )
        
        token = provider.create_token(
            identity=identity,
            audience="https://server.example.com",
        )
        
        result = await verifier.verify(token)
        
        assert result.verified
        assert result.trust_level.value == "provider"
    
    @pytest.mark.asyncio
    async def test_reject_missing_token(self):
        from attestation import (
            create_anthropic_provider,
            create_test_verifier,
            VerificationPolicy,
        )
        
        _, keypair = create_anthropic_provider()
        verifier = create_test_verifier(keypair, VerificationPolicy.REQUIRED)
        
        result = await verifier.verify(None)
        
        assert not result.verified
        assert "required" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_replay_protection(self):
        from attestation import (
            create_anthropic_provider,
            create_test_verifier,
            AgentIdentity,
        )
        
        provider, keypair = create_anthropic_provider()
        verifier = create_test_verifier(keypair)
        
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4",
            provider="anthropic",
        )
        
        token = provider.create_token(
            identity=identity,
            audience="https://server.example.com",
        )
        
        # First use should succeed
        result1 = await verifier.verify(token)
        assert result1.verified
        
        # Replay should fail
        result2 = await verifier.verify(token)
        assert not result2.verified
        assert "replay" in result2.error.lower()


class TestReplayCache:
    """Tests for replay protection cache."""
    
    def test_add_and_check(self):
        from attestation import ReplayCache
        import time
        
        cache = ReplayCache()
        jti = "test-jti-123"
        exp = int(time.time()) + 300
        
        # First check should succeed
        assert cache.check_and_add(jti, exp) is True
        
        # Second check should fail (replay)
        assert cache.check_and_add(jti, exp) is False
    
    def test_cleanup_expired(self):
        from attestation import ReplayCache
        import time
        
        cache = ReplayCache()
        
        # Add expired token
        old_jti = "old-token"
        cache._seen[old_jti] = int(time.time()) - 1
        
        # Add new token (triggers cleanup)
        new_jti = "new-token"
        cache.check_and_add(new_jti, int(time.time()) + 300)
        
        # Old token should be cleaned up
        assert old_jti not in cache._seen


# =============================================================================
# PROTOCOL MODULE TESTS
# =============================================================================

class TestAttestingAgent:
    """Tests for client-side attestation."""
    
    def test_inject_capabilities(self):
        from attestation import (
            AttestingAgent,
            AttestationProvider,
            AgentIdentity,
            KeyPair,
            ATTESTATION_CAPABILITY_KEY,
        )
        
        keypair = KeyPair.generate("test")
        provider = AttestationProvider(
            issuer="https://test.com",
            keypair=keypair,
        )
        identity = AgentIdentity(
            model_family="test",
            model_version="v1",
            provider="test",
        )
        
        agent = AttestingAgent(provider=provider, identity=identity)
        
        capabilities = {"sampling": {}}
        result = agent.inject_into_capabilities(
            capabilities,
            audience="https://server.example.com"
        )
        
        assert "experimental" in result
        assert ATTESTATION_CAPABILITY_KEY in result["experimental"]
        assert "token" in result["experimental"][ATTESTATION_CAPABILITY_KEY]


class TestAttestationMiddleware:
    """Tests for server-side middleware."""
    
    @pytest.mark.asyncio
    async def test_process_valid_request(self):
        from attestation import (
            AttestationMiddleware,
            AttestingAgent,
            AttestationProvider,
            AgentIdentity,
            KeyPair,
            InMemoryKeyResolver,
            AttestationVerifier,
            VerificationPolicy,
            ATTESTATION_CAPABILITY_KEY,
        )
        
        # Setup
        keypair = KeyPair.generate("test")
        provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=keypair,
        )
        
        key_resolver = InMemoryKeyResolver()
        key_resolver.add_keypair("https://api.anthropic.com", keypair)
        
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=key_resolver,
            policy=VerificationPolicy.REQUIRED,
        )
        
        middleware = AttestationMiddleware(verifier=verifier)
        
        # Create client request
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4",
            provider="anthropic",
        )
        agent = AttestingAgent(provider=provider, identity=identity)
        capabilities = agent.inject_into_capabilities(
            {},
            audience="https://server.example.com"
        )
        
        # Process
        result = await middleware.process_initialize({
            "capabilities": capabilities,
            "clientInfo": {"name": "test", "version": "1.0"}
        })
        
        assert result.should_proceed
        assert result.context.verified


# =============================================================================
# ATTACK SIMULATION TESTS
# =============================================================================

class TestAttackSimulator:
    """Tests that attack simulations run correctly."""
    
    @pytest.mark.asyncio
    async def test_all_attacks_blocked(self):
        from attestation import AttackSimulator
        
        simulator = AttackSimulator()
        results = await simulator.run_all_attacks()
        
        # All attacks should be blocked
        blocked_count = sum(1 for r in results if r.blocked)
        assert blocked_count == len(results), \
            f"Expected all {len(results)} attacks blocked, got {blocked_count}"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestEndToEnd:
    """End-to-end integration tests."""
    
    @pytest.mark.asyncio
    async def test_full_handshake_flow(self):
        """Test complete initialize handshake with attestation."""
        from attestation import (
            AttestationProvider,
            AttestationVerifier,
            AttestingAgent,
            AttestationMiddleware,
            AgentIdentity,
            KeyPair,
            InMemoryKeyResolver,
            VerificationPolicy,
        )
        
        # Setup provider (Anthropic side)
        keypair = KeyPair.generate("anthropic-2025-01")
        provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=keypair,
        )
        
        # Setup verifier (Server side)
        key_resolver = InMemoryKeyResolver()
        key_resolver.add_keypair("https://api.anthropic.com", keypair)
        
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=key_resolver,
            policy=VerificationPolicy.REQUIRED,
            audience="https://mcp-server.example.com",
        )
        
        middleware = AttestationMiddleware(verifier=verifier)
        
        # Create agent (Client side)
        identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4-20250514",
            provider="anthropic",
        )
        agent = AttestingAgent(provider=provider, identity=identity)
        
        # Build initialize request
        server_url = "https://mcp-server.example.com"
        capabilities = agent.inject_into_capabilities(
            {"sampling": {}, "roots": {"listChanged": True}},
            audience=server_url
        )
        
        initialize_params = {
            "protocolVersion": "2025-06-18",
            "capabilities": capabilities,
            "clientInfo": {"name": "claude-agent", "version": "1.0.0"}
        }
        
        # Process on server
        result = await middleware.process_initialize(initialize_params)
        
        # Verify result
        assert result.should_proceed
        assert result.verification.verified
        assert result.context.verified
        assert "anthropic" in result.context.subject


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
