# MCP Extension Proposal: Agent Attestation

**Author:** Joel Villarino
**Status:** Draft
**Created:** December 2025

## Summary

This proposal adds cryptographic agent identity verification to MCP using JWT-based attestation tokens with Ed25519 signatures, delivered via the existing `experimental` capability field.

## Motivation

MCP currently authenticates **users** (OAuth 2.1) but not **agents**. When a server receives a connection, it cannot verify:

- What model is connecting (Claude vs compromised variant)
- Who deployed the agent (Anthropic API vs third-party proxy)
- Whether the agent's provenance chain is intact

As agents gain real privileges (file access, code execution, API calls), this gap becomes a security liability.

## Proposed Solution

### Token Flow

```
Provider (Anthropic/OpenAI)
    │ signs JWT with Ed25519
    ▼
Agent carries token → Server verifies via JWKS
```

### Protocol Extension

Attestation uses the `experimental` field (no core protocol changes):

**Client (initialize request):**
```json
{
  "capabilities": {
    "experimental": {
      "security.attestation": {
        "version": "0.1.0",
        "token": "eyJhbGciOiJFZERTQSJ9..."
      }
    }
  }
}
```

**Server (initialize response):**
```json
{
  "capabilities": {
    "experimental": {
      "security.attestation": {
        "verification_status": "verified",
        "trust_level": "provider"
      }
    }
  }
}
```

### JWT Structure

```json
{
  "iss": "https://api.anthropic.com",
  "sub": "spiffe://anthropic.com/model/claude-sonnet-4",
  "aud": "https://mcp-server.example.com",
  "exp": 1735085100,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "agent_identity": {
    "model_family": "claude-4",
    "model_version": "claude-sonnet-4",
    "provider": "anthropic"
  }
}
```

### Key Distribution

Providers publish public keys via JWKS:
```
https://api.anthropic.com/.well-known/jwks.json
```

## Security Considerations

| Attack | Mitigation |
|--------|------------|
| Token Replay | JTI cache + short expiration |
| Token Theft | 5-minute lifetime |
| Issuer Spoofing | JWKS verification + trusted issuer list |
| Downgrade | Policy enforcement (required/preferred/optional) |

## Backwards Compatibility

- Uses `experimental` field - no breaking changes
- Servers can operate in `optional` mode during transition
- Non-attesting clients work with `optional`/`preferred` policies

## Reference Implementation

Complete Python implementation available:
- GitHub: [mcp-agent-attestation](https://github.com/joelv/mcp-agent-attestation)
- 140 passing tests
- Attack simulation with 100% detection rate
- MCP SDK integration (client + server wrappers)

## Open Questions

1. Should attestation be mandatory in a future MCP version?
2. How should cross-provider trust be established?
3. Should behavioral attestation (continuous verification) be in scope?

## Specification

Full technical specification: [SPEC.md](./SPEC.md)
