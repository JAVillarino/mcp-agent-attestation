# MCP Agent Attestation Protocol Extension

## Technical Specification v0.1.0

**Author:** Joel Villarino  
**Target:** Anthropic Security Fellowship Application  
**Date:** December 2025  
**Status:** Draft  

---

## 1. Executive Summary

This specification defines a cryptographic attestation extension for the Model Context Protocol (MCP) that enables servers to verify the identity and provenance of connecting agents. The extension uses the existing MCP `experimental` capabilities field and JWT-based tokens with Ed25519 signatures.

### 1.1 Problem Statement

MCP currently handles **user authorization** (OAuth 2.1) but lacks **agent identity verification**. Servers cannot verify:
- What model is connecting (Claude vs. compromised variant)
- Who deployed the agent (Anthropic API vs. third-party proxy)
- Whether the agent's provenance chain is intact

### 1.2 Solution Overview

We propose an attestation layer that:
1. Uses JWT tokens with Ed25519 signatures
2. Travels with the agent (not per-connection)
3. Leverages MCP's `experimental` capability field
4. Is SPIFFE-compatible for enterprise deployments
5. Supports provider attestation (Anthropic) with extensibility for enterprise IdP

---

## 2. Architecture

### 2.1 Trust Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     ATTESTATION FLOW                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐     signs      ┌──────────────────┐          │
│  │   Anthropic  │ ─────────────► │  Attestation JWT │          │
│  │   (Provider) │                └────────┬─────────┘          │
│  └──────────────┘                         │                    │
│                                           │ travels with       │
│                                           ▼                    │
│  ┌──────────────┐   initialize   ┌──────────────────┐          │
│  │  MCP Client  │ ─────────────► │   MCP Server     │          │
│  │  (Agent)     │  + attestation │                  │          │
│  └──────────────┘                └────────┬─────────┘          │
│                                           │                    │
│                                           │ verifies via       │
│                                           ▼                    │
│                                  ┌──────────────────┐          │
│                                  │  JWKS Endpoint   │          │
│                                  │  (Provider Keys) │          │
│                                  └──────────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Key Principles

1. **Provider-First**: Initial trust comes from model provider (Anthropic/OpenAI)
2. **Enterprise-Extensible**: Design accommodates enterprise IdP integration (SPIFFE/OIDC)
3. **Transport-Agnostic**: Works with stdio, SSE, and Streamable HTTP
4. **Non-Breaking**: Uses `experimental` field, no core protocol changes
5. **Attestation Travels**: Token follows agent across server hops

---

## 3. JWT Token Specification

### 3.1 Token Structure

```json
{
  "header": {
    "alg": "EdDSA",
    "typ": "JWT",
    "kid": "anthropic-2025-01"
  },
  "payload": {
    "iss": "https://api.anthropic.com",
    "sub": "spiffe://anthropic.com/model/claude-sonnet-4",
    "aud": "https://mcp-server.example.com",
    "iat": 1735084800,
    "exp": 1735085100,
    "nbf": 1735084800,
    "jti": "550e8400-e29b-41d4-a716-446655440000",
    
    "agent_identity": {
      "model_family": "claude-4",
      "model_version": "claude-sonnet-4-20250514",
      "provider": "anthropic",
      "deployment_id": "api-prod-us-east-1"
    },
    
    "agent_integrity": {
      "config_hash": "sha256:a1b2c3d4...",
      "system_prompt_hash": "sha256:e5f6g7h8..."
    },
    
    "attestation_metadata": {
      "attestation_version": "0.1.0",
      "attestation_type": "provider",
      "safety_level": "standard",
      "capabilities_declared": ["tools", "resources"]
    },
    
    "cnf": {
      "jwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "base64url-encoded-public-key"
      },
      "tls_binding": null
    }
  }
}
```

### 3.2 Claim Definitions

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | Issuer URL (provider or enterprise IdP) |
| `sub` | string | Yes | Subject identifier (SPIFFE ID format recommended) |
| `aud` | string/array | Yes | Target server(s) this token is valid for |
| `iat` | number | Yes | Issued-at timestamp (Unix seconds) |
| `exp` | number | Yes | Expiration timestamp (5 min max recommended) |
| `nbf` | number | No | Not-before timestamp |
| `jti` | string | Yes | Unique token ID (UUID v4) for replay protection |
| `agent_identity` | object | Yes | Model and provider information |
| `agent_integrity` | object | No | Hashes for integrity verification |
| `attestation_metadata` | object | Yes | Attestation version and type info |
| `cnf` | object | No | Confirmation key for proof-of-possession |

### 3.3 SPIFFE Subject Format

Subjects SHOULD use SPIFFE ID format for enterprise compatibility:

```
spiffe://<trust-domain>/<workload-path>

Examples:
  spiffe://anthropic.com/model/claude-sonnet-4
  spiffe://acme.corp/agent/finance-bot
  spiffe://openai.com/model/gpt-4o
```

### 3.4 Signature Algorithm

- **Algorithm**: Ed25519 (EdDSA with Curve25519)
- **Rationale**: 
  - Faster than ECDSA P-256
  - Deterministic (no nonce issues)
  - Better side-channel resistance
  - 64-byte signatures (compact)

---

## 4. MCP Protocol Extension

### 4.1 Capability Declaration

Attestation uses the `experimental` field in `ClientCapabilities`:

```python
# Client (Agent) declares attestation support
{
    "capabilities": {
        "experimental": {
            "security.attestation": {
                "version": "0.1.0",
                "supported_algorithms": ["EdDSA"],
                "attestation_types": ["provider", "enterprise"]
            }
        },
        "sampling": {},
        "roots": {"listChanged": true}
    }
}
```

```python
# Server declares attestation requirements
{
    "capabilities": {
        "experimental": {
            "security.attestation": {
                "version": "0.1.0",
                "policy": "required",  # "required" | "preferred" | "optional"
                "trusted_issuers": [
                    "https://api.anthropic.com",
                    "https://api.openai.com"
                ],
                "required_claims": ["agent_identity", "attestation_metadata"]
            }
        },
        "tools": {"listChanged": false},
        "resources": {"subscribe": false}
    }
}
```

### 4.2 Initialize Request Extension

The attestation token is included in the `initialize` request:

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {
            "experimental": {
                "security.attestation": {
                    "version": "0.1.0",
                    "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."
                }
            }
        },
        "clientInfo": {
            "name": "claude-agent",
            "version": "1.0.0"
        }
    }
}
```

### 4.3 Server Response

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {
            "experimental": {
                "security.attestation": {
                    "version": "0.1.0",
                    "verification_status": "verified",
                    "trust_level": "provider",
                    "verified_claims": ["agent_identity", "attestation_metadata"]
                }
            },
            "tools": {"listChanged": false}
        },
        "serverInfo": {
            "name": "secure-mcp-server",
            "version": "1.0.0"
        }
    }
}
```

### 4.4 Error Responses

| Error Code | Message | Description |
|------------|---------|-------------|
| -32001 | `attestation_required` | Server requires attestation but none provided |
| -32002 | `attestation_invalid` | Token signature verification failed |
| -32003 | `attestation_expired` | Token has expired |
| -32004 | `attestation_replay` | Token JTI has been seen before |
| -32005 | `attestation_issuer_untrusted` | Issuer not in trusted list |
| -32006 | `attestation_claims_insufficient` | Required claims missing |

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "error": {
        "code": -32001,
        "message": "attestation_required",
        "data": {
            "policy": "required",
            "trusted_issuers": ["https://api.anthropic.com"]
        }
    }
}
```

---

## 5. Key Management

### 5.1 JWKS Endpoint

Providers publish public keys at a well-known endpoint:

```
https://api.anthropic.com/.well-known/jwks.json
```

Response format:

```json
{
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "anthropic-2025-01",
            "x": "base64url-encoded-public-key",
            "use": "sig",
            "alg": "EdDSA"
        }
    ]
}
```

### 5.2 Key Rotation

- Keys SHOULD be rotated every 90 days
- Old keys remain valid for token lifetime after rotation
- `kid` (Key ID) identifies which key to use for verification
- Servers SHOULD cache JWKS with 1-hour TTL

### 5.3 Key Resolution Flow

```
1. Server receives attestation token
2. Server extracts `kid` from JWT header
3. Server checks local key cache
4. If cache miss or expired:
   a. Fetch JWKS from issuer's well-known endpoint
   b. Cache keys with TTL
5. Select key matching `kid`
6. Verify signature
```

---

## 6. Security Considerations

### 6.1 Replay Protection

Tokens include a unique `jti` (JWT ID) claim. Servers MUST:
1. Maintain a cache of seen JTI values
2. Reject tokens with previously-seen JTI
3. Cache TTL should match token expiration window
4. Consider distributed caching for multi-node deployments

```python
# Replay protection implementation
class ReplayCache:
    def __init__(self, backend="memory"):
        self.seen_tokens = {}  # jti -> expiration_time
    
    def check_and_add(self, jti: str, exp: int) -> bool:
        """Returns False if token was already seen (replay attack)"""
        self._cleanup_expired()
        if jti in self.seen_tokens:
            return False
        self.seen_tokens[jti] = exp
        return True
```

### 6.2 Clock Skew

- Servers SHOULD allow 30-second clock skew for `iat` validation
- Token `exp` SHOULD be 5 minutes maximum
- `nbf` (not-before) prevents premature token use

### 6.3 Audience Validation

- `aud` claim MUST match the server's identity
- Servers SHOULD validate against their canonical URL
- Wildcard audiences are NOT recommended

### 6.4 TLS Channel Binding (Future)

The `cnf.tls_binding` field is reserved for future channel binding:

```json
{
    "cnf": {
        "tls_binding": {
            "method": "tls-exporter",
            "hash": "sha256:..."
        }
    }
}
```

This prevents token replay across different TLS sessions.

### 6.5 Attack Mitigation Matrix

| Attack | Mitigation |
|--------|------------|
| Token Replay | JTI cache + expiration |
| Token Theft | Short expiration (5 min) |
| Man-in-the-Middle | TLS + audience validation |
| Issuer Spoofing | JWKS verification + trusted issuer list |
| Clock Manipulation | nbf/exp validation + skew tolerance |
| Downgrade | Policy enforcement (required mode) |

---

## 7. Implementation Notes

### 7.1 Transport Considerations

| Transport | Attestation Delivery |
|-----------|---------------------|
| stdio | In initialize request (trusted local) |
| SSE | In initialize request (verify always) |
| Streamable HTTP | In initialize request + optional header |

### 7.2 Session Binding

Once verified, attestation is bound to the session:
- Server stores verified claims in session context
- Subsequent requests don't re-send token
- Token refresh requires new initialize (rare due to 5-min lifetime)

### 7.3 Multi-Server Hops

When an agent connects to multiple servers:
1. Agent carries same attestation token
2. Each server independently verifies
3. Server A cannot forge attestation seen by Server B
4. Cross-server trust is based on shared issuer trust

---

## 8. Enterprise Extensions (Future)

### 8.1 Enterprise IdP Integration

Organizations can issue their own attestations:

```json
{
    "iss": "https://idp.acme.corp",
    "sub": "spiffe://acme.corp/workload/finance-agent",
    "agent_identity": {
        "model_family": "claude-4",
        "model_version": "claude-sonnet-4",
        "provider": "anthropic",
        "enterprise": {
            "org_id": "acme-corp",
            "workload_id": "finance-agent",
            "deployment_env": "production"
        }
    }
}
```

### 8.2 Nested Attestations

Provider attestation wrapped in enterprise attestation:

```json
{
    "iss": "https://idp.acme.corp",
    "attestation_metadata": {
        "attestation_type": "enterprise",
        "nested_attestation": "eyJhbGciOiJFZERTQSJ9..."
    }
}
```

### 8.3 SPIFFE/SPIRE Integration

Full SPIFFE integration would involve:
- SVID (SPIFFE Verifiable Identity Document) as attestation
- SPIRE agent for automatic key rotation
- Federation across trust domains

---

## 9. API Reference

### 9.1 Core Types

```python
@dataclass
class AgentIdentity:
    model_family: str
    model_version: str
    provider: str
    deployment_id: Optional[str] = None

@dataclass
class AgentIntegrity:
    config_hash: Optional[str] = None
    system_prompt_hash: Optional[str] = None

@dataclass
class AttestationMetadata:
    attestation_version: str
    attestation_type: str  # "provider" | "enterprise"
    safety_level: str
    capabilities_declared: List[str]

@dataclass
class AttestationToken:
    iss: str
    sub: str
    aud: Union[str, List[str]]
    iat: int
    exp: int
    jti: str
    agent_identity: AgentIdentity
    agent_integrity: Optional[AgentIntegrity]
    attestation_metadata: AttestationMetadata
    nbf: Optional[int] = None
    cnf: Optional[Dict] = None
```

### 9.2 Verification Result

```python
@dataclass
class VerificationResult:
    verified: bool
    trust_level: str  # "provider" | "enterprise" | "none"
    issuer: Optional[str]
    subject: Optional[str]
    verified_claims: List[str]
    error: Optional[str] = None
    error_code: Optional[int] = None
```

---

## 10. Conformance

### 10.1 Server Requirements

A conformant server MUST:
- [ ] Parse attestation from `experimental.security.attestation.token`
- [ ] Verify Ed25519 signatures
- [ ] Validate `exp`, `iat`, `aud` claims
- [ ] Implement JTI replay protection
- [ ] Support policy modes: required, preferred, optional
- [ ] Return appropriate error codes

### 10.2 Client Requirements

A conformant client SHOULD:
- [ ] Declare attestation capability in `experimental`
- [ ] Include valid attestation token when available
- [ ] Handle attestation error responses gracefully
- [ ] Support token refresh (re-initialize)

---

## Appendix A: Example JWKS Response

```json
{
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "anthropic-2025-01",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "use": "sig",
            "alg": "EdDSA"
        },
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "anthropic-2024-10",
            "x": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz_CZKt3wd2e2d4Ws",
            "use": "sig",
            "alg": "EdDSA"
        }
    ]
}
```

## Appendix B: Full Token Example

```
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImFudGhyb3BpYy0yMDI1LTAxIn0.
eyJpc3MiOiJodHRwczovL2FwaS5hbnRocm9waWMuY29tIiwic3ViIjoic3BpZmZlOi8vYW50
aHJvcGljLmNvbS9tb2RlbC9jbGF1ZGUtc29ubmV0LTQiLCJhdWQiOiJodHRwczovL21jcC1z
ZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE3MzUwODQ4MDAsImV4cCI6MTczNTA4NTEwMCwi
anRpIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiYWdlbnRfaWRl
bnRpdHkiOnsibW9kZWxfZmFtaWx5IjoiY2xhdWRlLTQiLCJtb2RlbF92ZXJzaW9uIjoiY2xh
dWRlLXNvbm5ldC00LTIwMjUwNTE0IiwicHJvdmlkZXIiOiJhbnRocm9waWMifSwiYXR0ZXN0
YXRpb25fbWV0YWRhdGEiOnsiYXR0ZXN0YXRpb25fdmVyc2lvbiI6IjAuMS4wIiwiYXR0ZXN0
YXRpb25fdHlwZSI6InByb3ZpZGVyIiwic2FmZXR5X2xldmVsIjoic3RhbmRhcmQifX0.
<signature>
```

## Appendix C: Why TypeScript Matters

TypeScript dominates the MCP ecosystem because:

1. **SDK Origin**: MCP SDK was TypeScript-first
2. **Ecosystem**: Most MCP servers in production are TypeScript
3. **Tooling**: Claude Desktop, Cursor, VS Code extensions are JS/TS
4. **Community**: `@modelcontextprotocol/sdk` has more examples

**For your PoC**: Python is fine. Note in README that the JWT schema is language-agnostic.

---

*End of Specification*
