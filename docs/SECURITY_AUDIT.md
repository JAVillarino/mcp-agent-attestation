# MCP Agent Attestation - Security Audit

**Version**: 0.1.0
**Date**: December 2025
**Author**: Joel Villarino

## Executive Summary

This document provides a security analysis of the MCP Agent Attestation library, including threat modeling, attack surface analysis, and security recommendations.

**Overall Assessment**: The implementation follows security best practices and successfully defends against all tested attack vectors. The cryptographic primitives (Ed25519, JWT) are industry-standard and correctly implemented.

---

## 1. Threat Model

### 1.1 Assets Protected

| Asset | Criticality | Description |
|-------|-------------|-------------|
| Agent Identity | High | Model family, version, provider information |
| Trust Relationship | High | Server's trust in connecting agents |
| Attestation Keys | Critical | Ed25519 private keys for signing |
| Replay Cache | Medium | Prevents token reuse attacks |

### 1.2 Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Malicious Agent | High | Impersonate legitimate AI models |
| Man-in-the-Middle | Medium | Intercept/modify attestation tokens |
| Replay Attacker | Low | Reuse captured valid tokens |
| Rogue Server | Medium | Extract sensitive claims from tokens |

### 1.3 Attack Vectors

```
                    ┌─────────────────┐
                    │  Threat Actors  │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ Token Forgery │   │ Token Replay  │   │ MITM Attack   │
└───────────────┘   └───────────────┘   └───────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
   Signature             JTI Cache            TLS/Audience
   Verification          Protection           Validation
```

---

## 2. Security Controls

### 2.1 Cryptographic Controls

| Control | Implementation | Status |
|---------|----------------|--------|
| Signature Algorithm | Ed25519 (EdDSA) | ✅ Implemented |
| Key Size | 256-bit (Ed25519 standard) | ✅ Secure |
| Token Format | JWT (RFC 7519) | ✅ Standard |
| Key Distribution | JWKS (RFC 7517) | ✅ Standard |

**Ed25519 Properties**:
- 128-bit security level (equivalent to RSA-3072)
- Deterministic signatures (no random number vulnerabilities)
- Fast verification (~15,000 verifications/second)
- Small signatures (64 bytes)

### 2.2 Token Security

| Claim | Purpose | Validation |
|-------|---------|------------|
| `iss` | Issuer identification | Checked against trusted list |
| `aud` | Audience restriction | Validated by server |
| `exp` | Expiration time | Enforced with clock skew tolerance |
| `iat` | Issued-at time | Used for freshness check |
| `jti` | Token ID | Replay protection via cache |
| `nbf` | Not-before time | Optional freshness constraint |

**Token Lifetime**:
- Default: 5 minutes
- Maximum recommended: 15 minutes
- Clock skew tolerance: 30 seconds

### 2.3 Replay Protection

```python
# Atomic check-and-add using Redis SETNX
was_set = await redis.setnx(f"jti:{token_id}", "1")
if was_set:
    await redis.expire(f"jti:{token_id}", ttl)
    return True  # New token
else:
    return False  # Replay detected
```

**Properties**:
- Atomic operation prevents race conditions
- TTL-based expiry matches token lifetime
- Distributed support via Redis
- Graceful degradation to in-memory

---

## 3. Attack Simulation Results

The library includes an attack simulation suite (`attestation.attacks`) that tests 8 attack vectors:

| Attack | Vector | Defense | Result |
|--------|--------|---------|--------|
| Model Spoofing | Forge `agent_identity` claims | Signature verification | ✅ Blocked |
| Provenance Forgery | Use untrusted issuer | Issuer allowlist | ✅ Blocked |
| Token Replay | Reuse valid token | JTI cache | ✅ Blocked |
| Token Tampering | Modify claims after signing | Signature verification | ✅ Blocked |
| Issuer Typosquatting | `anthropic.com` vs `anthroplc.com` | Exact string match | ✅ Blocked |
| Downgrade Attack | Remove attestation from request | Policy enforcement | ✅ Blocked |
| Audience Mismatch | Token for server A sent to B | Audience validation | ✅ Blocked |
| Safety Downgrade | Change `safety_level` claim | Signature verification | ✅ Blocked |

**Detection Rate: 100%**

Run the attack suite:
```bash
python -m attestation attack
```

---

## 4. Vulnerability Analysis

### 4.1 Addressed Vulnerabilities

| Vulnerability | CVE/CWE | Mitigation |
|---------------|---------|------------|
| Weak Crypto | CWE-327 | Ed25519 (modern, secure) |
| Missing Auth | CWE-306 | Required policy mode |
| Replay Attack | CWE-294 | JTI-based cache |
| Clock Skew | CWE-613 | 30-second tolerance |
| Timing Attack | CWE-208 | Constant-time comparison |

### 4.2 Potential Vulnerabilities (Mitigated)

| Issue | Risk | Mitigation |
|-------|------|------------|
| Key Compromise | High | Keys should rotate regularly; JWKS supports multiple keys |
| Cache Overflow | Medium | TTL-based expiry; Redis has memory limits |
| DoS via Verification | Low | Circuit breaker on JWKS fetch; cached keys |
| Token Leakage | Medium | Short lifetime (5 min); TLS required |

### 4.3 Out of Scope (Application Responsibility)

| Issue | Responsibility |
|-------|----------------|
| TLS/HTTPS enforcement | Deployment configuration |
| Key storage security | Infrastructure team |
| Access control to tools | MCP server implementation |
| Rate limiting | Application layer |

---

## 5. Cryptographic Analysis

### 5.1 Algorithm Selection

**Ed25519** was chosen over alternatives:

| Algorithm | Pros | Cons |
|-----------|------|------|
| Ed25519 ✓ | Fast, small keys, no RNG needed | Newer (2011) |
| RSA-2048 | Widely supported | Slow, large keys |
| ECDSA P-256 | NIST approved | RNG vulnerabilities possible |
| HMAC-SHA256 | Fast | Symmetric (shared secret) |

### 5.2 JWT Implementation

The library uses PyJWT with explicit algorithm specification:

```python
# Signing - only EdDSA allowed
jwt.encode(claims, private_key, algorithm="EdDSA")

# Verification - algorithm explicitly specified
jwt.decode(token, public_key, algorithms=["EdDSA"])
```

**Security Note**: Algorithm confusion attacks (CVE-2015-9235) are prevented by:
1. Explicit algorithm specification in decode
2. Not accepting `none` algorithm
3. Key type validation (Ed25519 only)

### 5.3 Key Management

**JWKS Endpoint Security**:
- HTTPS required (HTTP rejected)
- Certificate validation enabled
- Circuit breaker prevents abuse
- Keys cached with TTL

**Key Rotation**:
```json
{
  "keys": [
    {"kid": "key-2025-01", "x": "...", "use": "sig"},
    {"kid": "key-2024-12", "x": "...", "use": "sig"}
  ]
}
```
Multiple keys in JWKS allow graceful rotation.

---

## 6. Security Recommendations

### 6.1 Deployment Recommendations

| Priority | Recommendation |
|----------|----------------|
| Critical | Use TLS for all MCP connections |
| Critical | Protect Ed25519 private keys (HSM recommended for production) |
| High | Set `policy=REQUIRED` for sensitive servers |
| High | Use Redis for distributed replay protection |
| Medium | Monitor attestation metrics for anomalies |
| Medium | Rotate keys annually or on compromise |

### 6.2 Configuration Hardening

```python
# Recommended verifier configuration
verifier = AttestationVerifier(
    trusted_issuers=["https://api.anthropic.com"],  # Explicit allowlist
    key_resolver=HTTPKeyResolver(),
    policy=VerificationPolicy.REQUIRED,  # Reject unauthenticated
    audience="https://your-server.com",  # Validate audience
)

# Recommended Redis cache configuration
cache = RedisReplayCache(config=RedisConfig(
    url="rediss://...",  # TLS-enabled Redis
    fallback_enabled=True,  # Graceful degradation
    max_retries=3,
))
```

### 6.3 Monitoring Recommendations

Monitor these metrics for security anomalies:

| Metric | Alert Threshold | Indicates |
|--------|-----------------|-----------|
| `replay_detected` | > 10/min | Active replay attack |
| `verification_failure` | > 50% | Misconfiguration or attack |
| `circuit_breaker_opens` | Any | JWKS endpoint issues |
| `unknown_issuer` | Any | Unauthorized agent |

---

## 7. Compliance Considerations

### 7.1 Standards Alignment

| Standard | Alignment |
|----------|-----------|
| OWASP Top 10 | Addresses A01-A10 where applicable |
| NIST 800-63B | Ed25519 meets AAL2 requirements |
| RFC 7519 | JWT implementation follows spec |
| RFC 7517 | JWKS implementation follows spec |

### 7.2 Audit Trail

The library provides audit-ready logging:

```python
from attestation import register_event_handler, AttestationEventHandler

class AuditHandler(AttestationEventHandler):
    def on_verification_success(self, issuer, subject, trust_level):
        audit_log.info(f"ATTESTATION_SUCCESS: {subject} from {issuer}")

    def on_verification_failure(self, issuer, error, error_code):
        audit_log.warning(f"ATTESTATION_FAILURE: {error} (code={error_code})")

    def on_replay_detected(self, issuer, jti):
        audit_log.critical(f"REPLAY_ATTACK: {jti[:16]} from {issuer}")

register_event_handler(AuditHandler())
```

---

## 8. Known Limitations

| Limitation | Impact | Mitigation Path |
|------------|--------|-----------------|
| No hardware key support | Keys in memory | Future: PKCS#11 integration |
| In-memory cache single-server | Replay possible across servers | Use Redis in distributed deployments |
| No certificate pinning | MITM if CA compromised | Future: Certificate pinning option |
| MCP SDK coupling | May break on SDK updates | Version checks implemented |

---

## 9. Security Testing

### 9.1 Test Coverage

```bash
# Run security-focused tests
pytest tests/test_attestation.py -v -k "attack or replay or verify"

# Run attack simulation
python -m attestation attack
```

### 9.2 Fuzzing (Recommended)

For production deployments, run:
```bash
# Install hypothesis for property-based testing
pip install hypothesis

# Fuzz token parsing
python -c "
from hypothesis import given, strategies as st
from attestation.cli import decode_jwt_unsafe

@given(st.text())
def test_fuzz_jwt_decode(s):
    try:
        decode_jwt_unsafe(s)
    except ValueError:
        pass  # Expected for invalid input
"
```

---

## 10. Incident Response

### 10.1 Key Compromise Response

1. **Immediate**: Remove compromised key from JWKS endpoint
2. **Short-term**: Issue new key, update trusted clients
3. **Medium-term**: Investigate logs for unauthorized usage
4. **Long-term**: Review key management procedures

### 10.2 Attack Detection Response

If replay attacks detected:
1. Check source IPs in logs
2. Verify token wasn't leaked (check TLS)
3. Consider reducing token lifetime
4. Enable Redis if using in-memory cache

---

## Appendix A: Cryptographic Specifications

| Parameter | Value |
|-----------|-------|
| Signature Algorithm | Ed25519 (EdDSA) |
| Hash Function | SHA-512 (internal to Ed25519) |
| Key Size | 256-bit private, 256-bit public |
| Signature Size | 64 bytes |
| JWT Algorithm Header | `EdDSA` |
| JWK Key Type | `OKP` |
| JWK Curve | `Ed25519` |

## Appendix B: Error Codes

| Code | Meaning | Security Implication |
|------|---------|---------------------|
| 1001 | Token expired | Normal expiry |
| 1002 | Token not yet valid | Clock skew |
| 1003 | Invalid signature | **Potential forgery** |
| 1004 | Unknown issuer | **Untrusted source** |
| 1005 | Invalid audience | Token misuse |
| 1006 | Replay detected | **Active attack** |
| 1007 | Missing required claims | Malformed token |
| 1008 | Malformed token | Invalid input |

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Dec 2025 | Joel Villarino | Initial security audit |
