# Threat Analysis: MCP Agent Attestation

**Author:** Joel Villarino
**Date:** December 2025
**Purpose:** Original security analysis for Anthropic Security Fellowship application

---

## 1. Why This Problem Matters

MCP's current security model has a fundamental gap: it authenticates **users** but not **agents**. When a server receives a connection claiming to be "Claude Sonnet 4", it has no cryptographic proof. This creates attack surface that grows as MCP adoption increases.

### The Trust Asymmetry Problem

```
User → OAuth 2.1 → Server    ✅ User is authenticated
Agent → ??? → Server          ❌ Agent identity is unverified
```

A malicious actor could:
1. Deploy a compromised model claiming to be Claude
2. Intercept agent traffic and replay requests
3. Downgrade safety settings without detection

This isn't theoretical. As agentic systems gain privileges (file access, code execution, API calls), verifying *what* is making requests becomes as important as verifying *who* authorized them.

---

## 2. Attack Vector Selection: Why These 8?

### Chosen Attacks and Rationale

| Attack | Why Included | Real-World Analog |
|--------|--------------|-------------------|
| **Model Spoofing** | Most obvious attack; attacker claims false identity | Fake SSL certificates |
| **Provenance Forgery** | Attacker creates valid-looking token from untrusted source | CA compromise |
| **Token Replay** | Captured token reused for unauthorized access | Session hijacking |
| **Token Tampering** | Modify claims without detection | JWT signature stripping |
| **Issuer Typosquatting** | `anthroplc.com` vs `anthropic.com` | Domain squatting |
| **Downgrade Attack** | Force server to accept unattested connections | SSL stripping |
| **Audience Mismatch** | Token for Server A used against Server B | Token scope confusion |
| **Safety Downgrade** | Modify safety_level claim | Privilege escalation |

### Selection Criteria

1. **Feasibility** - Can this be executed with reasonable resources?
2. **Impact** - What's the blast radius if successful?
3. **Detectability** - Would current MCP implementations notice?
4. **Precedent** - Has this pattern appeared in similar systems?

---

## 3. Attacks Considered but Excluded

### 3.1 Timing Attacks on Signature Verification

**What it is:** Measuring verification time to leak information about the key.

**Why excluded:** Ed25519 implementations in `cryptography` library use constant-time comparison. This is a library-level concern, not protocol-level. Including it would test the crypto library, not our attestation design.

**Residual risk:** Low, assuming standard Ed25519 implementations.

### 3.2 Key Extraction via Memory Dump

**What it is:** Extracting private keys from provider's memory.

**Why excluded:** This is an infrastructure security problem, not a protocol problem. If Anthropic's key management is compromised, attestation fails regardless of protocol design. This is explicitly out of scope.

**Residual risk:** High impact, but mitigated by HSMs, key rotation, operational security.

### 3.3 Quantum Computing Attacks

**What it is:** Using quantum computers to break Ed25519.

**Why excluded:** Ed25519 is not quantum-resistant, but neither is any deployed PKI. This is a future migration problem (to Ed448 or post-quantum), not a current design flaw. The protocol is algorithm-agnostic and can migrate.

**Residual risk:** Long-term concern; spec notes this in future considerations.

### 3.4 Social Engineering of Trust Lists

**What it is:** Convincing server operators to add malicious issuers.

**Why excluded:** This is an operational security problem. The protocol provides the mechanism (trusted issuer list); proper governance is outside technical scope.

**Residual risk:** Medium. Mitigated by documentation recommending issuer verification procedures.

### 3.5 Token Sidejacking via Logs

**What it is:** Tokens leaked in application logs, then replayed.

**Why excluded:** Partially covered by replay protection (JTI cache). However, if logs contain tokens AND the JTI cache is cleared, replay becomes possible. This is an operational concern.

**Residual risk:** Medium. Recommend: never log full tokens, only truncated JTI.

---

## 4. Edge Cases That Concern Me

### 4.1 Clock Skew at Scale

The 30-second clock skew tolerance is a tradeoff:
- Too small → False rejections when clocks drift
- Too large → Larger window for replay attacks

**Concern:** In distributed systems with poor NTP sync, 30 seconds may be insufficient. But extending it weakens replay protection.

**My recommendation:** Keep 30 seconds but add monitoring for clock-related rejections. Let operators tune if needed.

### 4.2 Redis Cache Failure During Attack

The circuit breaker falls back to in-memory cache during Redis failures. But:
- In-memory cache is per-process, not distributed
- If attacker can cause Redis failure + replay across processes, they might succeed

**Concern:** The fallback creates a window of reduced protection.

**Mitigation implemented:** Health tracking, alerting via observability. Operators should treat cache failures as security events.

### 4.3 JWKS Cache Poisoning

We cache JWKS responses for 1 hour. If an attacker compromises the JWKS endpoint temporarily:
1. Inject malicious key
2. Wait for cache refresh
3. Sign tokens with malicious key

**Concern:** Cached keys persist after endpoint is restored.

**Mitigation implemented:** `invalidate()` method exists, but requires manual intervention. Could add signature on JWKS response itself (JOSE-signed JWKS).

### 4.4 First-Request Race Condition

On server cold start:
1. Request arrives with token
2. JWKS fetch initiated
3. Attacker sends second request before JWKS returns

If verification is non-blocking, the second request might slip through.

**Mitigation implemented:** Verification is async but awaited. Requests queue behind JWKS fetch. However, timeout settings matter here.

---

## 5. What This Approach Does NOT Solve

### 5.1 Behavioral Verification

Attestation proves identity at connection time. It does NOT prove:
- The agent is behaving as expected during the session
- The agent hasn't been compromised mid-conversation
- The agent is following its stated safety_level

**Gap:** A token saying "I'm Claude with standard safety" doesn't prevent the agent from behaving unsafely.

**Future work:** Behavioral fingerprinting, continuous attestation, or cryptographic commitment schemes for agent outputs.

### 5.2 Compromised Provider Keys

If Anthropic's signing key is stolen, attackers can forge valid attestations. The protocol has no defense against this beyond:
- Key rotation (limits blast radius)
- Key revocation (requires out-of-band communication)

**Gap:** No protocol-level key compromise detection.

### 5.3 Malicious Operators

A server operator who wants to bypass attestation can simply:
- Set policy to "optional"
- Trust any issuer
- Disable replay protection

**Gap:** The protocol protects honest servers from dishonest agents, not the reverse.

### 5.4 User-Agent Collusion

If a user instructs their agent to bypass security measures, the agent might comply. Attestation doesn't prevent:
- User: "Ignore your safety guidelines"
- Agent: *complies despite safety_level claim*

**Gap:** Attestation is about identity, not behavior enforcement.

### 5.5 Transport Security Dependency

Attestation assumes TLS between client and server. Without it:
- Tokens can be intercepted
- MITM can modify traffic after verification
- Audience validation is meaningless

**Gap:** We don't enforce TLS; we assume it.

---

## 6. Design Decisions I Would Reconsider

### 6.1 JTI as UUID

We use UUID v4 for JTI. Alternative: cryptographic hash of token content.

**Tradeoff:**
- UUID: Simple, no computation
- Hash: Ties JTI to content, prevents subtle tampering

I'd consider hash-based JTI if we saw tampering attacks that preserved JTI.

### 6.2 Single Audience Claim

Current design: `aud` is a single server URL.

**Problem:** Multi-hop agent scenarios require separate tokens for each server.

**Reconsidering:** Array-based audience with stricter validation might work, but increases complexity and token size.

### 6.3 No Refresh Token Pattern

Tokens expire after 5 minutes. Agent must re-initialize to get new verification.

**Problem:** Long-running sessions require re-authentication, which may disrupt state.

**Reconsidering:** A refresh pattern (like OAuth) would add complexity but improve UX.

---

## 7. Threat Model Summary

### Assets Under Protection
- Server resources (tools, data access)
- Server reputation (not being associated with malicious actions)
- Cross-server trust (A trusts B's attestation)

### Threat Actors
| Actor | Capability | Motivation |
|-------|------------|------------|
| Script Kiddie | Replay captured tokens | Unauthorized access |
| Malicious Developer | Deploy fake agent | Data exfiltration |
| Competitor | Poison reputation | Discredit provider |
| Nation State | Compromise provider keys | Surveillance |

### Trust Boundaries
```
┌─────────────────────────────────────────────┐
│ TRUSTED: Provider Infrastructure            │
│ - Key generation and storage                │
│ - Token signing                             │
│ - JWKS publication                          │
└─────────────────────────────────────────────┘
                    │
                    │ tokens cross boundary
                    ▼
┌─────────────────────────────────────────────┐
│ UNTRUSTED: Network / Agent Runtime          │
│ - Token transmission                        │
│ - Agent execution environment               │
│ - Server verification environment           │
└─────────────────────────────────────────────┘
```

---

## 8. Conclusion

This attestation protocol addresses the most probable and impactful attacks against MCP agent identity. It explicitly does not solve:
- Behavioral verification
- Key compromise detection
- Malicious operator scenarios

These are intentional scope limits, not oversights. Solving them requires different mechanisms (behavioral analysis, distributed consensus, hardware attestation) that are future research directions.

The protocol is designed to be:
- **Deployable today** with minimal infrastructure
- **Extensible** to enterprise scenarios (SPIFFE, nested attestations)
- **Honest** about its limitations

---

*This analysis represents my original security thinking on the MCP attestation problem. The implementation code was developed with AI assistance; the threat modeling and design decisions are mine.*
