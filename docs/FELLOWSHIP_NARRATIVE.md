# Fellowship Application Narrative Outline

**Anthropic Security Fellowship - MCP Agent Attestation**
**Applicant:** Joel Villarino, Rice University

---

## 1. The Problem (Why This Matters)

### Opening Hook
As AI agents gain access to sensitive systems through protocols like MCP, a critical security gap emerges: we authenticate *users* but not *agents*. A server receiving a connection from "Claude" has no cryptographic proof it's actually Claude.

### The Gap in Current MCP Security
- MCP implements OAuth 2.1 for user authorization
- No mechanism to verify agent identity or provenance
- Servers trust self-reported `clientInfo` without verification
- No defense against model spoofing, token theft, or provenance forgery

### Why Now
- Agentic systems are gaining real privileges (file access, code execution, API calls)
- MCP adoption is growing rapidly
- The attack surface expands with every new MCP server deployment
- This is a tractable problem with known solutions (PKI, JWT, attestation)

---

## 2. The Solution (What I Built)

### Core Idea
Provider-signed JWT tokens that cryptographically attest agent identity, traveling with the agent through MCP's `experimental` capability field.

### Technical Approach
- Ed25519 signatures for fast, secure verification
- SPIFFE-compatible identifiers for enterprise integration
- JTI-based replay protection
- JWKS for key distribution
- Non-breaking protocol extension (uses existing `experimental` field)

### Implementation Evidence
- 140 passing tests
- 8 attack vectors simulated and blocked
- Production patterns (circuit breakers, fallbacks, observability)
- Full MCP SDK integration

---

## 3. Security Analysis (My Thinking)

### Threat Model
[Reference THREAT_ANALYSIS.md for detailed analysis]

### Key Security Decisions
1. **Why Ed25519** - Deterministic signatures prevent nonce-related vulnerabilities
2. **Why 5-minute tokens** - Limits window for stolen token abuse
3. **Why JTI replay protection** - Prevents captured token reuse

### What This Doesn't Solve (Honest Limitations)
- Behavioral verification (agent could misbehave after attestation)
- Key compromise detection
- Malicious operators who disable protection
- User-agent collusion

### Edge Cases That Concern Me
- Clock skew in distributed systems
- Redis failure during active attack
- JWKS cache poisoning window

---

## 4. My Journey (Learning and Growth)

### Starting Point
<!-- TODO: Fill in your actual starting knowledge -->
- Familiarity with: [what you knew]
- New to me: [what you learned]

### Key Learning Moments
<!-- TODO: Add specific insights you gained -->

### Research That Informed This Work
<!-- TODO: List papers, specs, prior art you studied -->

---

## 5. Why Anthropic (What I'd Do With the Fellowship)

### Proposed Research Directions

**1. Behavioral Attestation**
Current attestation proves identity at connection time. What about continuous verification? Could we cryptographically commit to agent behavior patterns?

**2. Cross-Provider Trust**
If Anthropic and OpenAI both deploy attestation, how do servers establish cross-provider trust? Federation models from SPIFFE could apply.

**3. Hardware-Backed Attestation**
Can we leverage TPMs or secure enclaves for stronger key protection? What would a hardware attestation flow look like for cloud-deployed agents?

### Why Security Research at Anthropic
- Direct access to model deployment infrastructure
- Ability to implement provider-side signing
- Collaboration with teams building safety systems
- Real-world testing with production MCP deployments

---

## 6. Evidence of Capability

### Technical Artifacts
| Artifact | Description |
|----------|-------------|
| SPEC.md | Complete technical specification |
| THREAT_ANALYSIS.md | Original security analysis |
| 140 tests | Comprehensive test coverage |
| Attack simulation | 8 vectors, 100% detection |
| Production patterns | Circuit breakers, observability |

### What This Demonstrates
- Ability to identify security gaps
- Systematic threat modeling
- Implementation skills
- Understanding of limitations (not overselling)

---

## 7. Closing

### The Ask
Support to continue this research at Anthropic, with access to:
- Provider infrastructure for real attestation deployment
- Collaboration with MCP and security teams
- Resources for extended research on behavioral attestation

### The Outcome
A production-ready agent identity layer that makes MCP deployments measurably more secure.

---

*Draft outline - to be refined into actual application materials*
