# MCP Agent Attestation

**Cryptographic identity verification for Model Context Protocol agents**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

This project implements a cryptographic attestation extension for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io) that enables servers to verify the identity and provenance of connecting AI agents.

**Problem**: MCP handles user authorization (OAuth 2.1) but lacks agent identity verification. Servers cannot verify what model is connecting, who deployed it, or whether its provenance chain is intact.

**Solution**: JWT-based attestation tokens with Ed25519 signatures that travel with the agent, using MCP's `experimental` capability field for non-breaking protocol extension.

## Features

- 🔐 **Ed25519 Signatures**: Fast, secure cryptographic verification
- 🎫 **JWT-Based Tokens**: Standard format with SPIFFE-compatible identifiers  
- 🔄 **Replay Protection**: JTI-based caching prevents token reuse
- 🏢 **Enterprise Ready**: SPIFFE ID format, JWKS key distribution
- 🛡️ **Policy Enforcement**: Required/Preferred/Optional attestation modes
- 🧪 **Attack Simulation**: Demo suite proving security against common attacks

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/joelv/mcp-agent-attestation.git
cd mcp-agent-attestation

# Create virtual environment with uv (recommended)
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with all dependencies
uv pip install -e ".[all]"

# Or with pip
pip install -e ".[all]"
```

### Run the Demo

```bash
# Core attestation demo
python -m attestation.core

# Attack simulation suite
python -m attestation.attacks

# Protocol extension demo
python -m attestation.protocol
```

## Project Structure

```
mcp-agent-attestation/
├── SPEC.md                    # Technical specification
├── README.md                  # This file
├── pyproject.toml             # Project configuration
├── src/
│   └── attestation/
│       ├── __init__.py        # Package exports
│       ├── core.py            # Core attestation primitives
│       ├── protocol.py        # MCP protocol extension
│       └── attacks.py         # Attack simulations
└── tests/
    └── ...
```

## Usage

### Creating Attestation Tokens (Agent/Client Side)

```python
from attestation import (
    AttestationProvider,
    AgentIdentity,
    KeyPair,
)

# In production, Anthropic would run this
keypair = KeyPair.generate("anthropic-2025-01")
provider = AttestationProvider(
    issuer="https://api.anthropic.com",
    keypair=keypair,
)

# Create identity for the agent
identity = AgentIdentity(
    model_family="claude-4",
    model_version="claude-sonnet-4-20250514",
    provider="anthropic",
)

# Generate token for a specific server
token = provider.create_token(
    identity=identity,
    audience="https://mcp-server.example.com",
)
```

### Verifying Attestation (Server Side)

```python
from attestation import (
    AttestationVerifier,
    InMemoryKeyResolver,
    VerificationPolicy,
)

# Setup key resolver (would fetch from JWKS in production)
key_resolver = InMemoryKeyResolver()
key_resolver.add_keypair("https://api.anthropic.com", keypair)

# Create verifier
verifier = AttestationVerifier(
    trusted_issuers=["https://api.anthropic.com"],
    key_resolver=key_resolver,
    policy=VerificationPolicy.REQUIRED,
)

# Verify incoming token
result = await verifier.verify(token)

if result.verified:
    print(f"Verified agent: {result.subject}")
    print(f"Trust level: {result.trust_level}")
else:
    print(f"Verification failed: {result.error}")
```

### MCP Protocol Integration

```python
from attestation import (
    AttestingAgent,
    AttestationMiddleware,
    ServerAttestationCapability,
)

# Client side: Attach attestation to initialize request
agent = AttestingAgent(provider=provider, identity=identity)
capabilities = agent.inject_into_capabilities(
    {"sampling": {}, "roots": {"listChanged": True}},
    audience="https://mcp-server.example.com"
)

# Server side: Verify in middleware
middleware = AttestationMiddleware(
    verifier=verifier,
    capability=ServerAttestationCapability(
        policy="required",
        trusted_issuers=["https://api.anthropic.com"]
    )
)

result = await middleware.process_initialize(request_params)
if result.should_proceed:
    session.attestation = result.context
else:
    return result.error_response
```

## Attack Simulation Results

The attack simulation suite demonstrates protection against:

| Attack | Status | Defense |
|--------|--------|---------|
| Model Spoofing | ✅ Blocked | Signature verification |
| Provenance Forgery | ✅ Blocked | Trusted issuer list |
| Token Replay | ✅ Blocked | JTI cache |
| Token Tampering | ✅ Blocked | Signature verification |
| Issuer Typosquatting | ✅ Blocked | Strict issuer matching |
| Downgrade Attack | ✅ Blocked | Policy enforcement |
| Audience Mismatch | ✅ Blocked | Audience validation |
| Safety Downgrade | ✅ Blocked | Signed claims |

**Detection Rate: 100%**

## Specification

See [SPEC.md](SPEC.md) for the complete technical specification including:

- JWT token structure and claims
- MCP protocol extension format
- Key management (JWKS)
- Security considerations
- Enterprise extensions (SPIFFE/IdP)

## Roadmap

- [x] Core attestation primitives
- [x] MCP protocol extension
- [x] Attack simulation suite
- [ ] Real MCP SDK integration
- [ ] JWKS HTTP fetcher
- [ ] Redis-backed replay cache
- [ ] TypeScript implementation
- [ ] Behavioral fingerprinting (future research)

## Contributing

Contributions and feedback are welcome!

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Joel Villarino**  
Rice University, Computer Science & Statistics  
[joelavillarino@gmail.com](mailto:joelavillarino@gmail.com)

## Acknowledgments

Initial implementation developed with assistance from Claude (Anthropic). 
All code reviewed, tested, and extended by Joel Villarino.

---


