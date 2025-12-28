# MCP Agent Attestation

## Project Overview
Cryptographic attestation extension for MCP that enables servers to verify agent identity and provenance. Uses JWT tokens with Ed25519 signatures, traveling with agents via MCP's `experimental` capability field.

## Project Status: Feature Complete

### Completed Components
| Component | File(s) | Status |
|-----------|---------|--------|
| Core attestation | `src/attestation/core.py` | Production-ready |
| MCP protocol extension | `src/attestation/protocol.py` | Complete |
| MCP SDK integration | `src/attestation/mcp_client.py`, `mcp_server.py` | Complete |
| Attack simulation | `src/attestation/attacks.py` | 100% detection rate |
| JWKS fetcher | `src/attestation/jwks.py` | With caching, retry, circuit breaker |
| Replay cache | `src/attestation/cache.py` | Redis + in-memory fallback |
| CLI tools | `src/attestation/cli.py` | keygen, generate, verify, inspect, attack |
| Observability | `src/attestation/observability.py` | Prometheus metrics, tracing, events |
| Tests | `tests/` | 132 tests, 100% pass |
| Demo | `demo/` | Docker Compose with Redis/server/client |
| Benchmarks | `benchmarks/benchmark.py` | 3,168 ops/sec full flow |
| Documentation | `docs/`, `SPEC.md` | API.md, SECURITY_AUDIT.md |

## Key Files
- `SPEC.md` - Full technical specification (v0.1.0)
- `docs/API.md` - API reference documentation
- `docs/SECURITY_AUDIT.md` - Security analysis and threat model
- `src/attestation/core.py` - Token creation/verification primitives
- `src/attestation/protocol.py` - MCP protocol extension types
- `src/attestation/mcp_client.py` - AttestingClientSession wrapper
- `src/attestation/mcp_server.py` - AttestingServer wrapper

## Commands
```bash
# Install all dependencies
pip install -e ".[all]"

# Run all tests (132 tests)
pytest tests/ -v

# Run demos
python -m attestation.core      # Core attestation demo
python -m attestation.attacks   # Attack simulation suite
python -m attestation.protocol  # Protocol extension demo

# CLI tools
python -m attestation keygen --kid my-key
python -m attestation generate --issuer https://api.anthropic.com --audience https://server.com
python -m attestation inspect <token>
python -m attestation attack

# Run benchmarks
python benchmarks/benchmark.py

# Docker demo
cd demo && docker-compose up --build
```

## Architecture
```
Provider (Anthropic) signs JWT → Agent carries token → Server verifies via JWKS
```

## Security Features
- Ed25519 signatures (fast, deterministic)
- JTI-based replay protection (Redis or in-memory)
- Audience validation
- Trusted issuer allowlist
- Short token lifetime (5 min default)
- Clock skew tolerance (30s)

## What's NOT Implemented
1. **TypeScript port** - Would increase adoption in MCP ecosystem
2. **Ecosystem adoption** - Requires Anthropic/OpenAI to publish JWKS endpoints
3. **MCP spec PR** - Formal proposal to modelcontextprotocol/specification

## Performance
- Full attestation flow: 0.32ms latency, 3,168 ops/sec
- Token creation: 0.106ms, 9,397 ops/sec
- Token verification: 0.201ms, 4,959 ops/sec

## Author
Joel Villarino - Rice University
