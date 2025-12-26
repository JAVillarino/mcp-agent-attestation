# MCP Agent Attestation

## Project Overview
Cryptographic attestation extension for MCP. Enables servers to verify agent identity.

## Key Files
- `src/attestation/core.py` - Token creation/verification
- `src/attestation/protocol.py` - MCP protocol extension
- `src/attestation/attacks.py` - Security validation
- `SPEC.md` - Technical specification

## Commands
```bash
# Run tests
pytest tests/ -v

# Run demos
python -m attestation.core
python -m attestation.attacks

# Install deps
pip install -e ".[all]"
```

## Current State
- Core attestation: Working (mock crypto)
- MCP integration: Designed, not wired to SDK
- Real crypto: Needs testing with cryptography/PyJWT installed

## Next Tasks
1. Test with real Ed25519 (install cryptography)
2. Wire into MCP SDK ClientSession/ServerSession
3. Integration tests with real MCP server