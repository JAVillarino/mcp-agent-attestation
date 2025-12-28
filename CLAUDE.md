# MCP Agent Attestation

Cryptographic attestation extension for MCP enabling servers to verify agent identity.

## Quick Reference

### Python

```bash
# Install
pip install -e ".[all]"

# Run tests (140 passing)
pytest tests/ -v

# Demos
python -m attestation.core      # Core demo
python -m attestation.attacks   # Attack simulation

# CLI
python -m attestation keygen --kid my-key
python -m attestation generate --issuer https://api.anthropic.com --audience https://server.com
```

### TypeScript

```bash
# Install
cd typescript && npm install

# Run tests (68 passing)
npm test

# CLI
npx mcp-attestation keygen --kid my-key
npx mcp-attestation generate --issuer https://api.anthropic.com --audience https://server.com
npx mcp-attestation attack  # Run attack simulations
```

## Key Files
- `SPEC.md` - Technical specification
- `docs/API.md` - API reference
- `docs/THREAT_ANALYSIS.md` - Security analysis
- `src/attestation/` - Python implementation
- `typescript/` - TypeScript implementation

## Status
Feature complete. Python: 140 tests. TypeScript: 68 tests. All 8 attack vectors blocked.
