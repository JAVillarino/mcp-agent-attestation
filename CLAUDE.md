# MCP Agent Attestation

Cryptographic attestation extension for MCP enabling servers to verify agent identity.

## Quick Reference

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

## Key Files
- `SPEC.md` - Technical specification
- `docs/API.md` - API reference
- `docs/THREAT_ANALYSIS.md` - Security analysis
- `src/attestation/` - Implementation

## Status
Feature complete. 140 tests passing.
