# MCP Agent Attestation - Demo

This demo shows the attestation system working end-to-end.

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
cd demo
docker-compose up --build
```

This starts:
- **Redis** for distributed replay protection
- **MCP Server** with attestation verification
- **MCP Client** demonstrating token creation/verification

### Option 2: Local Development

Terminal 1 - Start Redis:
```bash
docker run -p 6379:6379 redis:7-alpine
```

Terminal 2 - Start Server:
```bash
python demo/server.py
```

Terminal 3 - Run Client:
```bash
python demo/client.py
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/.well-known/jwks.json` | GET | JWKS public keys |
| `/demo/token` | GET | Generate demo token |
| `/verify` | POST | Verify attestation token |

## Demo Flow

1. **Server starts** with trusted issuer list and policy
2. **Client connects** and requests JWKS
3. **Client creates token** with its identity claims
4. **Client sends token** for verification
5. **Server verifies**:
   - Signature validity
   - Issuer is trusted
   - Audience matches
   - Token not replayed
6. **Server responds** with trust level

## Example Output

```
MCP Agent Attestation - Demo Client
============================================================

1. Fetching server's JWKS...
   Server public key: {"keys": [{"kty": "OKP", ...}]}

2. Generating attestation token...
   Token generated: eyJhbGciOiJFZERTQSIsImtpZCI6...

3. Getting demo token from server...
   Demo token: eyJhbGciOiJFZERTQSIsImtpZCI6...

4. Verifying our token (expect failure - unknown issuer)...
   Result: {"verified": false, "error": "Unknown issuer"}

5. Verifying demo token (expect success)...
   Result: {"verified": true, "trust_level": "provider"}

6. Attempting replay attack (expect failure)...
   Result: {"verified": false, "error": "Token replay detected"}

Demo complete!
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `ATTESTATION_POLICY` | `required` | `required`, `preferred`, or `optional` |
| `TRUSTED_ISSUERS` | `https://api.anthropic.com` | Comma-separated issuer URLs |
| `SERVER_AUDIENCE` | `https://demo-server.local` | Expected audience claim |
| `PORT` | `8080` | Server listen port |

## Metrics

The server exposes Prometheus metrics at `/metrics`:

```
attestation_verification_total 3
attestation_verification_success_total 1
attestation_verification_failure_total 2
attestation_replay_detected_total 1
```
