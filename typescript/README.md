# MCP Agent Attestation - TypeScript

TypeScript implementation of the MCP Agent Attestation protocol, enabling MCP servers to verify agent identity using JWT tokens with Ed25519 signatures.

## Installation

```bash
npm install mcp-agent-attestation
```

## Quick Start

### Creating Attestation Tokens (Agent/Client side)

```typescript
import {
  AttestationProvider,
  generateEd25519KeyPair,
  buildAttestationCapability,
  ATTESTATION_CAPABILITY_KEY,
} from 'mcp-agent-attestation';

// Generate key pair (in production, this comes from your provider)
const keyPair = await generateEd25519KeyPair('my-key-id');

// Create provider
const provider = new AttestationProvider({
  issuer: 'https://api.anthropic.com',
  keyPair,
});

// Build attestation capability for MCP initialize request
const attestationCap = await buildAttestationCapability({
  provider,
  identity: {
    model_family: 'claude-4',
    model_version: 'claude-sonnet-4-20250514',
    provider: 'anthropic',
  },
  targetAudience: 'https://my-mcp-server.com',
});

// Include in MCP initialize request
const capabilities = {
  experimental: {
    [ATTESTATION_CAPABILITY_KEY]: attestationCap,
  },
  // ... other capabilities
};
```

### Verifying Attestation Tokens (Server side)

```typescript
import {
  AttestationVerifier,
  InMemoryKeyResolver,
  verifyMcpAttestation,
  buildAttestationResponse,
  VerificationPolicy,
  ATTESTATION_CAPABILITY_KEY,
} from 'mcp-agent-attestation';

// Set up key resolver with trusted public keys
const keyResolver = new InMemoryKeyResolver();
keyResolver.addKeyPair('https://api.anthropic.com', providerKeyPair);

// Create verifier
const verifier = new AttestationVerifier({
  trustedIssuers: ['https://api.anthropic.com'],
  keyResolver,
  policy: VerificationPolicy.REQUIRED,
  audience: 'https://my-mcp-server.com',
});

// In your MCP initialize handler
const result = await verifyMcpAttestation(
  verifier,
  request.params.capabilities?.experimental
);

if (result.verified) {
  console.log(`Verified! Trust level: ${result.trustLevel}`);
}

// Build response for client
const response = buildAttestationResponse(result, verifier.policy);
```

## Features

- **JWT-based attestation** with Ed25519 signatures
- **Replay protection** via JTI cache
- **JWKS support** for key distribution
- **MCP SDK integration** utilities
- **Attack simulations** to validate security
- **CLI tools** for testing

## CLI Usage

```bash
# Generate key pair
npx mcp-attestation keygen --kid my-key

# Generate attestation token
npx mcp-attestation generate \
  --issuer https://api.anthropic.com \
  --audience https://server.example.com

# Inspect token (without verification)
npx mcp-attestation inspect <token>

# Verify token
npx mcp-attestation verify <token> --public-key key.json

# Run attack simulations
npx mcp-attestation attack
```

## API Reference

### Core Classes

- `AttestationProvider` - Creates signed attestation tokens
- `AttestationVerifier` - Verifies attestation tokens
- `InMemoryKeyResolver` - Simple in-memory public key store
- `JWKSKeyResolver` - Fetches keys from JWKS endpoints
- `InMemoryReplayCache` - Tracks JTIs to prevent replay attacks

### MCP Integration

- `buildAttestationCapability()` - Build client attestation capability
- `extractAttestationToken()` - Extract token from experimental caps
- `verifyMcpAttestation()` - Verify attestation from MCP request
- `buildAttestationResponse()` - Build server response
- `AttestationSessionStore` - Store attestation context per session
- `requireAttestation()` - Check attestation requirements

### Types

See [src/types.ts](src/types.ts) for all Zod schemas and TypeScript types.

## Error Codes

| Code   | Name                    | Description                         |
| ------ | ----------------------- | ----------------------------------- |
| -32001 | `attestation_required`  | Server requires attestation         |
| -32002 | `attestation_invalid`   | Signature verification failed       |
| -32003 | `attestation_expired`   | Token has expired                   |
| -32004 | `attestation_replay`    | Token JTI seen before               |
| -32005 | `attestation_untrusted` | Issuer not in trusted list          |
| -32006 | `attestation_claims`    | Required claims missing             |

## Testing

```bash
npm test
```

## License

MIT
