/**
 * Core Attestation Tests
 *
 * Tests for token creation, verification, and key management.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  AttestationProvider,
  AttestationVerifier,
  createAnthropicProvider,
  createTestVerifier,
  decodeTokenUnsafe,
  generateEd25519KeyPair,
  InMemoryKeyResolver,
  exportPublicKeyAsJWK,
  exportPrivateKeyAsJWK,
  importKeyPairFromJWK,
  InMemoryReplayCache,
  VerificationPolicy,
  TrustLevel,
  AttestationErrorCode,
  toSpiffeId,
  computeHash,
  createAgentIdentity,
  createAttestationMetadata,
} from '../src/index.js';

describe('Key Management', () => {
  it('should generate Ed25519 key pair', async () => {
    const keyPair = await generateEd25519KeyPair('test-key');

    expect(keyPair.kid).toBe('test-key');
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
  });

  it('should generate key pair with auto-generated kid', async () => {
    const keyPair = await generateEd25519KeyPair();

    expect(keyPair.kid).toMatch(/^key-[a-f0-9]{8}$/);
  });

  it('should export public key as JWK', async () => {
    const keyPair = await generateEd25519KeyPair('export-test');
    const jwk = await exportPublicKeyAsJWK(keyPair);

    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.kid).toBe('export-test');
    expect(jwk.x).toBeDefined();
    expect(jwk.use).toBe('sig');
    expect(jwk.alg).toBe('EdDSA');
  });

  it('should export private key as JWK', async () => {
    const keyPair = await generateEd25519KeyPair('private-test');
    const jwk = await exportPrivateKeyAsJWK(keyPair);

    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.kid).toBe('private-test');
    expect(jwk.x).toBeDefined();
    expect(jwk.d).toBeDefined(); // Private component
  });

  it('should import key pair from JWK', async () => {
    const originalKeyPair = await generateEd25519KeyPair('import-test');
    const jwk = await exportPrivateKeyAsJWK(originalKeyPair);

    const importedKeyPair = await importKeyPairFromJWK(jwk);

    expect(importedKeyPair.kid).toBe('import-test');
    expect(importedKeyPair.publicKey).toBeDefined();
    expect(importedKeyPair.privateKey).toBeDefined();
  });
});

describe('InMemoryKeyResolver', () => {
  let resolver: InMemoryKeyResolver;
  let keyPair: Awaited<ReturnType<typeof generateEd25519KeyPair>>;

  beforeEach(async () => {
    resolver = new InMemoryKeyResolver();
    keyPair = await generateEd25519KeyPair('resolver-test');
  });

  it('should add and retrieve keys', async () => {
    resolver.addKeyPair('https://api.anthropic.com', keyPair);

    const retrieved = await resolver.getKey('https://api.anthropic.com', 'resolver-test');

    expect(retrieved).toBeDefined();
  });

  it('should return null for unknown issuer', async () => {
    resolver.addKeyPair('https://api.anthropic.com', keyPair);

    const retrieved = await resolver.getKey('https://unknown.com', 'resolver-test');

    expect(retrieved).toBeNull();
  });

  it('should return null for unknown kid', async () => {
    resolver.addKeyPair('https://api.anthropic.com', keyPair);

    const retrieved = await resolver.getKey('https://api.anthropic.com', 'unknown-kid');

    expect(retrieved).toBeNull();
  });

  it('should export keys as JWKS', async () => {
    resolver.addKeyPair('https://api.anthropic.com', keyPair);

    const jwks = await resolver.toJWKS('https://api.anthropic.com');

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]?.kid).toBe('resolver-test');
  });

  it('should clear keys', async () => {
    resolver.addKeyPair('https://api.anthropic.com', keyPair);
    resolver.clear();

    const retrieved = await resolver.getKey('https://api.anthropic.com', 'resolver-test');

    expect(retrieved).toBeNull();
  });
});

describe('AttestationProvider', () => {
  let provider: AttestationProvider;
  let keyPair: Awaited<ReturnType<typeof generateEd25519KeyPair>>;

  beforeEach(async () => {
    keyPair = await generateEd25519KeyPair('provider-test');
    provider = new AttestationProvider({
      issuer: 'https://api.anthropic.com',
      keyPair,
      tokenLifetimeSeconds: 300,
    });
  });

  it('should create valid JWT token', async () => {
    const token = await provider.createToken({
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      audience: 'https://server.example.com',
    });

    expect(token).toBeDefined();
    expect(token.split('.')).toHaveLength(3); // JWT format
  });

  it('should include all required claims', async () => {
    const token = await provider.createToken({
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
        deployment_id: 'prod-1',
      },
      audience: 'https://server.example.com',
      metadata: { safety_level: 'enhanced' },
    });

    const decoded = decodeTokenUnsafe(token);

    expect(decoded.header.alg).toBe('EdDSA');
    expect(decoded.header.kid).toBe('provider-test');
    expect(decoded.payload.iss).toBe('https://api.anthropic.com');
    expect(decoded.payload.aud).toBe('https://server.example.com');
    expect(decoded.payload.jti).toBeDefined();
    expect(decoded.payload.iat).toBeDefined();
    expect(decoded.payload.exp).toBeDefined();
    expect(decoded.payload.agent_identity).toBeDefined();
    expect(decoded.payload.attestation_metadata).toBeDefined();
  });

  it('should generate unique JTI for each token', async () => {
    const identity = {
      model_family: 'claude-4',
      model_version: 'claude-sonnet-4-20250514',
      provider: 'anthropic',
    };

    const token1 = await provider.createToken({
      identity,
      audience: 'https://server.example.com',
    });
    const token2 = await provider.createToken({
      identity,
      audience: 'https://server.example.com',
    });

    const decoded1 = decodeTokenUnsafe(token1);
    const decoded2 = decodeTokenUnsafe(token2);

    expect(decoded1.payload.jti).not.toBe(decoded2.payload.jti);
  });

  it('should support multiple audiences', async () => {
    const token = await provider.createToken({
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      audience: ['https://server1.example.com', 'https://server2.example.com'],
    });

    const decoded = decodeTokenUnsafe(token);

    expect(decoded.payload.aud).toEqual([
      'https://server1.example.com',
      'https://server2.example.com',
    ]);
  });
});

describe('AttestationVerifier', () => {
  let provider: AttestationProvider;
  let keyPair: Awaited<ReturnType<typeof generateEd25519KeyPair>>;
  let verifier: AttestationVerifier;

  beforeEach(async () => {
    [provider, keyPair] = await createAnthropicProvider('verify-test');
    verifier = await createTestVerifier(keyPair, VerificationPolicy.REQUIRED);
  });

  it('should verify valid token', async () => {
    const token = await provider.createToken({
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      audience: 'https://server.example.com',
    });

    const result = await verifier.verify(token);

    expect(result.verified).toBe(true);
    expect(result.trustLevel).toBe(TrustLevel.PROVIDER);
    expect(result.claims).toBeDefined();
    expect(result.issuer).toBe('https://api.anthropic.com');
  });

  it('should reject missing token with REQUIRED policy', async () => {
    const result = await verifier.verify(null);

    expect(result.verified).toBe(false);
    expect(result.errorCode).toBe(AttestationErrorCode.REQUIRED);
    expect(result.error).toContain('required');
  });

  it('should accept missing token with OPTIONAL policy', async () => {
    const optionalVerifier = await createTestVerifier(keyPair, VerificationPolicy.OPTIONAL);

    const result = await optionalVerifier.verify(null);

    expect(result.verified).toBe(false);
    expect(result.trustLevel).toBe(TrustLevel.NONE);
    expect(result.errorCode).toBeUndefined();
  });

  it('should reject token from untrusted issuer', async () => {
    const untrustedKeyPair = await generateEd25519KeyPair('untrusted');
    const untrustedProvider = new AttestationProvider({
      issuer: 'https://evil.example.com',
      keyPair: untrustedKeyPair,
    });

    const token = await untrustedProvider.createToken({
      identity: {
        model_family: 'evil-model',
        model_version: 'v1',
        provider: 'evil',
      },
      audience: 'https://server.example.com',
    });

    const result = await verifier.verify(token);

    expect(result.verified).toBe(false);
    expect(result.error).toContain('Untrusted issuer');
  });

  it('should reject token with unknown key', async () => {
    const unknownKeyPair = await generateEd25519KeyPair('unknown-key');
    const providerWithUnknownKey = new AttestationProvider({
      issuer: 'https://api.anthropic.com',
      keyPair: unknownKeyPair,
    });

    const token = await providerWithUnknownKey.createToken({
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      audience: 'https://server.example.com',
    });

    const result = await verifier.verify(token);

    expect(result.verified).toBe(false);
    expect(result.error).toContain('Unknown key ID');
  });

  it('should detect token replay', async () => {
    const token = await provider.createToken({
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      audience: 'https://server.example.com',
    });

    // First use
    const result1 = await verifier.verify(token);
    expect(result1.verified).toBe(true);

    // Replay
    const result2 = await verifier.verify(token);
    expect(result2.verified).toBe(false);
    expect(result2.error).toContain('replay');
  });

  it('should validate audience when configured', async () => {
    const keyResolver = new InMemoryKeyResolver();
    keyResolver.addKeyPair('https://api.anthropic.com', keyPair);

    const audienceVerifier = new AttestationVerifier({
      trustedIssuers: ['https://api.anthropic.com'],
      keyResolver,
      policy: VerificationPolicy.REQUIRED,
      audience: 'https://correct-server.example.com',
    });

    const token = await provider.createToken({
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      audience: 'https://wrong-server.example.com',
    });

    const result = await audienceVerifier.verify(token);

    expect(result.verified).toBe(false);
  });
});

describe('Helper Functions', () => {
  it('should create agent identity', () => {
    const identity = createAgentIdentity('claude-4', 'claude-sonnet-4', 'anthropic', 'prod-1');

    expect(identity.model_family).toBe('claude-4');
    expect(identity.model_version).toBe('claude-sonnet-4');
    expect(identity.provider).toBe('anthropic');
    expect(identity.deployment_id).toBe('prod-1');
  });

  it('should generate SPIFFE ID', () => {
    const identity = createAgentIdentity('claude-4', 'claude-sonnet-4-20250514', 'anthropic');
    const spiffeId = toSpiffeId(identity);

    expect(spiffeId).toBe('spiffe://anthropic.com/model/claude-sonnet-4-20250514');
  });

  it('should generate SPIFFE ID with custom domain', () => {
    const identity = createAgentIdentity('claude-4', 'claude-sonnet-4-20250514', 'anthropic');
    const spiffeId = toSpiffeId(identity, 'custom.domain.com');

    expect(spiffeId).toBe('spiffe://custom.domain.com/model/claude-sonnet-4-20250514');
  });

  it('should compute SHA256 hash', async () => {
    const hash = await computeHash('test content');

    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('should create attestation metadata with defaults', () => {
    const metadata = createAttestationMetadata();

    expect(metadata.attestation_version).toBe('0.1.0');
    expect(metadata.attestation_type).toBe('provider');
    expect(metadata.safety_level).toBe('standard');
    expect(metadata.capabilities_declared).toEqual([]);
  });

  it('should create attestation metadata with custom values', () => {
    const metadata = createAttestationMetadata({
      safety_level: 'enhanced',
      capabilities_declared: ['tools', 'resources'],
    });

    expect(metadata.safety_level).toBe('enhanced');
    expect(metadata.capabilities_declared).toEqual(['tools', 'resources']);
  });
});

describe('InMemoryReplayCache', () => {
  let cache: InMemoryReplayCache;

  beforeEach(() => {
    cache = new InMemoryReplayCache();
  });

  afterEach(() => {
    cache.destroy();
  });

  it('should accept new tokens', async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 300;
    const result = await cache.checkAndAdd('jti-1', futureExp);

    expect(result).toBe(true);
  });

  it('should reject replayed tokens', async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 300;

    await cache.checkAndAdd('jti-1', futureExp);
    const result = await cache.checkAndAdd('jti-1', futureExp);

    expect(result).toBe(false);
  });

  it('should track token count', async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 300;

    await cache.checkAndAdd('jti-1', futureExp);
    await cache.checkAndAdd('jti-2', futureExp);

    expect(await cache.count()).toBe(2);
  });

  it('should clear all tokens', async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 300;

    await cache.checkAndAdd('jti-1', futureExp);
    await cache.checkAndAdd('jti-2', futureExp);
    await cache.clear();

    expect(await cache.count()).toBe(0);
    expect(await cache.checkAndAdd('jti-1', futureExp)).toBe(true);
  });

  it('should check existence without adding', async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 300;

    await cache.checkAndAdd('jti-1', futureExp);

    expect(await cache.exists('jti-1')).toBe(true);
    expect(await cache.exists('jti-2')).toBe(false);
  });
});

describe('Convenience Functions', () => {
  it('should create Anthropic provider', async () => {
    const [provider, keyPair] = await createAnthropicProvider();

    expect(provider.issuerUrl).toBe('https://api.anthropic.com');
    expect(keyPair.kid).toBe('anthropic-2025-01');
  });

  it('should create test verifier', async () => {
    const [_, keyPair] = await createAnthropicProvider();
    const verifier = await createTestVerifier(keyPair);

    expect(verifier.trustedIssuers).toContain('https://api.anthropic.com');
    expect(verifier.policy).toBe(VerificationPolicy.REQUIRED);
  });

  it('should decode token without verification', async () => {
    const [provider] = await createAnthropicProvider();
    const token = await provider.createToken({
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4',
        provider: 'anthropic',
      },
      audience: 'https://server.example.com',
    });

    const decoded = decodeTokenUnsafe(token);

    expect(decoded.header.alg).toBe('EdDSA');
    expect(decoded.payload.iss).toBe('https://api.anthropic.com');
  });
});
