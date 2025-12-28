/**
 * Integration Tests
 *
 * Tests for MCP integration utilities and end-to-end flows.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  // Core
  AttestationProvider,
  AttestationVerifier,
  createAnthropicProvider,
  createTestVerifier,
  generateEd25519KeyPair,
  VerificationPolicy,
  TrustLevel,

  // MCP Integration
  buildAttestationCapability,
  extractAttestationToken,
  parseAttestationResponse,
  buildServerAttestationRequirements,
  buildAttestationResponse,
  verifyMcpAttestation,
  createAttestationContext,
  AttestationSessionStore,
  requireAttestation,
  ATTESTATION_CAPABILITY_KEY,
  ATTESTATION_VERSION,
} from '../src/index.js';

describe('MCP Client Integration', () => {
  let provider: AttestationProvider;

  beforeEach(async () => {
    [provider] = await createAnthropicProvider();
  });

  it('should build attestation capability for client', async () => {
    const capability = await buildAttestationCapability({
      provider,
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      targetAudience: 'https://mcp-server.example.com',
    });

    expect(capability.version).toBe(ATTESTATION_VERSION);
    expect(capability.token).toBeDefined();
    expect(capability.supported_algorithms).toContain('EdDSA');
    expect(capability.attestation_types).toContain('provider');
  });

  it('should build capability with metadata', async () => {
    const capability = await buildAttestationCapability({
      provider,
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
        deployment_id: 'prod-1',
      },
      targetAudience: 'https://mcp-server.example.com',
      metadata: {
        safety_level: 'enhanced',
        capabilities_declared: ['tools', 'resources'],
      },
    });

    expect(capability.token).toBeDefined();
  });

  it('should extract attestation token from experimental caps', async () => {
    const capability = await buildAttestationCapability({
      provider,
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      targetAudience: 'https://mcp-server.example.com',
    });

    const experimentalCaps = {
      [ATTESTATION_CAPABILITY_KEY]: capability,
    };

    const token = extractAttestationToken(experimentalCaps);

    expect(token).toBe(capability.token);
  });

  it('should return undefined for missing attestation', () => {
    const token = extractAttestationToken({});
    expect(token).toBeUndefined();
  });

  it('should return undefined for null experimental caps', () => {
    const token = extractAttestationToken(undefined);
    expect(token).toBeUndefined();
  });
});

describe('MCP Server Integration', () => {
  let provider: AttestationProvider;
  let keyPair: Awaited<ReturnType<typeof generateEd25519KeyPair>>;
  let verifier: AttestationVerifier;

  beforeEach(async () => {
    [provider, keyPair] = await createAnthropicProvider();
    verifier = await createTestVerifier(keyPair);
  });

  it('should build server attestation requirements', () => {
    const requirements = buildServerAttestationRequirements(verifier);

    expect(requirements.version).toBe(ATTESTATION_VERSION);
    expect(requirements.policy).toBe(VerificationPolicy.REQUIRED);
    expect(requirements.trusted_issuers).toContain('https://api.anthropic.com');
    expect(requirements.required_claims).toContain('agent_identity');
  });

  it('should verify attestation from MCP request', async () => {
    const capability = await buildAttestationCapability({
      provider,
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      targetAudience: 'https://mcp-server.example.com',
    });

    const experimentalCaps = {
      [ATTESTATION_CAPABILITY_KEY]: capability,
    };

    const result = await verifyMcpAttestation(verifier, experimentalCaps);

    expect(result.verified).toBe(true);
    expect(result.trustLevel).toBe(TrustLevel.PROVIDER);
  });

  it('should handle missing attestation in MCP request', async () => {
    const result = await verifyMcpAttestation(verifier, {});

    expect(result.verified).toBe(false);
  });

  it('should build success response', async () => {
    const capability = await buildAttestationCapability({
      provider,
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      targetAudience: 'https://mcp-server.example.com',
    });

    const verificationResult = await verifyMcpAttestation(verifier, {
      [ATTESTATION_CAPABILITY_KEY]: capability,
    });

    const response = buildAttestationResponse(verificationResult, verifier.policy);

    expect(response.verification_status).toBe('verified');
    expect(response.trust_level).toBe(TrustLevel.PROVIDER);
    expect(response.verified_claims).toBeDefined();
  });

  it('should build failure response', async () => {
    const verificationResult = await verifyMcpAttestation(verifier, {});

    const response = buildAttestationResponse(verificationResult, verifier.policy);

    expect(response.verification_status).toBe('failed');
    expect(response.error).toBeDefined();
  });

  it('should parse attestation response', () => {
    const response = {
      version: ATTESTATION_VERSION,
      verification_status: 'verified' as const,
      trust_level: TrustLevel.PROVIDER,
      verified_claims: {
        issuer: 'https://api.anthropic.com',
        subject: 'spiffe://anthropic.com/model/claude-sonnet-4',
      },
    };

    const parsed = parseAttestationResponse({
      [ATTESTATION_CAPABILITY_KEY]: response,
    });

    expect(parsed?.verification_status).toBe('verified');
    expect(parsed?.trust_level).toBe(TrustLevel.PROVIDER);
  });
});

describe('AttestationSessionStore', () => {
  let store: AttestationSessionStore;
  let provider: AttestationProvider;
  let keyPair: Awaited<ReturnType<typeof generateEd25519KeyPair>>;
  let verifier: AttestationVerifier;

  beforeEach(async () => {
    store = new AttestationSessionStore();
    [provider, keyPair] = await createAnthropicProvider();
    verifier = await createTestVerifier(keyPair);
  });

  it('should store and retrieve attestation context', async () => {
    const capability = await buildAttestationCapability({
      provider,
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      targetAudience: 'https://mcp-server.example.com',
    });

    const result = await verifyMcpAttestation(verifier, {
      [ATTESTATION_CAPABILITY_KEY]: capability,
    });

    const context = createAttestationContext(result);
    store.set('session-1', context);

    const retrieved = store.get('session-1');

    expect(retrieved?.verified).toBe(true);
    expect(retrieved?.trustLevel).toBe(TrustLevel.PROVIDER);
  });

  it('should check verification status', async () => {
    const capability = await buildAttestationCapability({
      provider,
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      targetAudience: 'https://mcp-server.example.com',
    });

    const result = await verifyMcpAttestation(verifier, {
      [ATTESTATION_CAPABILITY_KEY]: capability,
    });

    const context = createAttestationContext(result);
    store.set('session-1', context);

    expect(store.isVerified('session-1')).toBe(true);
    expect(store.isVerified('unknown-session')).toBe(false);
  });

  it('should get trust level', async () => {
    const capability = await buildAttestationCapability({
      provider,
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      targetAudience: 'https://mcp-server.example.com',
    });

    const result = await verifyMcpAttestation(verifier, {
      [ATTESTATION_CAPABILITY_KEY]: capability,
    });

    const context = createAttestationContext(result);
    store.set('session-1', context);

    expect(store.getTrustLevel('session-1')).toBe(TrustLevel.PROVIDER);
    expect(store.getTrustLevel('unknown')).toBe(TrustLevel.NONE);
  });

  it('should delete session', () => {
    store.set('session-1', {
      verified: true,
      trustLevel: TrustLevel.PROVIDER,
    });

    store.delete('session-1');

    expect(store.get('session-1')).toBeUndefined();
  });

  it('should clear all sessions', () => {
    store.set('session-1', { verified: true, trustLevel: TrustLevel.PROVIDER });
    store.set('session-2', { verified: true, trustLevel: TrustLevel.PROVIDER });

    store.clear();

    expect(store.size).toBe(0);
  });
});

describe('requireAttestation', () => {
  let store: AttestationSessionStore;

  beforeEach(() => {
    store = new AttestationSessionStore();
  });

  it('should require verified attestation', () => {
    store.set('session-1', { verified: true, trustLevel: TrustLevel.PROVIDER });
    store.set('session-2', { verified: false, trustLevel: TrustLevel.NONE });

    expect(requireAttestation(store, 'session-1')).toBe(true);
    expect(requireAttestation(store, 'session-2')).toBe(false);
    expect(requireAttestation(store, 'unknown')).toBe(false);
  });

  it('should require minimum trust level', () => {
    store.set('session-provider', {
      verified: true,
      trustLevel: TrustLevel.PROVIDER,
    });
    store.set('session-enterprise', {
      verified: true,
      trustLevel: TrustLevel.ENTERPRISE,
    });

    expect(
      requireAttestation(store, 'session-provider', {
        trustLevel: TrustLevel.PROVIDER,
      })
    ).toBe(true);
    expect(
      requireAttestation(store, 'session-enterprise', {
        trustLevel: TrustLevel.PROVIDER,
      })
    ).toBe(false);
  });

  it('should require specific issuer', () => {
    store.set('session-1', {
      verified: true,
      trustLevel: TrustLevel.PROVIDER,
      issuer: 'https://api.anthropic.com',
    });

    expect(
      requireAttestation(store, 'session-1', {
        issuer: 'https://api.anthropic.com',
      })
    ).toBe(true);
    expect(
      requireAttestation(store, 'session-1', {
        issuer: 'https://other.com',
      })
    ).toBe(false);
  });

  it('should support custom check function', () => {
    store.set('session-1', {
      verified: true,
      trustLevel: TrustLevel.PROVIDER,
      agentIdentity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
    });

    const checkClaudeOnly = (ctx: { agentIdentity?: { provider: string } }) =>
      ctx.agentIdentity?.provider === 'anthropic';

    expect(
      requireAttestation(store, 'session-1', {
        check: checkClaudeOnly,
      })
    ).toBe(true);
  });
});

describe('End-to-End Flow', () => {
  it('should complete full attestation flow', async () => {
    // 1. Provider creates key pair and provider
    const [provider, keyPair] = await createAnthropicProvider();

    // 2. Server sets up verifier
    const verifier = await createTestVerifier(keyPair);
    const sessionStore = new AttestationSessionStore();

    // 3. Client builds attestation capability
    const attestationCap = await buildAttestationCapability({
      provider,
      identity: {
        model_family: 'claude-4',
        model_version: 'claude-sonnet-4-20250514',
        provider: 'anthropic',
      },
      targetAudience: 'https://mcp-server.example.com',
    });

    // 4. Client sends initialize request with attestation
    const clientExperimental = {
      [ATTESTATION_CAPABILITY_KEY]: attestationCap,
    };

    // 5. Server verifies attestation
    const verificationResult = await verifyMcpAttestation(verifier, clientExperimental);
    expect(verificationResult.verified).toBe(true);

    // 6. Server stores context
    const context = createAttestationContext(verificationResult);
    sessionStore.set('client-session-1', context);

    // 7. Server builds response
    const serverResponse = buildAttestationResponse(verificationResult, verifier.policy);
    expect(serverResponse.verification_status).toBe('verified');

    // 8. Server can check attestation for tool calls
    expect(requireAttestation(sessionStore, 'client-session-1')).toBe(true);
    expect(
      requireAttestation(sessionStore, 'client-session-1', {
        trustLevel: TrustLevel.PROVIDER,
      })
    ).toBe(true);

    // 9. Client parses response
    const clientExperimentalResponse = {
      [ATTESTATION_CAPABILITY_KEY]: serverResponse,
    };
    const parsedResponse = parseAttestationResponse(clientExperimentalResponse);
    expect(parsedResponse?.verification_status).toBe('verified');
  });
});
