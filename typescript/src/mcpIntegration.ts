/**
 * MCP Agent Attestation - MCP SDK Integration
 *
 * Provides utilities for integrating attestation with the
 * @modelcontextprotocol/sdk package.
 *
 * @author Joel Villarino
 * @license MIT
 */

import type {
  AgentIdentity,
  AgentIntegrity,
  AttestationMetadata,
  AttestationCapability,
  ServerAttestationRequirements,
  AttestationResponse,
  VerificationResult,
  TrustLevel,
  VerificationPolicy,
} from './types.js';
import {
  ATTESTATION_CAPABILITY_KEY,
  ATTESTATION_VERSION,
  TrustLevel as TrustLevels,
} from './types.js';
import { AttestationProvider, AttestationVerifier } from './core.js';

// =============================================================================
// ATTESTATION CONTEXT
// =============================================================================

/**
 * Attestation context stored per session after verification.
 */
export interface AttestationContext {
  /** Whether attestation was verified */
  verified: boolean;
  /** Trust level after verification */
  trustLevel: TrustLevel;
  /** Issuer URL */
  issuer?: string;
  /** Subject (SPIFFE ID) */
  subject?: string;
  /** Agent identity claims */
  agentIdentity?: AgentIdentity;
  /** Attestation metadata */
  attestationMetadata?: AttestationMetadata;
  /** Verification error if any */
  error?: string;
}

/**
 * Create attestation context from verification result.
 *
 * @param result - Verification result
 * @returns AttestationContext
 */
export function createAttestationContext(result: VerificationResult): AttestationContext {
  return {
    verified: result.verified,
    trustLevel: result.trustLevel,
    issuer: result.issuer,
    subject: result.subject,
    agentIdentity: result.claims?.agent_identity,
    attestationMetadata: result.claims?.attestation_metadata,
    error: result.error,
  };
}

// =============================================================================
// CLIENT-SIDE HELPERS
// =============================================================================

/**
 * Configuration for creating attestation-enabled MCP client capabilities.
 */
export interface AttestingClientConfig {
  /** Attestation provider for creating tokens */
  provider: AttestationProvider;
  /** Agent identity claims */
  identity: AgentIdentity;
  /** Target server URL (used as audience) */
  targetAudience: string;
  /** Optional integrity hashes */
  integrity?: AgentIntegrity;
  /** Optional attestation metadata */
  metadata?: Partial<AttestationMetadata>;
}

/**
 * Build attestation capability for MCP experimental field.
 *
 * Use this when creating MCP client capabilities to include attestation.
 *
 * @example
 * ```typescript
 * const attestationCap = await buildAttestationCapability({
 *   provider,
 *   identity: {
 *     model_family: 'claude-4',
 *     model_version: 'claude-sonnet-4-20250514',
 *     provider: 'anthropic',
 *   },
 *   targetAudience: 'https://my-mcp-server.com',
 * });
 *
 * // Include in MCP initialize request
 * const capabilities = {
 *   experimental: {
 *     [ATTESTATION_CAPABILITY_KEY]: attestationCap,
 *   },
 *   // ... other capabilities
 * };
 * ```
 */
export async function buildAttestationCapability(
  config: AttestingClientConfig
): Promise<AttestationCapability> {
  const token = await config.provider.createToken({
    identity: config.identity,
    audience: config.targetAudience,
    integrity: config.integrity,
    metadata: config.metadata,
  });

  return {
    version: ATTESTATION_VERSION,
    token,
    supported_algorithms: ['EdDSA'],
    attestation_types: ['provider', 'enterprise'],
  };
}

/**
 * Extract attestation token from MCP initialize params.
 *
 * @param experimentalCaps - Experimental capabilities from initialize request
 * @returns Token string or undefined
 */
export function extractAttestationToken(
  experimentalCaps?: Record<string, unknown>
): string | undefined {
  if (!experimentalCaps) {
    return undefined;
  }

  const attestationCap = experimentalCaps[ATTESTATION_CAPABILITY_KEY];
  if (typeof attestationCap !== 'object' || attestationCap === null) {
    return undefined;
  }

  const cap = attestationCap as Record<string, unknown>;
  if (typeof cap.token === 'string') {
    return cap.token;
  }

  return undefined;
}

/**
 * Check attestation response from server.
 *
 * @param experimentalCaps - Experimental capabilities from server response
 * @returns AttestationResponse or undefined
 */
export function parseAttestationResponse(
  experimentalCaps?: Record<string, unknown>
): AttestationResponse | undefined {
  if (!experimentalCaps) {
    return undefined;
  }

  const attestationCap = experimentalCaps[ATTESTATION_CAPABILITY_KEY];
  if (typeof attestationCap !== 'object' || attestationCap === null) {
    return undefined;
  }

  const cap = attestationCap as Record<string, unknown>;
  if (cap.verification_status !== 'verified' && cap.verification_status !== 'failed') {
    return undefined;
  }

  return cap as unknown as AttestationResponse;
}

// =============================================================================
// SERVER-SIDE HELPERS
// =============================================================================

/**
 * Configuration for attestation-enabled MCP server.
 */
export interface AttestingServerConfig {
  /** Attestation verifier */
  verifier: AttestationVerifier;
}

/**
 * Build server attestation requirements for MCP experimental field.
 *
 * Include this in server capabilities to inform clients about
 * attestation requirements.
 *
 * @example
 * ```typescript
 * const requirements = buildServerAttestationRequirements(verifier);
 *
 * // Include in MCP server capabilities
 * const capabilities = {
 *   experimental: {
 *     [ATTESTATION_CAPABILITY_KEY]: requirements,
 *   },
 *   // ... other capabilities
 * };
 * ```
 */
export function buildServerAttestationRequirements(
  verifier: AttestationVerifier
): ServerAttestationRequirements {
  return {
    version: ATTESTATION_VERSION,
    policy: verifier.policy,
    trusted_issuers: [...verifier.trustedIssuers],
    required_claims: [...verifier.requiredClaims],
  };
}

/**
 * Build attestation response for server capabilities.
 *
 * @param result - Verification result
 * @param policy - Server policy
 * @returns AttestationResponse
 */
export function buildAttestationResponse(
  result: VerificationResult,
  policy: VerificationPolicy
): AttestationResponse {
  if (result.verified) {
    return {
      version: ATTESTATION_VERSION,
      verification_status: 'verified',
      trust_level: result.trustLevel,
      verified_claims: result.claims
        ? {
            issuer: result.claims.iss,
            subject: result.claims.sub,
          }
        : undefined,
      policy,
    };
  }

  return {
    version: ATTESTATION_VERSION,
    verification_status: 'failed',
    error: result.error ?? 'Unknown error',
    policy,
  };
}

/**
 * Verify attestation from MCP initialize request.
 *
 * Use this on the server side to verify incoming attestation tokens.
 *
 * @example
 * ```typescript
 * // In MCP server initialize handler
 * const result = await verifyMcpAttestation(
 *   verifier,
 *   request.params.capabilities?.experimental
 * );
 *
 * if (!result.verified && verifier.policy === 'required') {
 *   throw new Error(`Attestation required: ${result.error}`);
 * }
 *
 * // Store context for session
 * sessionContext.attestation = createAttestationContext(result);
 * ```
 */
export async function verifyMcpAttestation(
  verifier: AttestationVerifier,
  experimentalCaps?: Record<string, unknown>
): Promise<VerificationResult> {
  const token = extractAttestationToken(experimentalCaps);
  return verifier.verify(token);
}

// =============================================================================
// SESSION MANAGEMENT
// =============================================================================

/**
 * Session store for attestation contexts.
 *
 * Stores verified attestation information per session for later access.
 */
export class AttestationSessionStore {
  private sessions: Map<string, AttestationContext> = new Map();

  /**
   * Store attestation context for a session.
   *
   * @param sessionId - Unique session identifier
   * @param context - Attestation context to store
   */
  set(sessionId: string, context: AttestationContext): void {
    this.sessions.set(sessionId, context);
  }

  /**
   * Get attestation context for a session.
   *
   * @param sessionId - Session identifier
   * @returns AttestationContext or undefined
   */
  get(sessionId: string): AttestationContext | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Check if session has verified attestation.
   *
   * @param sessionId - Session identifier
   * @returns true if verified
   */
  isVerified(sessionId: string): boolean {
    return this.sessions.get(sessionId)?.verified ?? false;
  }

  /**
   * Get trust level for a session.
   *
   * @param sessionId - Session identifier
   * @returns TrustLevel or 'none'
   */
  getTrustLevel(sessionId: string): TrustLevel {
    return this.sessions.get(sessionId)?.trustLevel ?? TrustLevels.NONE;
  }

  /**
   * Remove attestation context for a session.
   *
   * Call this when a session ends to prevent memory leaks.
   *
   * @param sessionId - Session identifier
   */
  delete(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Clear all sessions.
   */
  clear(): void {
    this.sessions.clear();
  }

  /**
   * Get count of stored sessions.
   */
  get size(): number {
    return this.sessions.size;
  }
}

// =============================================================================
// AUTHORIZATION HELPERS
// =============================================================================

/**
 * Check if session meets attestation requirements.
 *
 * Use this in tool handlers to enforce attestation requirements.
 *
 * @example
 * ```typescript
 * // In a tool handler
 * if (!requireAttestation(sessionStore, sessionId)) {
 *   throw new Error('Attestation required for this operation');
 * }
 *
 * // Or with trust level
 * if (!requireAttestation(sessionStore, sessionId, { trustLevel: 'provider' })) {
 *   throw new Error('Provider attestation required');
 * }
 * ```
 */
export function requireAttestation(
  store: AttestationSessionStore,
  sessionId: string,
  options?: {
    /** Minimum required trust level */
    trustLevel?: TrustLevel;
    /** Required issuer */
    issuer?: string;
    /** Custom check function */
    check?: (context: AttestationContext) => boolean;
  }
): boolean {
  const context = store.get(sessionId);

  if (!context || !context.verified) {
    return false;
  }

  if (options?.trustLevel) {
    const trustOrder: TrustLevel[] = ['none', 'enterprise', 'provider'];
    const requiredIndex = trustOrder.indexOf(options.trustLevel);
    const actualIndex = trustOrder.indexOf(context.trustLevel);
    if (actualIndex < requiredIndex) {
      return false;
    }
  }

  if (options?.issuer && context.issuer !== options.issuer) {
    return false;
  }

  if (options?.check && !options.check(context)) {
    return false;
  }

  return true;
}

// =============================================================================
// RE-EXPORTS
// =============================================================================

export { ATTESTATION_CAPABILITY_KEY, ATTESTATION_VERSION };
