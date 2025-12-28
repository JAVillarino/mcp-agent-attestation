/**
 * MCP Agent Attestation - Core Module
 *
 * Implements attestation token creation and verification using
 * Ed25519 signatures and JWT format.
 *
 * @author Joel Villarino
 * @license MIT
 */

import { SignJWT, jwtVerify, decodeJwt, decodeProtectedHeader } from 'jose';
import type {
  AttestationClaims,
  VerificationResult,
  CreateTokenOptions,
  KeyPair,
  KeyResolver,
  VerificationPolicy,
} from './types.js';
import {
  DEFAULT_TOKEN_LIFETIME_SECONDS,
  CLOCK_SKEW_SECONDS,
  AttestationErrorCode as ErrorCodes,
  TrustLevel as TrustLevels,
  VerificationPolicy as Policies,
  toSpiffeId,
  createAttestationMetadata,
  createSuccessResult,
  createFailureResult,
  AttestationClaimsSchema,
} from './types.js';
import type { ReplayCache } from './replayCache.js';
import { InMemoryReplayCache } from './replayCache.js';

// =============================================================================
// ATTESTATION PROVIDER (TOKEN CREATION)
// =============================================================================

/**
 * Configuration for AttestationProvider.
 */
export interface AttestationProviderConfig {
  /** Issuer URL (e.g., "https://api.anthropic.com") */
  issuer: string;
  /** Key pair for signing tokens */
  keyPair: KeyPair;
  /** Token lifetime in seconds (default: 300 = 5 minutes) */
  tokenLifetimeSeconds?: number;
}

/**
 * Creates attestation tokens for agents.
 *
 * In production, this runs on the model provider's infrastructure.
 * For development/testing, it can be run locally.
 *
 * @example
 * ```typescript
 * const keyPair = await generateEd25519KeyPair('my-key');
 * const provider = new AttestationProvider({
 *   issuer: 'https://api.anthropic.com',
 *   keyPair,
 * });
 *
 * const token = await provider.createToken({
 *   identity: {
 *     model_family: 'claude-4',
 *     model_version: 'claude-sonnet-4-20250514',
 *     provider: 'anthropic',
 *   },
 *   audience: 'https://mcp-server.example.com',
 * });
 * ```
 */
export class AttestationProvider {
  private readonly issuer: string;
  private readonly keyPair: KeyPair;
  private readonly tokenLifetimeSeconds: number;

  constructor(config: AttestationProviderConfig) {
    this.issuer = config.issuer;
    this.keyPair = config.keyPair;
    this.tokenLifetimeSeconds = config.tokenLifetimeSeconds ?? DEFAULT_TOKEN_LIFETIME_SECONDS;
  }

  /**
   * Create a signed attestation token.
   *
   * @param options - Token creation options
   * @returns Promise resolving to signed JWT string
   */
  async createToken(options: CreateTokenOptions): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();

    const payload = {
      iss: this.issuer,
      sub: toSpiffeId(options.identity),
      aud: options.audience,
      iat: now,
      exp: now + this.tokenLifetimeSeconds,
      nbf: now,
      jti,
      agent_identity: options.identity,
      attestation_metadata: createAttestationMetadata(options.metadata),
      ...(options.integrity && { agent_integrity: options.integrity }),
    };

    const jwt = await new SignJWT(payload)
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: 'JWT',
        kid: this.keyPair.kid,
      })
      .sign(this.keyPair.privateKey);

    return jwt;
  }

  /**
   * Get the issuer URL.
   */
  get issuerUrl(): string {
    return this.issuer;
  }

  /**
   * Get the key ID.
   */
  get keyId(): string {
    return this.keyPair.kid;
  }
}

// =============================================================================
// ATTESTATION VERIFIER (TOKEN VALIDATION)
// =============================================================================

/**
 * Configuration for AttestationVerifier.
 */
export interface AttestationVerifierConfig {
  /** List of trusted issuer URLs */
  trustedIssuers: string[];
  /** Key resolver for fetching public keys */
  keyResolver: KeyResolver;
  /** Verification policy (required, preferred, optional) */
  policy?: VerificationPolicy;
  /** Required claims that must be present */
  requiredClaims?: string[];
  /** Expected audience (server URL) */
  audience?: string;
  /** Replay cache for JTI tracking */
  replayCache?: ReplayCache;
  /** Clock skew tolerance in seconds */
  clockSkewSeconds?: number;
}

/**
 * Verifies attestation tokens from agents.
 *
 * Runs on MCP server to validate incoming connections.
 *
 * @example
 * ```typescript
 * const keyResolver = new InMemoryKeyResolver();
 * keyResolver.addKeyPair('https://api.anthropic.com', keyPair);
 *
 * const verifier = new AttestationVerifier({
 *   trustedIssuers: ['https://api.anthropic.com'],
 *   keyResolver,
 *   policy: 'required',
 *   audience: 'https://my-server.com',
 * });
 *
 * const result = await verifier.verify(token);
 * if (result.verified) {
 *   console.log(`Verified! Trust level: ${result.trustLevel}`);
 * }
 * ```
 */
export class AttestationVerifier {
  readonly trustedIssuers: readonly string[];
  readonly policy: VerificationPolicy;
  readonly requiredClaims: readonly string[];
  readonly audience?: string;
  private readonly keyResolver: KeyResolver;
  private readonly replayCache: ReplayCache;
  private readonly clockSkewSeconds: number;

  constructor(config: AttestationVerifierConfig) {
    this.trustedIssuers = config.trustedIssuers;
    this.keyResolver = config.keyResolver;
    this.policy = config.policy ?? Policies.REQUIRED;
    this.requiredClaims = config.requiredClaims ?? ['agent_identity', 'attestation_metadata'];
    this.audience = config.audience;
    this.replayCache = config.replayCache ?? new InMemoryReplayCache();
    this.clockSkewSeconds = config.clockSkewSeconds ?? CLOCK_SKEW_SECONDS;
  }

  /**
   * Verify an attestation token.
   *
   * @param token - JWT token string, or null/undefined if not provided
   * @returns Promise resolving to VerificationResult
   */
  async verify(token: string | null | undefined): Promise<VerificationResult> {
    // Handle missing token based on policy
    if (!token) {
      if (this.policy === Policies.REQUIRED) {
        return createFailureResult(
          'Attestation required but not provided',
          ErrorCodes.REQUIRED
        );
      }
      return {
        verified: false,
        trustLevel: TrustLevels.NONE,
        error: 'No attestation provided',
        verifiedClaims: [],
      };
    }

    try {
      const claims = await this.verifyAndDecode(token);
      return createSuccessResult(claims, TrustLevels.PROVIDER);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return createFailureResult(message, ErrorCodes.INVALID);
    }
  }

  /**
   * Verify token and decode claims.
   *
   * @param token - JWT token string
   * @returns Promise resolving to AttestationClaims
   * @throws Error if verification fails
   */
  private async verifyAndDecode(token: string): Promise<AttestationClaims> {
    // Decode header to get kid
    const header = decodeProtectedHeader(token);
    const kid = header.kid;
    if (!kid) {
      throw new Error('Token missing key ID (kid) in header');
    }

    // Decode payload to get issuer (for key lookup)
    const unverifiedPayload = decodeJwt(token);
    const issuer = unverifiedPayload.iss;
    if (!issuer) {
      throw new Error('Token missing issuer (iss) claim');
    }

    // Verify issuer is trusted
    if (!this.trustedIssuers.includes(issuer)) {
      throw new Error(`Untrusted issuer: ${issuer}`);
    }

    // Get public key for verification
    const publicKey = await this.keyResolver.getKey(issuer, kid);
    if (!publicKey) {
      throw new Error(`Unknown key ID: ${kid}`);
    }

    // Verify signature and decode
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
      issuer: this.trustedIssuers as string[],
      audience: this.audience,
      clockTolerance: this.clockSkewSeconds,
    });

    // Get jti for replay check
    const jti = payload.jti;
    if (!jti) {
      throw new Error('Token missing JWT ID (jti) claim');
    }

    // Get expiration for replay cache
    const exp = payload.exp;
    if (!exp) {
      throw new Error('Token missing expiration (exp) claim');
    }

    // Check for replay
    const isNew = await this.replayCache.checkAndAdd(jti, exp);
    if (!isNew) {
      throw new Error('Token replay detected');
    }

    // Check required claims
    for (const claim of this.requiredClaims) {
      if (!(claim in payload)) {
        throw new Error(`Missing required claim: ${claim}`);
      }
    }

    // Validate and return claims
    const claims = AttestationClaimsSchema.parse(payload);
    return claims;
  }

  /**
   * Clear the replay cache.
   */
  async clearReplayCache(): Promise<void> {
    await this.replayCache.clear();
  }
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

import { generateEd25519KeyPair, InMemoryKeyResolver } from './keys.js';

/**
 * Create a mock Anthropic attestation provider for testing.
 *
 * @param kid - Key ID (default: "anthropic-2025-01")
 * @returns Promise resolving to [provider, keyPair]
 */
export async function createAnthropicProvider(
  kid = 'anthropic-2025-01'
): Promise<[AttestationProvider, KeyPair]> {
  const keyPair = await generateEd25519KeyPair(kid);
  const provider = new AttestationProvider({
    issuer: 'https://api.anthropic.com',
    keyPair,
  });
  return [provider, keyPair];
}

/**
 * Create a verifier configured to trust the test provider.
 *
 * @param providerKeyPair - Key pair from the provider
 * @param policy - Verification policy (default: "required")
 * @returns Promise resolving to AttestationVerifier
 */
export async function createTestVerifier(
  providerKeyPair: KeyPair,
  policy: VerificationPolicy = Policies.REQUIRED
): Promise<AttestationVerifier> {
  const keyResolver = new InMemoryKeyResolver();
  keyResolver.addKeyPair('https://api.anthropic.com', providerKeyPair);

  return new AttestationVerifier({
    trustedIssuers: ['https://api.anthropic.com'],
    keyResolver,
    policy,
  });
}

/**
 * Decode a JWT token without verification (for inspection only).
 *
 * WARNING: This does NOT verify the signature!
 * Only use for debugging/inspection purposes.
 *
 * @param token - JWT token string
 * @returns Decoded header and payload
 */
export function decodeTokenUnsafe(token: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const header = decodeProtectedHeader(token);
  const payload = decodeJwt(token);
  return {
    header: header as Record<string, unknown>,
    payload: payload as Record<string, unknown>,
  };
}

/**
 * Format Unix timestamp as human-readable string.
 *
 * @param timestamp - Unix timestamp in seconds
 * @returns Formatted date string
 */
export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp * 1000).toISOString();
}
