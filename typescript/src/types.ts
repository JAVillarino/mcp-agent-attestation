/**
 * MCP Agent Attestation - Types and Schemas
 *
 * Zod schemas for runtime validation and TypeScript types for the
 * attestation token structure.
 *
 * @author Joel Villarino
 * @license MIT
 */

import { z } from 'zod';

// =============================================================================
// ENUMS AND CONSTANTS
// =============================================================================

/** Type of attestation issuer */
export const AttestationType = {
  PROVIDER: 'provider',
  ENTERPRISE: 'enterprise',
} as const;
export type AttestationType = (typeof AttestationType)[keyof typeof AttestationType];

/** Model safety configuration level */
export const SafetyLevel = {
  STANDARD: 'standard',
  ENHANCED: 'enhanced',
  MINIMAL: 'minimal',
} as const;
export type SafetyLevel = (typeof SafetyLevel)[keyof typeof SafetyLevel];

/** Server attestation policy */
export const VerificationPolicy = {
  REQUIRED: 'required',
  PREFERRED: 'preferred',
  OPTIONAL: 'optional',
} as const;
export type VerificationPolicy = (typeof VerificationPolicy)[keyof typeof VerificationPolicy];

/** Resulting trust level after verification */
export const TrustLevel = {
  PROVIDER: 'provider',
  ENTERPRISE: 'enterprise',
  NONE: 'none',
} as const;
export type TrustLevel = (typeof TrustLevel)[keyof typeof TrustLevel];

/** Attestation protocol version */
export const ATTESTATION_VERSION = '0.1.0';

/** Default token lifetime (5 minutes) */
export const DEFAULT_TOKEN_LIFETIME_SECONDS = 300;

/** Clock skew tolerance (30 seconds) */
export const CLOCK_SKEW_SECONDS = 30;

/** MCP experimental capability key */
export const ATTESTATION_CAPABILITY_KEY = 'security.attestation';

// =============================================================================
// ERROR CODES
// =============================================================================

/** Error codes for attestation failures (matches MCP JSON-RPC error codes) */
export const AttestationErrorCode = {
  REQUIRED: -32001,
  INVALID: -32002,
  EXPIRED: -32003,
  REPLAY: -32004,
  UNTRUSTED_ISSUER: -32005,
  INSUFFICIENT_CLAIMS: -32006,
} as const;
export type AttestationErrorCode =
  (typeof AttestationErrorCode)[keyof typeof AttestationErrorCode];

// =============================================================================
// ZOD SCHEMAS
// =============================================================================

/** Agent identity schema */
export const AgentIdentitySchema = z.object({
  model_family: z.string().min(1),
  model_version: z.string().min(1),
  provider: z.string().min(1),
  deployment_id: z.string().optional(),
});
export type AgentIdentity = z.infer<typeof AgentIdentitySchema>;

/** Agent integrity schema (hashes) */
export const AgentIntegritySchema = z.object({
  config_hash: z.string().optional(),
  system_prompt_hash: z.string().optional(),
});
export type AgentIntegrity = z.infer<typeof AgentIntegritySchema>;

/** Attestation metadata schema */
export const AttestationMetadataSchema = z.object({
  attestation_version: z.string().default(ATTESTATION_VERSION),
  attestation_type: z.enum(['provider', 'enterprise']).default('provider'),
  safety_level: z.enum(['standard', 'enhanced', 'minimal']).default('standard'),
  capabilities_declared: z.array(z.string()).default([]),
});
export type AttestationMetadata = z.infer<typeof AttestationMetadataSchema>;

/** Confirmation key schema (for proof-of-possession) */
export const ConfirmationKeySchema = z.object({
  jwk: z
    .object({
      kty: z.string(),
      crv: z.string(),
      x: z.string(),
      kid: z.string().optional(),
    })
    .optional(),
  tls_binding: z.record(z.string()).optional(),
});
export type ConfirmationKey = z.infer<typeof ConfirmationKeySchema>;

/** JWK (JSON Web Key) schema for Ed25519 */
export const Ed25519JWKSchema = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  kid: z.string(),
  x: z.string(),
  use: z.literal('sig').optional(),
  alg: z.literal('EdDSA').optional(),
  d: z.string().optional(), // Private key component (only for private keys)
});
export type Ed25519JWK = z.infer<typeof Ed25519JWKSchema>;

/** JWKS (JSON Web Key Set) schema */
export const JWKSSchema = z.object({
  keys: z.array(Ed25519JWKSchema),
});
export type JWKS = z.infer<typeof JWKSSchema>;

/** Complete JWT payload schema for attestation token */
export const AttestationClaimsSchema = z.object({
  // Standard JWT claims
  iss: z.string().url(),
  sub: z.string().min(1),
  aud: z.union([z.string(), z.array(z.string())]),
  iat: z.number().int().positive(),
  exp: z.number().int().positive(),
  jti: z.string().uuid(),
  nbf: z.number().int().positive().optional(),

  // Attestation-specific claims
  agent_identity: AgentIdentitySchema,
  attestation_metadata: AttestationMetadataSchema,

  // Optional claims
  agent_integrity: AgentIntegritySchema.optional(),
  cnf: ConfirmationKeySchema.optional(),
});
export type AttestationClaims = z.infer<typeof AttestationClaimsSchema>;

/** JWT header schema */
export const JWTHeaderSchema = z.object({
  alg: z.literal('EdDSA'),
  typ: z.literal('JWT').optional(),
  kid: z.string(),
});
export type JWTHeader = z.infer<typeof JWTHeaderSchema>;

// =============================================================================
// RESULT TYPES
// =============================================================================

/** Verification result */
export interface VerificationResult {
  verified: boolean;
  trustLevel: TrustLevel;
  issuer?: string;
  subject?: string;
  claims?: AttestationClaims;
  verifiedClaims: string[];
  error?: string;
  errorCode?: AttestationErrorCode;
}

/** Options for creating attestation tokens */
export interface CreateTokenOptions {
  identity: AgentIdentity;
  audience: string | string[];
  integrity?: AgentIntegrity;
  metadata?: Partial<AttestationMetadata>;
}

/** Options for verifying attestation tokens */
export interface VerifyOptions {
  audience?: string;
  clockSkewSeconds?: number;
}

/** Key-like type for jose library compatibility */
export type KeyLike = import('jose').KeyLike;

/** Key pair with public and private key */
export interface KeyPair {
  privateKey: KeyLike;
  publicKey: KeyLike;
  kid: string;
}

/** Key resolver interface for fetching public keys */
export interface KeyResolver {
  getKey(issuer: string, kid: string): Promise<KeyLike | null>;
}

// =============================================================================
// MCP INTEGRATION TYPES
// =============================================================================

/** Attestation capability for MCP experimental field */
export interface AttestationCapability {
  version: string;
  token?: string;
  supported_algorithms?: string[];
  attestation_types?: string[];
}

/** Server attestation requirements */
export interface ServerAttestationRequirements {
  version: string;
  policy: VerificationPolicy;
  trusted_issuers: string[];
  required_claims: string[];
}

/** Server attestation response */
export interface AttestationResponse {
  version: string;
  verification_status: 'verified' | 'failed';
  trust_level?: TrustLevel;
  verified_claims?: {
    issuer: string;
    subject: string;
  };
  error?: string;
  policy?: VerificationPolicy;
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Create a default AgentIdentity
 */
export function createAgentIdentity(
  modelFamily: string,
  modelVersion: string,
  provider: string,
  deploymentId?: string
): AgentIdentity {
  return {
    model_family: modelFamily,
    model_version: modelVersion,
    provider,
    deployment_id: deploymentId,
  };
}

/**
 * Create a default AttestationMetadata
 */
export function createAttestationMetadata(
  options?: Partial<AttestationMetadata>
): AttestationMetadata {
  return AttestationMetadataSchema.parse(options ?? {});
}

/**
 * Generate SPIFFE ID from agent identity
 */
export function toSpiffeId(identity: AgentIdentity, trustDomain?: string): string {
  const domain = trustDomain ?? `${identity.provider}.com`;
  return `spiffe://${domain}/model/${identity.model_version}`;
}

/**
 * Compute SHA256 hash of content with prefix
 */
export async function computeHash(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return `sha256:${hashHex}`;
}

/**
 * Create AgentIntegrity with computed hashes
 */
export async function createAgentIntegrity(
  config?: string,
  systemPrompt?: string
): Promise<AgentIntegrity> {
  const integrity: AgentIntegrity = {};
  if (config) {
    integrity.config_hash = await computeHash(config);
  }
  if (systemPrompt) {
    integrity.system_prompt_hash = await computeHash(systemPrompt);
  }
  return integrity;
}

/**
 * Create a successful verification result
 */
export function createSuccessResult(
  claims: AttestationClaims,
  trustLevel: TrustLevel = TrustLevel.PROVIDER
): VerificationResult {
  return {
    verified: true,
    trustLevel,
    issuer: claims.iss,
    subject: claims.sub,
    claims,
    verifiedClaims: ['agent_identity', 'attestation_metadata'],
  };
}

/**
 * Create a failed verification result
 */
export function createFailureResult(
  error: string,
  errorCode: AttestationErrorCode
): VerificationResult {
  return {
    verified: false,
    trustLevel: TrustLevel.NONE,
    error,
    errorCode,
    verifiedClaims: [],
  };
}
