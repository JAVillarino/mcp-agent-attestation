/**
 * MCP Agent Attestation
 *
 * Cryptographic attestation extension for MCP enabling servers
 * to verify agent identity using JWT tokens with Ed25519 signatures.
 *
 * @author Joel Villarino
 * @license MIT
 * @packageDocumentation
 */

// =============================================================================
// TYPES AND SCHEMAS
// =============================================================================

export {
  // Enums and constants
  AttestationType,
  SafetyLevel,
  VerificationPolicy,
  TrustLevel,
  ATTESTATION_VERSION,
  DEFAULT_TOKEN_LIFETIME_SECONDS,
  CLOCK_SKEW_SECONDS,
  ATTESTATION_CAPABILITY_KEY,
  AttestationErrorCode,

  // Zod schemas
  AgentIdentitySchema,
  AgentIntegritySchema,
  AttestationMetadataSchema,
  ConfirmationKeySchema,
  Ed25519JWKSchema,
  JWKSSchema,
  AttestationClaimsSchema,
  JWTHeaderSchema,

  // Helper functions
  createAgentIdentity,
  createAttestationMetadata,
  toSpiffeId,
  computeHash,
  createAgentIntegrity,
  createSuccessResult,
  createFailureResult,
} from './types.js';

export type {
  // Types inferred from schemas
  AgentIdentity,
  AgentIntegrity,
  AttestationMetadata,
  ConfirmationKey,
  Ed25519JWK,
  JWKS,
  AttestationClaims,
  JWTHeader,

  // Result types
  VerificationResult,
  CreateTokenOptions,
  VerifyOptions,
  KeyPair,
  KeyResolver,

  // MCP integration types
  AttestationCapability,
  ServerAttestationRequirements,
  AttestationResponse,
} from './types.js';

// =============================================================================
// CORE FUNCTIONALITY
// =============================================================================

export {
  AttestationProvider,
  AttestationVerifier,
  createAnthropicProvider,
  createTestVerifier,
  decodeTokenUnsafe,
  formatTimestamp,
} from './core.js';

export type {
  AttestationProviderConfig,
  AttestationVerifierConfig,
} from './core.js';

// =============================================================================
// KEY MANAGEMENT
// =============================================================================

export {
  generateEd25519KeyPair,
  exportPublicKeyAsJWK,
  exportPrivateKeyAsJWK,
  importPublicKeyFromJWK,
  importPrivateKeyFromJWK,
  importKeyPairFromJWK,
  InMemoryKeyResolver,
  JWKSFetcher,
  JWKSKeyResolver,
} from './keys.js';

export type { JWKSFetcherConfig } from './keys.js';

// =============================================================================
// REPLAY CACHE
// =============================================================================

export {
  InMemoryReplayCache,
  LRUReplayCache,
  NoopReplayCache,
} from './replayCache.js';

export type { ReplayCache } from './replayCache.js';

// =============================================================================
// ATTACK SIMULATION
// =============================================================================

export {
  AttackType,
  AttackSimulator,
  printAttackReport,
  runAttackSimulations,
} from './attacks.js';

export type { AttackResult } from './attacks.js';

// =============================================================================
// MCP INTEGRATION
// =============================================================================

export {
  createAttestationContext,
  buildAttestationCapability,
  extractAttestationToken,
  parseAttestationResponse,
  buildServerAttestationRequirements,
  buildAttestationResponse,
  verifyMcpAttestation,
  AttestationSessionStore,
  requireAttestation,
} from './mcpIntegration.js';

export type {
  AttestationContext,
  AttestingClientConfig,
  AttestingServerConfig,
} from './mcpIntegration.js';
