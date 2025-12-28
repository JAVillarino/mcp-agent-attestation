/**
 * MCP Agent Attestation - Attack Simulations
 *
 * Demonstrates various attack scenarios and how attestation prevents them.
 * All 8 attack vectors from the Python implementation.
 *
 * @author Joel Villarino
 * @license MIT
 */

import { base64url } from 'jose';
import {
  AttestationProvider,
  AttestationVerifier,
  createAnthropicProvider,
  createTestVerifier,
} from './core.js';
import { generateEd25519KeyPair, InMemoryKeyResolver } from './keys.js';
import type { AgentIdentity, KeyPair } from './types.js';
import { VerificationPolicy } from './types.js';

// =============================================================================
// ATTACK TYPES
// =============================================================================

/** Categories of attacks the attestation system defends against */
export const AttackType = {
  MODEL_SPOOFING: 'model_spoofing',
  PROVENANCE_FORGERY: 'provenance_forgery',
  TOKEN_REPLAY: 'token_replay',
  TOKEN_TAMPERING: 'token_tampering',
  ISSUER_SPOOFING: 'issuer_spoofing',
  DOWNGRADE_ATTACK: 'downgrade_attack',
  AUDIENCE_MISMATCH: 'audience_mismatch',
  SAFETY_DOWNGRADE: 'safety_downgrade',
} as const;
export type AttackType = (typeof AttackType)[keyof typeof AttackType];

/** Result of an attack simulation */
export interface AttackResult {
  attackType: AttackType;
  attackName: string;
  description: string;
  blocked: boolean;
  errorMessage?: string;
  details: Record<string, unknown>;
}

// =============================================================================
// ATTACK SIMULATOR
// =============================================================================

/**
 * Simulates various attack scenarios against the attestation system.
 *
 * @example
 * ```typescript
 * const simulator = await AttackSimulator.create();
 * const results = await simulator.runAllAttacks();
 * printAttackReport(results);
 * ```
 */
export class AttackSimulator {
  private provider: AttestationProvider;
  private keyPair: KeyPair;
  private verifier: AttestationVerifier;
  private readonly legitIdentity: AgentIdentity;
  private readonly serverUrl: string;

  private constructor(
    provider: AttestationProvider,
    keyPair: KeyPair,
    verifier: AttestationVerifier
  ) {
    this.provider = provider;
    this.keyPair = keyPair;
    this.verifier = verifier;
    this.legitIdentity = {
      model_family: 'claude-4',
      model_version: 'claude-sonnet-4-20250514',
      provider: 'anthropic',
    };
    this.serverUrl = 'https://mcp-server.example.com';
  }

  /**
   * Create a new attack simulator.
   */
  static async create(): Promise<AttackSimulator> {
    const [provider, keyPair] = await createAnthropicProvider();
    const verifier = await createTestVerifier(keyPair, VerificationPolicy.REQUIRED);
    return new AttackSimulator(provider, keyPair, verifier);
  }

  /**
   * Run all attack simulations.
   *
   * @returns Promise resolving to array of AttackResult
   */
  async runAllAttacks(): Promise<AttackResult[]> {
    const attacks = [
      () => this.attackModelSpoofing(),
      () => this.attackProvenanceForgery(),
      () => this.attackTokenReplay(),
      () => this.attackTokenTampering(),
      () => this.attackIssuerSpoofing(),
      () => this.attackDowngrade(),
      () => this.attackAudienceMismatch(),
      () => this.attackSafetyDowngrade(),
    ];

    const results: AttackResult[] = [];
    for (const attack of attacks) {
      results.push(await attack());
    }
    return results;
  }

  /**
   * Attack: Attacker claims to be Claude but uses their own signing key.
   * Defense: Signature verification fails - unknown key.
   */
  async attackModelSpoofing(): Promise<AttackResult> {
    // Attacker generates their own key
    const attackerKeyPair = await generateEd25519KeyPair('attacker-key');
    const attackerProvider = new AttestationProvider({
      issuer: 'https://api.anthropic.com', // Claims to be Anthropic
      keyPair: attackerKeyPair,
    });

    // Create fake token claiming to be Claude
    const fakeToken = await attackerProvider.createToken({
      identity: this.legitIdentity,
      audience: this.serverUrl,
    });

    // Verify - should fail because key is unknown
    const result = await this.verifier.verify(fakeToken);

    return {
      attackType: AttackType.MODEL_SPOOFING,
      attackName: 'Model Spoofing',
      description: 'Attacker claims to be Claude using forged token',
      blocked: !result.verified,
      errorMessage: result.error,
      details: {
        attacker_claimed: 'claude-sonnet-4',
        reason: 'Unknown signing key',
      },
    };
  }

  /**
   * Attack: Token from untrusted issuer.
   * Defense: Issuer not in trusted list.
   */
  async attackProvenanceForgery(): Promise<AttackResult> {
    const attackerKeyPair = await generateEd25519KeyPair('malicious-provider');
    const attackerProvider = new AttestationProvider({
      issuer: 'https://evil-llm-provider.com', // Untrusted issuer
      keyPair: attackerKeyPair,
    });

    const fakeToken = await attackerProvider.createToken({
      identity: this.legitIdentity,
      audience: this.serverUrl,
    });

    const result = await this.verifier.verify(fakeToken);

    return {
      attackType: AttackType.PROVENANCE_FORGERY,
      attackName: 'Provenance Forgery',
      description: 'Token from untrusted issuer',
      blocked: !result.verified,
      errorMessage: result.error,
      details: {
        attacker_issuer: 'https://evil-llm-provider.com',
        trusted_issuers: this.verifier.trustedIssuers,
      },
    };
  }

  /**
   * Attack: Replay captured token.
   * Defense: JTI cache detects replay.
   */
  async attackTokenReplay(): Promise<AttackResult> {
    // Create a legitimate token
    const legitToken = await this.provider.createToken({
      identity: this.legitIdentity,
      audience: this.serverUrl,
    });

    // First use - should succeed
    const firstResult = await this.verifier.verify(legitToken);
    const firstSuccess = firstResult.verified;

    // Replay - should be blocked
    const replayResult = await this.verifier.verify(legitToken);
    const replayBlocked = !replayResult.verified;

    return {
      attackType: AttackType.TOKEN_REPLAY,
      attackName: 'Token Replay',
      description: 'Attacker replays intercepted token',
      blocked: replayBlocked,
      errorMessage: replayBlocked ? replayResult.error : undefined,
      details: {
        first_use_success: firstSuccess,
        replay_blocked: replayBlocked,
      },
    };
  }

  /**
   * Attack: Modify token claims after signing.
   * Defense: Signature verification fails.
   */
  async attackTokenTampering(): Promise<AttackResult> {
    // Create legitimate token
    const legitToken = await this.provider.createToken({
      identity: this.legitIdentity,
      audience: this.serverUrl,
    });

    // Split token and decode payload
    const parts = legitToken.split('.');
    const payloadJson = new TextDecoder().decode(base64url.decode(parts[1]!));
    const payload = JSON.parse(payloadJson);

    // Tamper with expiration (extend by 1 year)
    payload.exp = Math.floor(Date.now() / 1000) + 86400 * 365;

    // Re-encode payload
    const tamperedPayload = base64url.encode(JSON.stringify(payload));
    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    // Verify - should fail due to signature mismatch
    const result = await this.verifier.verify(tamperedToken);

    return {
      attackType: AttackType.TOKEN_TAMPERING,
      attackName: 'Token Tampering',
      description: 'Attacker modifies token claims without re-signing',
      blocked: !result.verified,
      errorMessage: result.error,
      details: {
        modification: 'Extended expiration by 1 year',
      },
    };
  }

  /**
   * Attack: Typosquatted issuer domain.
   * Defense: Strict issuer allowlist.
   */
  async attackIssuerSpoofing(): Promise<AttackResult> {
    const attackerKeyPair = await generateEd25519KeyPair('typosquat-key');
    const attackerProvider = new AttestationProvider({
      issuer: 'https://api.anthropic.org', // .org instead of .com
      keyPair: attackerKeyPair,
    });

    const fakeToken = await attackerProvider.createToken({
      identity: this.legitIdentity,
      audience: this.serverUrl,
    });

    const result = await this.verifier.verify(fakeToken);

    return {
      attackType: AttackType.ISSUER_SPOOFING,
      attackName: 'Issuer Typosquatting',
      description: 'Attacker uses similar-looking issuer domain',
      blocked: !result.verified,
      errorMessage: result.error,
      details: {
        fake_issuer: 'https://api.anthropic.org',
        real_issuer: 'https://api.anthropic.com',
      },
    };
  }

  /**
   * Attack: Omit attestation entirely.
   * Defense: REQUIRED policy rejects.
   */
  async attackDowngrade(): Promise<AttackResult> {
    // Create verifier with REQUIRED policy
    const requiredVerifier = await createTestVerifier(
      this.keyPair,
      VerificationPolicy.REQUIRED
    );

    // Try to connect without attestation
    const result = await requiredVerifier.verify(null);

    return {
      attackType: AttackType.DOWNGRADE_ATTACK,
      attackName: 'Downgrade Attack',
      description: 'Attacker omits attestation entirely',
      blocked: !result.verified,
      errorMessage: result.error,
      details: {
        policy: 'REQUIRED',
        token_provided: false,
      },
    };
  }

  /**
   * Attack: Use token for different server.
   * Defense: Audience validation.
   */
  async attackAudienceMismatch(): Promise<AttackResult> {
    // Create verifier for server B
    const keyResolver = new InMemoryKeyResolver();
    keyResolver.addKeyPair('https://api.anthropic.com', this.keyPair);

    const audienceVerifier = new AttestationVerifier({
      trustedIssuers: ['https://api.anthropic.com'],
      keyResolver,
      policy: VerificationPolicy.REQUIRED,
      audience: 'https://server-b.example.com',
    });

    // Create token for server A
    const tokenForServerA = await this.provider.createToken({
      identity: this.legitIdentity,
      audience: 'https://server-a.example.com',
    });

    // Try to use on server B
    const result = await audienceVerifier.verify(tokenForServerA);

    return {
      attackType: AttackType.AUDIENCE_MISMATCH,
      attackName: 'Audience Mismatch',
      description: 'Token intended for different server',
      blocked: !result.verified,
      errorMessage: result.error,
      details: {
        token_audience: 'https://server-a.example.com',
        server_identity: 'https://server-b.example.com',
      },
    };
  }

  /**
   * Attack: Modify safety level in token.
   * Defense: Signature verification (reduces to tampering).
   */
  async attackSafetyDowngrade(): Promise<AttackResult> {
    // Create token with enhanced safety
    const legitToken = await this.provider.createToken({
      identity: this.legitIdentity,
      audience: this.serverUrl,
      metadata: { safety_level: 'enhanced' },
    });

    // Split and decode
    const parts = legitToken.split('.');
    const payloadJson = new TextDecoder().decode(base64url.decode(parts[1]!));
    const payload = JSON.parse(payloadJson);

    // Tamper with safety level
    payload.attestation_metadata.safety_level = 'minimal';

    // Re-encode
    const tamperedPayload = base64url.encode(JSON.stringify(payload));
    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    const result = await this.verifier.verify(tamperedToken);

    return {
      attackType: AttackType.SAFETY_DOWNGRADE,
      attackName: 'Safety Level Downgrade',
      description: 'Attacker modifies safety level claim',
      blocked: !result.verified,
      errorMessage: result.error,
      details: {
        original_safety: 'enhanced',
        attempted_safety: 'minimal',
      },
    };
  }
}

// =============================================================================
// REPORT GENERATION
// =============================================================================

/**
 * Print formatted attack simulation report.
 *
 * @param results - Array of attack results
 */
export function printAttackReport(results: AttackResult[]): void {
  console.log('\n' + '='.repeat(70));
  console.log('MCP AGENT ATTESTATION - ATTACK SIMULATION REPORT');
  console.log('='.repeat(70));

  const blockedCount = results.filter((r) => r.blocked).length;
  const totalCount = results.length;

  console.log(`\nSummary: ${blockedCount}/${totalCount} attacks blocked`);
  console.log('-'.repeat(70));

  results.forEach((result, index) => {
    const status = result.blocked ? '✅ BLOCKED' : '❌ NOT BLOCKED';
    console.log(`\n[${index + 1}] ${result.attackName}`);
    console.log(`    Type: ${result.attackType}`);
    console.log(`    Status: ${status}`);
    console.log(`    Description: ${result.description}`);

    if (result.errorMessage) {
      console.log(`    Error: ${result.errorMessage}`);
    }

    if (Object.keys(result.details).length > 0) {
      console.log('    Details:');
      for (const [key, value] of Object.entries(result.details)) {
        console.log(`      - ${key}: ${JSON.stringify(value)}`);
      }
    }
  });

  console.log('\n' + '-'.repeat(70));
  console.log(`Detection Rate: ${((blockedCount / totalCount) * 100).toFixed(1)}%`);
  console.log('='.repeat(70));
}

/**
 * Run attack simulations and print report.
 */
export async function runAttackSimulations(): Promise<AttackResult[]> {
  console.log('Initializing attack simulator...');
  const simulator = await AttackSimulator.create();

  console.log('Running attack simulations...');
  const results = await simulator.runAllAttacks();
  printAttackReport(results);

  return results;
}
