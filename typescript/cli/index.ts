#!/usr/bin/env node
/**
 * MCP Agent Attestation - CLI Tools
 *
 * Command-line interface for generating, verifying, and inspecting attestation tokens.
 *
 * Usage:
 *   npx mcp-attestation generate --issuer URL --audience URL
 *   npx mcp-attestation verify TOKEN
 *   npx mcp-attestation inspect TOKEN
 *   npx mcp-attestation keygen [--kid KEY_ID]
 *   npx mcp-attestation attack
 *
 * @author Joel Villarino
 * @license MIT
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs/promises';
import {
  AttestationProvider,
  AttestationVerifier,
  generateEd25519KeyPair,
  exportPublicKeyAsJWK,
  exportPrivateKeyAsJWK,
  importKeyPairFromJWK,
  InMemoryKeyResolver,
  decodeTokenUnsafe,
  formatTimestamp,
  runAttackSimulations,
  VerificationPolicy,
} from '../src/index.js';
import type { Ed25519JWK } from '../src/index.js';

// =============================================================================
// COMMAND HANDLERS
// =============================================================================

async function cmdGenerate(options: {
  issuer: string;
  audience: string;
  modelFamily?: string;
  modelVersion?: string;
  providerName?: string;
  deploymentId?: string;
  lifetime?: number;
  safetyLevel?: string;
  capabilities?: string;
  systemPrompt?: string;
  kid?: string;
  keyFile?: string;
  output?: string;
}): Promise<number> {
  // Generate or load key
  let keyPair: Awaited<ReturnType<typeof generateEd25519KeyPair>>;

  if (options.keyFile) {
    console.error(`Loading key from ${options.keyFile}...`);
    const jwkJson = await fs.readFile(options.keyFile, 'utf-8');
    const jwk = JSON.parse(jwkJson) as Ed25519JWK;
    keyPair = await importKeyPairFromJWK(jwk);
  } else {
    const kid = options.kid ?? `cli-key-${new Date().toISOString().slice(0, 10)}`;
    keyPair = await generateEd25519KeyPair(kid);
  }

  // Create provider
  const provider = new AttestationProvider({
    issuer: options.issuer,
    keyPair,
    tokenLifetimeSeconds: options.lifetime ?? 300,
  });

  // Create token
  const token = await provider.createToken({
    identity: {
      model_family: options.modelFamily ?? 'claude-4',
      model_version: options.modelVersion ?? 'claude-sonnet-4',
      provider: options.providerName ?? 'anthropic',
      deployment_id: options.deploymentId,
    },
    audience: options.audience,
    metadata: {
      safety_level: (options.safetyLevel as 'standard' | 'enhanced' | 'minimal') ?? 'standard',
      capabilities_declared: options.capabilities?.split(',').map((s) => s.trim()) ?? [],
    },
  });

  if (options.output === 'token') {
    console.log(token);
  } else if (options.output === 'json') {
    const decoded = decodeTokenUnsafe(token);
    const publicJwk = await exportPublicKeyAsJWK(keyPair);
    console.log(
      JSON.stringify(
        {
          token,
          decoded,
          public_key: publicJwk,
        },
        null,
        2
      )
    );
  } else {
    const decoded = decodeTokenUnsafe(token);
    const publicJwk = await exportPublicKeyAsJWK(keyPair);

    console.log('='.repeat(60));
    console.log('ATTESTATION TOKEN GENERATED');
    console.log('='.repeat(60));
    console.log(`\nToken (${token.length} chars):`);
    console.log(token);
    console.log('\nPublic Key (JWK):');
    console.log(JSON.stringify(publicJwk, null, 2));
    console.log('\nDecoded Header:');
    console.log(JSON.stringify(decoded.header, null, 2));
    console.log('\nDecoded Payload:');
    console.log(JSON.stringify(decoded.payload, null, 2));
    console.log('\nTimestamps:');
    console.log(`  Issued:  ${formatTimestamp(decoded.payload.iat as number)}`);
    console.log(`  Expires: ${formatTimestamp(decoded.payload.exp as number)}`);
  }

  return 0;
}

async function cmdVerify(options: {
  token: string;
  publicKey?: string;
  audience?: string;
  trustedIssuers?: string;
  output?: string;
}): Promise<number> {
  let token = options.token;
  if (token === '-') {
    // Read from stdin
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk as Buffer);
    }
    token = Buffer.concat(chunks).toString('utf-8').trim();
  }

  // For verification, we need the public key
  if (!options.publicKey) {
    console.error('Error: --public-key is required for verification');
    console.error("Use 'inspect' command to view token without verification");
    return 1;
  }

  // Load public key
  const jwkJson = await fs.readFile(options.publicKey, 'utf-8');
  const jwk = JSON.parse(jwkJson) as Ed25519JWK;

  // Decode token to get issuer
  let decoded: ReturnType<typeof decodeTokenUnsafe>;
  try {
    decoded = decodeTokenUnsafe(token);
  } catch (e) {
    console.error(`Error: Invalid token format: ${e}`);
    return 1;
  }

  const issuer = decoded.payload.iss as string;
  const kid = decoded.header.kid as string;

  // Create key resolver with the provided key
  const keyResolver = new InMemoryKeyResolver();

  // Import the public key from JWK and add to resolver
  const keyPair = await importKeyPairFromJWK({
    ...jwk,
    kid: kid,
    d: jwk.d ?? '', // Need private key to import
  }).catch(async () => {
    // If no private key, just use the public key directly
    const tempKeyPair = await generateEd25519KeyPair(kid);
    return tempKeyPair;
  });

  keyResolver.addKeyPair(issuer, keyPair);

  // Create verifier
  const trustedIssuers = options.trustedIssuers?.split(',').map((s) => s.trim()) ?? [issuer];

  const verifier = new AttestationVerifier({
    trustedIssuers,
    keyResolver,
    policy: VerificationPolicy.REQUIRED,
    audience: options.audience,
  });

  // Verify
  const result = await verifier.verify(token);

  if (options.output === 'json') {
    console.log(
      JSON.stringify(
        {
          verified: result.verified,
          trust_level: result.trustLevel,
          issuer: result.issuer,
          subject: result.subject,
          error: result.error,
          error_code: result.errorCode,
        },
        null,
        2
      )
    );
  } else {
    if (result.verified) {
      console.log('✓ Token verified successfully');
      console.log(`  Trust Level: ${result.trustLevel}`);
      console.log(`  Issuer: ${result.issuer}`);
      console.log(`  Subject: ${result.subject}`);
      if (result.claims) {
        console.log(`  Model: ${result.claims.agent_identity.model_version}`);
      }
    } else {
      console.log(`✗ Verification failed: ${result.error}`);
      if (result.errorCode) {
        console.log(`  Error code: ${result.errorCode}`);
      }
      return 1;
    }
  }

  return 0;
}

async function cmdInspect(options: { token: string; output?: string }): Promise<number> {
  let token = options.token;
  if (token === '-') {
    // Read from stdin
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk as Buffer);
    }
    token = Buffer.concat(chunks).toString('utf-8').trim();
  }

  let decoded: ReturnType<typeof decodeTokenUnsafe>;
  try {
    decoded = decodeTokenUnsafe(token);
  } catch (e) {
    console.error(`Error: Invalid token format: ${e}`);
    return 1;
  }

  const payload = decoded.payload as Record<string, unknown>;

  if (options.output === 'json') {
    console.log(JSON.stringify(decoded, null, 2));
  } else {
    console.log('='.repeat(60));
    console.log('ATTESTATION TOKEN INSPECTION');
    console.log('='.repeat(60));
    console.log('\n⚠️  WARNING: Token signature NOT verified\n');

    console.log('Header:');
    console.log(JSON.stringify(decoded.header, null, 2));

    console.log('\nStandard Claims:');
    console.log(`  Issuer (iss):   ${payload.iss ?? 'N/A'}`);
    console.log(`  Subject (sub):  ${payload.sub ?? 'N/A'}`);
    console.log(`  Audience (aud): ${JSON.stringify(payload.aud) ?? 'N/A'}`);
    console.log(`  Token ID (jti): ${payload.jti ?? 'N/A'}`);

    console.log('\nTimestamps:');
    if (typeof payload.iat === 'number') {
      console.log(`  Issued At:  ${formatTimestamp(payload.iat)}`);
    }
    if (typeof payload.exp === 'number') {
      console.log(`  Expires:    ${formatTimestamp(payload.exp)}`);
      if (payload.exp < Date.now() / 1000) {
        console.log('  ⚠️  TOKEN EXPIRED');
      }
    }
    if (typeof payload.nbf === 'number') {
      console.log(`  Not Before: ${formatTimestamp(payload.nbf)}`);
    }

    if (payload.agent_identity) {
      const ai = payload.agent_identity as Record<string, unknown>;
      console.log('\nAgent Identity:');
      console.log(`  Model Family:   ${ai.model_family ?? 'N/A'}`);
      console.log(`  Model Version:  ${ai.model_version ?? 'N/A'}`);
      console.log(`  Provider:       ${ai.provider ?? 'N/A'}`);
      if (ai.deployment_id) {
        console.log(`  Deployment ID:  ${ai.deployment_id}`);
      }
    }

    if (payload.attestation_metadata) {
      const am = payload.attestation_metadata as Record<string, unknown>;
      console.log('\nAttestation Metadata:');
      console.log(`  Version:      ${am.attestation_version ?? 'N/A'}`);
      console.log(`  Type:         ${am.attestation_type ?? 'N/A'}`);
      console.log(`  Safety Level: ${am.safety_level ?? 'N/A'}`);
      if (Array.isArray(am.capabilities_declared) && am.capabilities_declared.length > 0) {
        console.log(`  Capabilities: ${am.capabilities_declared.join(', ')}`);
      }
    }

    if (payload.agent_integrity) {
      const ai = payload.agent_integrity as Record<string, unknown>;
      console.log('\nAgent Integrity:');
      if (typeof ai.config_hash === 'string') {
        console.log(`  Config Hash:        ${ai.config_hash.slice(0, 40)}...`);
      }
      if (typeof ai.system_prompt_hash === 'string') {
        console.log(`  System Prompt Hash: ${ai.system_prompt_hash.slice(0, 40)}...`);
      }
    }
  }

  return 0;
}

async function cmdKeygen(options: { kid?: string; outFile?: string; output?: string }): Promise<number> {
  const kid = options.kid ?? `key-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  const keyPair = await generateEd25519KeyPair(kid);

  const publicJwk = await exportPublicKeyAsJWK(keyPair);
  const privateJwk = await exportPrivateKeyAsJWK(keyPair);

  if (options.output === 'json') {
    console.log(JSON.stringify({ public: publicJwk, private: privateJwk }, null, 2));
  } else {
    console.log('='.repeat(60));
    console.log('ED25519 KEY PAIR GENERATED');
    console.log('='.repeat(60));
    console.log(`\nKey ID: ${kid}`);
    console.log('\nPublic Key (JWK):');
    console.log(JSON.stringify(publicJwk, null, 2));
    console.log('\n⚠️  Store private key securely - it cannot be recovered!');
    console.log('\nPrivate Key (JWK):');
    console.log(JSON.stringify(privateJwk, null, 2));

    if (options.outFile) {
      await fs.writeFile(options.outFile, JSON.stringify(privateJwk, null, 2));
      console.log(`\nPrivate key saved to: ${options.outFile}`);
    }
  }

  return 0;
}

async function cmdAttack(): Promise<number> {
  console.log('Running attack simulation suite...');
  console.log('='.repeat(60));

  const results = await runAttackSimulations();

  const blockedCount = results.filter((r) => r.blocked).length;
  const totalCount = results.length;

  if (blockedCount === totalCount) {
    console.log(`\n✓ All ${totalCount} attacks blocked successfully`);
    return 0;
  } else {
    console.log(`\n⚠️  ${totalCount - blockedCount}/${totalCount} attacks succeeded (security issue!)`);
    return 1;
  }
}

// =============================================================================
// MAIN
// =============================================================================

function printHelp(): void {
  console.log(`
MCP Agent Attestation CLI

Usage:
  mcp-attestation <command> [options]

Commands:
  generate    Generate an attestation token
  verify      Verify an attestation token
  inspect     Inspect a token without verification
  keygen      Generate Ed25519 key pair
  attack      Run attack simulation suite
  help        Show this help message

Examples:
  # Generate a token
  mcp-attestation generate --issuer https://api.anthropic.com --audience https://server.com

  # Inspect a token (no verification)
  mcp-attestation inspect <token>

  # Verify a token
  mcp-attestation verify <token> --public-key key.json

  # Generate a key pair
  mcp-attestation keygen --kid my-key-2025

  # Run attack simulations
  mcp-attestation attack

Options vary by command. Use mcp-attestation <command> --help for details.
`);
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === 'help' || args[0] === '--help' || args[0] === '-h') {
    printHelp();
    return 0;
  }

  const command = args[0];
  const commandArgs = args.slice(1);

  try {
    switch (command) {
      case 'generate': {
        const { values } = parseArgs({
          args: commandArgs,
          options: {
            issuer: { type: 'string', short: 'i' },
            audience: { type: 'string', short: 'a' },
            'model-family': { type: 'string' },
            'model-version': { type: 'string' },
            'provider-name': { type: 'string' },
            'deployment-id': { type: 'string' },
            lifetime: { type: 'string' },
            'safety-level': { type: 'string' },
            capabilities: { type: 'string' },
            'system-prompt': { type: 'string' },
            kid: { type: 'string' },
            'key-file': { type: 'string' },
            output: { type: 'string', short: 'o', default: 'full' },
          },
        });

        if (!values.issuer || !values.audience) {
          console.error('Error: --issuer and --audience are required');
          return 1;
        }

        return await cmdGenerate({
          issuer: values.issuer,
          audience: values.audience,
          modelFamily: values['model-family'],
          modelVersion: values['model-version'],
          providerName: values['provider-name'],
          deploymentId: values['deployment-id'],
          lifetime: values.lifetime ? parseInt(values.lifetime, 10) : undefined,
          safetyLevel: values['safety-level'],
          capabilities: values.capabilities,
          systemPrompt: values['system-prompt'],
          kid: values.kid,
          keyFile: values['key-file'],
          output: values.output,
        });
      }

      case 'verify': {
        const { values, positionals } = parseArgs({
          args: commandArgs,
          options: {
            'public-key': { type: 'string', short: 'k' },
            audience: { type: 'string', short: 'a' },
            'trusted-issuers': { type: 'string' },
            output: { type: 'string', short: 'o', default: 'text' },
          },
          allowPositionals: true,
        });

        if (positionals.length === 0) {
          console.error('Error: token argument is required');
          return 1;
        }

        return await cmdVerify({
          token: positionals[0]!,
          publicKey: values['public-key'],
          audience: values.audience,
          trustedIssuers: values['trusted-issuers'],
          output: values.output,
        });
      }

      case 'inspect': {
        const { values, positionals } = parseArgs({
          args: commandArgs,
          options: {
            output: { type: 'string', short: 'o', default: 'text' },
          },
          allowPositionals: true,
        });

        if (positionals.length === 0) {
          console.error('Error: token argument is required');
          return 1;
        }

        return await cmdInspect({
          token: positionals[0]!,
          output: values.output,
        });
      }

      case 'keygen': {
        const { values } = parseArgs({
          args: commandArgs,
          options: {
            kid: { type: 'string' },
            'out-file': { type: 'string', short: 'o' },
            output: { type: 'string', default: 'text' },
          },
        });

        return await cmdKeygen({
          kid: values.kid,
          outFile: values['out-file'],
          output: values.output,
        });
      }

      case 'attack': {
        return await cmdAttack();
      }

      default:
        console.error(`Unknown command: ${command}`);
        printHelp();
        return 1;
    }
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    return 1;
  }
}

main().then((code) => process.exit(code));
