/**
 * Attack Simulation Tests
 *
 * Tests that all 8 attack vectors are properly blocked.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  AttackSimulator,
  AttackType,
  runAttackSimulations,
} from '../src/attacks.js';

describe('AttackSimulator', () => {
  it('should create simulator', async () => {
    const simulator = await AttackSimulator.create();
    expect(simulator).toBeDefined();
  });

  it('should run all 8 attacks', async () => {
    const simulator = await AttackSimulator.create();
    const results = await simulator.runAllAttacks();

    expect(results).toHaveLength(8);
  });

  it('should block all attacks', async () => {
    const simulator = await AttackSimulator.create();
    const results = await simulator.runAllAttacks();

    const blockedCount = results.filter((r) => r.blocked).length;
    expect(blockedCount).toBe(8);
  });
});

describe('Individual Attack Vectors', () => {
  let simulator: AttackSimulator;

  beforeAll(async () => {
    simulator = await AttackSimulator.create();
  });

  it('should block model spoofing attack', async () => {
    const results = await simulator.runAllAttacks();
    const result = results.find((r) => r.attackType === AttackType.MODEL_SPOOFING);

    expect(result).toBeDefined();
    expect(result!.blocked).toBe(true);
    expect(result!.attackName).toBe('Model Spoofing');
  });

  it('should block provenance forgery attack', async () => {
    const results = await simulator.runAllAttacks();
    const result = results.find((r) => r.attackType === AttackType.PROVENANCE_FORGERY);

    expect(result).toBeDefined();
    expect(result!.blocked).toBe(true);
    expect(result!.errorMessage).toContain('Untrusted issuer');
  });

  it('should block token replay attack', async () => {
    const results = await simulator.runAllAttacks();
    const result = results.find((r) => r.attackType === AttackType.TOKEN_REPLAY);

    expect(result).toBeDefined();
    expect(result!.blocked).toBe(true);
    expect(result!.details.first_use_success).toBe(true);
    expect(result!.details.replay_blocked).toBe(true);
  });

  it('should block token tampering attack', async () => {
    const results = await simulator.runAllAttacks();
    const result = results.find((r) => r.attackType === AttackType.TOKEN_TAMPERING);

    expect(result).toBeDefined();
    expect(result!.blocked).toBe(true);
  });

  it('should block issuer spoofing (typosquatting) attack', async () => {
    const results = await simulator.runAllAttacks();
    const result = results.find((r) => r.attackType === AttackType.ISSUER_SPOOFING);

    expect(result).toBeDefined();
    expect(result!.blocked).toBe(true);
    expect(result!.details.fake_issuer).toBe('https://api.anthropic.org');
    expect(result!.details.real_issuer).toBe('https://api.anthropic.com');
  });

  it('should block downgrade attack', async () => {
    const results = await simulator.runAllAttacks();
    const result = results.find((r) => r.attackType === AttackType.DOWNGRADE_ATTACK);

    expect(result).toBeDefined();
    expect(result!.blocked).toBe(true);
    expect(result!.details.policy).toBe('REQUIRED');
    expect(result!.details.token_provided).toBe(false);
  });

  it('should block audience mismatch attack', async () => {
    const results = await simulator.runAllAttacks();
    const result = results.find((r) => r.attackType === AttackType.AUDIENCE_MISMATCH);

    expect(result).toBeDefined();
    expect(result!.blocked).toBe(true);
    expect(result!.details.token_audience).toBe('https://server-a.example.com');
    expect(result!.details.server_identity).toBe('https://server-b.example.com');
  });

  it('should block safety downgrade attack', async () => {
    const results = await simulator.runAllAttacks();
    const result = results.find((r) => r.attackType === AttackType.SAFETY_DOWNGRADE);

    expect(result).toBeDefined();
    expect(result!.blocked).toBe(true);
    expect(result!.details.original_safety).toBe('enhanced');
    expect(result!.details.attempted_safety).toBe('minimal');
  });
});

describe('Attack Report', () => {
  it('should generate report without errors', async () => {
    // This just verifies the report function runs without throwing
    const results = await runAttackSimulations();
    expect(results).toHaveLength(8);
  });
});
