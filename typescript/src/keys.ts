/**
 * MCP Agent Attestation - Key Management
 *
 * Ed25519 key generation, JWKS handling, and key resolution.
 * Uses the jose library for cryptographic operations.
 *
 * @author Joel Villarino
 * @license MIT
 */

import { generateKeyPair, exportJWK, importJWK, type KeyLike } from 'jose';
import type { Ed25519JWK, JWKS, KeyResolver, KeyPair } from './types.js';

// =============================================================================
// KEY PAIR GENERATION
// =============================================================================

/**
 * Generate a new Ed25519 key pair for signing attestation tokens.
 *
 * @param kid - Key ID (optional, auto-generated if not provided)
 * @returns Promise resolving to KeyPair
 */
export async function generateEd25519KeyPair(kid?: string): Promise<KeyPair> {
  const keyId = kid ?? `key-${crypto.randomUUID().slice(0, 8)}`;

  const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });

  return {
    publicKey,
    privateKey,
    kid: keyId,
  };
}

/**
 * Export a public key as JWK.
 *
 * @param keyPair - Key pair to export
 * @returns Promise resolving to Ed25519JWK
 */
export async function exportPublicKeyAsJWK(keyPair: KeyPair): Promise<Ed25519JWK> {
  const jwk = await exportJWK(keyPair.publicKey);
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    kid: keyPair.kid,
    x: jwk.x as string,
    use: 'sig',
    alg: 'EdDSA',
  };
}

/**
 * Export a private key as JWK.
 *
 * @param keyPair - Key pair to export
 * @returns Promise resolving to Ed25519JWK with private component
 */
export async function exportPrivateKeyAsJWK(keyPair: KeyPair): Promise<Ed25519JWK> {
  const jwk = await exportJWK(keyPair.privateKey);
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    kid: keyPair.kid,
    x: jwk.x as string,
    d: jwk.d as string,
    use: 'sig',
    alg: 'EdDSA',
  };
}

/**
 * Import a public key from JWK.
 *
 * @param jwk - JWK to import
 * @returns Promise resolving to KeyLike
 */
export async function importPublicKeyFromJWK(jwk: Ed25519JWK): Promise<KeyLike> {
  const key = await importJWK(
    {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
    },
    'EdDSA'
  );
  return key as KeyLike;
}

/**
 * Import a private key from JWK.
 *
 * @param jwk - JWK to import (must include 'd' component)
 * @returns Promise resolving to KeyLike
 */
export async function importPrivateKeyFromJWK(jwk: Ed25519JWK): Promise<KeyLike> {
  if (!jwk.d) {
    throw new Error('JWK missing private key component (d)');
  }
  const key = await importJWK(
    {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      d: jwk.d,
    },
    'EdDSA'
  );
  return key as KeyLike;
}

/**
 * Import a complete key pair from JWK.
 *
 * @param jwk - JWK with both public and private components
 * @returns Promise resolving to KeyPair
 */
export async function importKeyPairFromJWK(jwk: Ed25519JWK): Promise<KeyPair> {
  if (!jwk.d) {
    throw new Error('JWK missing private key component (d)');
  }
  if (!jwk.kid) {
    throw new Error('JWK missing key ID (kid)');
  }

  const publicKey = await importPublicKeyFromJWK(jwk);
  const privateKey = await importPrivateKeyFromJWK(jwk);

  return {
    publicKey,
    privateKey,
    kid: jwk.kid,
  };
}

// =============================================================================
// IN-MEMORY KEY RESOLVER
// =============================================================================

/**
 * Simple in-memory key resolver for development and testing.
 *
 * In production, use JWKSKeyResolver which fetches from JWKS endpoints.
 */
export class InMemoryKeyResolver implements KeyResolver {
  private keys: Map<string, Map<string, KeyLike>> = new Map();

  /**
   * Add a public key for an issuer.
   *
   * @param issuer - Issuer URL
   * @param kid - Key ID
   * @param publicKey - KeyLike to add
   */
  addKey(issuer: string, kid: string, publicKey: KeyLike): void {
    if (!this.keys.has(issuer)) {
      this.keys.set(issuer, new Map());
    }
    this.keys.get(issuer)!.set(kid, publicKey);
  }

  /**
   * Add a key pair (public key only is stored).
   *
   * @param issuer - Issuer URL
   * @param keyPair - Key pair to add
   */
  addKeyPair(issuer: string, keyPair: KeyPair): void {
    this.addKey(issuer, keyPair.kid, keyPair.publicKey);
  }

  /**
   * Get public key for issuer and key ID.
   *
   * @param issuer - Issuer URL
   * @param kid - Key ID
   * @returns Promise resolving to KeyLike or null
   */
  async getKey(issuer: string, kid: string): Promise<KeyLike | null> {
    const issuerKeys = this.keys.get(issuer);
    if (!issuerKeys) {
      return null;
    }
    return issuerKeys.get(kid) ?? null;
  }

  /**
   * Export all keys for an issuer as JWKS.
   *
   * @param issuer - Issuer URL
   * @returns Promise resolving to JWKS
   */
  async toJWKS(issuer: string): Promise<JWKS> {
    const issuerKeys = this.keys.get(issuer);
    if (!issuerKeys) {
      return { keys: [] };
    }

    const keys: Ed25519JWK[] = [];
    for (const [kid, publicKey] of issuerKeys) {
      const jwk = await exportJWK(publicKey);
      keys.push({
        kty: 'OKP',
        crv: 'Ed25519',
        kid,
        x: jwk.x as string,
        use: 'sig',
        alg: 'EdDSA',
      });
    }

    return { keys };
  }

  /**
   * Clear all stored keys.
   */
  clear(): void {
    this.keys.clear();
  }

  /**
   * Clear keys for a specific issuer.
   *
   * @param issuer - Issuer URL to clear
   */
  clearIssuer(issuer: string): void {
    this.keys.delete(issuer);
  }
}

// =============================================================================
// JWKS FETCHER
// =============================================================================

/** Configuration for JWKS fetching */
export interface JWKSFetcherConfig {
  /** Cache TTL in milliseconds (default: 1 hour) */
  cacheTtlMs?: number;
  /** Request timeout in milliseconds (default: 10 seconds) */
  requestTimeoutMs?: number;
  /** Maximum retries on failure (default: 3) */
  maxRetries?: number;
  /** Base delay for exponential backoff in ms (default: 500) */
  baseDelayMs?: number;
}

interface CacheEntry {
  jwks: JWKS;
  cachedAt: number;
}

/**
 * JWKS Fetcher with caching and retry logic.
 *
 * Fetches public keys from issuer's well-known JWKS endpoints.
 * Production-hardened with:
 * - Automatic caching with configurable TTL
 * - Retry logic with exponential backoff
 * - Request timeout handling
 */
export class JWKSFetcher {
  private cache: Map<string, CacheEntry> = new Map();
  private readonly config: Required<JWKSFetcherConfig>;

  constructor(config?: JWKSFetcherConfig) {
    this.config = {
      cacheTtlMs: config?.cacheTtlMs ?? 3600000, // 1 hour
      requestTimeoutMs: config?.requestTimeoutMs ?? 10000, // 10 seconds
      maxRetries: config?.maxRetries ?? 3,
      baseDelayMs: config?.baseDelayMs ?? 500,
    };
  }

  /**
   * Build JWKS endpoint URL from issuer.
   *
   * @param issuer - Issuer URL
   * @returns JWKS endpoint URL
   */
  private getJWKSUrl(issuer: string): string {
    return `${issuer.replace(/\/$/, '')}/.well-known/jwks.json`;
  }

  /**
   * Check if cache entry is still valid.
   *
   * @param issuer - Issuer URL
   * @returns true if cache is valid
   */
  private isCacheValid(issuer: string): boolean {
    const entry = this.cache.get(issuer);
    if (!entry) {
      return false;
    }
    return Date.now() - entry.cachedAt < this.config.cacheTtlMs;
  }

  /**
   * Calculate delay for retry with exponential backoff and jitter.
   *
   * @param attempt - Current attempt number (0-based)
   * @returns Delay in milliseconds
   */
  private calculateRetryDelay(attempt: number): number {
    const delay = this.config.baseDelayMs * Math.pow(2, attempt);
    // Add jitter (0.5 to 1.5 multiplier)
    const jitter = 0.5 + Math.random();
    return Math.min(delay * jitter, 10000); // Cap at 10 seconds
  }

  /**
   * Fetch JWKS from issuer with retry logic.
   *
   * @param issuer - Issuer URL
   * @returns Promise resolving to JWKS
   */
  async getJWKS(issuer: string): Promise<JWKS> {
    // Check cache first
    if (this.isCacheValid(issuer)) {
      return this.cache.get(issuer)!.jwks;
    }

    const url = this.getJWKSUrl(issuer);
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(
          () => controller.abort(),
          this.config.requestTimeoutMs
        );

        const response = await fetch(url, {
          signal: controller.signal,
          headers: {
            Accept: 'application/json',
          },
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = (await response.json()) as unknown;

        // Validate JWKS structure
        if (
          typeof data !== 'object' ||
          data === null ||
          !('keys' in data) ||
          !Array.isArray((data as Record<string, unknown>).keys)
        ) {
          throw new Error('Invalid JWKS response: missing keys array');
        }

        const jwks = data as JWKS;

        // Cache the result
        this.cache.set(issuer, {
          jwks,
          cachedAt: Date.now(),
        });

        return jwks;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // Don't retry on 4xx errors (except 429)
        if (
          error instanceof Error &&
          error.message.startsWith('HTTP 4') &&
          !error.message.startsWith('HTTP 429')
        ) {
          throw error;
        }

        // Wait before retrying
        if (attempt < this.config.maxRetries) {
          const delay = this.calculateRetryDelay(attempt);
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }

    throw new Error(
      `Failed to fetch JWKS from ${url} after ${this.config.maxRetries + 1} attempts: ${lastError?.message}`
    );
  }

  /**
   * Get a specific key from issuer's JWKS.
   *
   * @param issuer - Issuer URL
   * @param kid - Key ID
   * @returns Promise resolving to KeyLike or null
   */
  async getKey(issuer: string, kid: string): Promise<KeyLike | null> {
    try {
      const jwks = await this.getJWKS(issuer);
      const jwk = jwks.keys.find((k) => k.kid === kid);

      if (!jwk) {
        return null;
      }

      return await importPublicKeyFromJWK(jwk);
    } catch (error) {
      console.warn(`Failed to get key ${kid} from ${issuer}:`, error);
      return null;
    }
  }

  /**
   * Clear the JWKS cache.
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Invalidate cache for a specific issuer.
   *
   * @param issuer - Issuer URL
   */
  invalidate(issuer: string): void {
    this.cache.delete(issuer);
  }
}

/**
 * Key resolver that fetches keys from JWKS endpoints.
 *
 * This is the production-ready key resolver for verifying
 * attestation tokens from real providers.
 */
export class JWKSKeyResolver implements KeyResolver {
  private fetcher: JWKSFetcher;

  constructor(config?: JWKSFetcherConfig) {
    this.fetcher = new JWKSFetcher(config);
  }

  /**
   * Get public key for issuer and key ID.
   *
   * @param issuer - Issuer URL
   * @param kid - Key ID
   * @returns Promise resolving to KeyLike or null
   */
  async getKey(issuer: string, kid: string): Promise<KeyLike | null> {
    return this.fetcher.getKey(issuer, kid);
  }

  /**
   * Clear the JWKS cache.
   */
  clearCache(): void {
    this.fetcher.clearCache();
  }

  /**
   * Invalidate cache for a specific issuer.
   *
   * @param issuer - Issuer URL
   */
  invalidate(issuer: string): void {
    this.fetcher.invalidate(issuer);
  }
}
