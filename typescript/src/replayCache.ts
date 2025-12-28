/**
 * MCP Agent Attestation - Replay Cache
 *
 * JTI (JWT ID) tracking for preventing token replay attacks.
 * Provides both in-memory and interface for distributed caches.
 *
 * @author Joel Villarino
 * @license MIT
 */

// =============================================================================
// INTERFACES
// =============================================================================

/**
 * Interface for replay cache implementations.
 */
export interface ReplayCache {
  /**
   * Check if JTI is new and add to cache atomically.
   *
   * @param jti - JWT ID to check
   * @param exp - Token expiration timestamp (Unix seconds)
   * @returns Promise resolving to true if new (not replay), false if seen
   */
  checkAndAdd(jti: string, exp: number): Promise<boolean>;

  /**
   * Clear all cached tokens.
   */
  clear(): Promise<void>;

  /**
   * Check if JTI exists without adding.
   *
   * @param jti - JWT ID to check
   * @returns Promise resolving to true if exists
   */
  exists(jti: string): Promise<boolean>;

  /**
   * Get count of cached tokens.
   *
   * @returns Promise resolving to count
   */
  count(): Promise<number>;
}

// =============================================================================
// IN-MEMORY REPLAY CACHE
// =============================================================================

/**
 * In-memory replay cache for single-server deployments.
 *
 * This cache stores seen JWT IDs in memory with automatic cleanup
 * of expired entries. Suitable for single-server deployments.
 *
 * Note: This cache will NOT work in distributed deployments!
 * For multi-server setups, implement a Redis-based cache.
 *
 * @example
 * ```typescript
 * const cache = new InMemoryReplayCache();
 *
 * // Check if token is new
 * const isNew = await cache.checkAndAdd(jti, expTimestamp);
 * if (!isNew) {
 *   throw new Error('Token replay detected');
 * }
 * ```
 */
export class InMemoryReplayCache implements ReplayCache {
  private seen: Map<string, number> = new Map();
  private cleanupIntervalId?: ReturnType<typeof setInterval>;
  private readonly cleanupIntervalMs: number;

  /**
   * Create a new in-memory replay cache.
   *
   * @param cleanupIntervalMs - Interval for cleanup of expired entries (default: 60 seconds)
   */
  constructor(cleanupIntervalMs = 60000) {
    this.cleanupIntervalMs = cleanupIntervalMs;
    this.startCleanupInterval();
  }

  /**
   * Start periodic cleanup of expired entries.
   */
  private startCleanupInterval(): void {
    this.cleanupIntervalId = setInterval(() => {
      this.cleanupExpired();
    }, this.cleanupIntervalMs);

    // Don't prevent process exit
    if (typeof this.cleanupIntervalId === 'object' && 'unref' in this.cleanupIntervalId) {
      this.cleanupIntervalId.unref();
    }
  }

  /**
   * Stop the cleanup interval.
   */
  stopCleanup(): void {
    if (this.cleanupIntervalId) {
      clearInterval(this.cleanupIntervalId);
      this.cleanupIntervalId = undefined;
    }
  }

  /**
   * Remove expired entries from cache.
   */
  private cleanupExpired(): void {
    const now = Math.floor(Date.now() / 1000);
    let cleanedCount = 0;

    for (const [jti, exp] of this.seen) {
      if (exp < now) {
        this.seen.delete(jti);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      console.debug(`Cleaned up ${cleanedCount} expired tokens from replay cache`);
    }
  }

  /**
   * Check if JTI is new and add to cache.
   *
   * @param jti - JWT ID to check
   * @param exp - Token expiration timestamp (Unix seconds)
   * @returns Promise resolving to true if new, false if replay
   */
  async checkAndAdd(jti: string, exp: number): Promise<boolean> {
    // Clean up expired entries occasionally
    if (this.seen.size > 1000 && Math.random() < 0.1) {
      this.cleanupExpired();
    }

    if (this.seen.has(jti)) {
      console.warn(`Replay detected for JTI ${jti.slice(0, 8)}...`);
      return false;
    }

    this.seen.set(jti, exp);
    console.debug(`Added JTI ${jti.slice(0, 8)}... to replay cache`);
    return true;
  }

  /**
   * Clear all cached tokens.
   */
  async clear(): Promise<void> {
    const count = this.seen.size;
    this.seen.clear();
    console.info(`Cleared ${count} tokens from replay cache`);
  }

  /**
   * Check if JTI exists in cache.
   *
   * @param jti - JWT ID to check
   * @returns Promise resolving to true if exists
   */
  async exists(jti: string): Promise<boolean> {
    return this.seen.has(jti);
  }

  /**
   * Get count of cached tokens.
   *
   * @returns Promise resolving to count
   */
  async count(): Promise<number> {
    return this.seen.size;
  }

  /**
   * Destroy the cache and clean up resources.
   */
  destroy(): void {
    this.stopCleanup();
    this.seen.clear();
  }
}

// =============================================================================
// LRU REPLAY CACHE
// =============================================================================

/**
 * LRU (Least Recently Used) replay cache with size limits.
 *
 * This is an enhanced in-memory cache that automatically evicts
 * the least recently used entries when the cache reaches its
 * maximum size. Useful when memory constraints are a concern.
 */
export class LRUReplayCache implements ReplayCache {
  private cache: Map<string, number> = new Map();
  private readonly maxSize: number;
  private cleanupIntervalId?: ReturnType<typeof setInterval>;

  /**
   * Create a new LRU replay cache.
   *
   * @param maxSize - Maximum number of entries (default: 10000)
   * @param cleanupIntervalMs - Cleanup interval in ms (default: 60 seconds)
   */
  constructor(maxSize = 10000, cleanupIntervalMs = 60000) {
    this.maxSize = maxSize;

    // Start periodic cleanup
    this.cleanupIntervalId = setInterval(() => {
      this.cleanupExpired();
    }, cleanupIntervalMs);

    if (typeof this.cleanupIntervalId === 'object' && 'unref' in this.cleanupIntervalId) {
      this.cleanupIntervalId.unref();
    }
  }

  /**
   * Remove expired entries.
   */
  private cleanupExpired(): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, exp] of this.cache) {
      if (exp < now) {
        this.cache.delete(jti);
      }
    }
  }

  /**
   * Evict oldest entries when cache is full.
   */
  private evictIfNeeded(): void {
    while (this.cache.size >= this.maxSize) {
      // Map iteration order is insertion order, so first key is oldest
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.cache.delete(oldestKey);
      } else {
        break;
      }
    }
  }

  /**
   * Check if JTI is new and add to cache.
   *
   * @param jti - JWT ID to check
   * @param exp - Token expiration timestamp
   * @returns Promise resolving to true if new, false if replay
   */
  async checkAndAdd(jti: string, exp: number): Promise<boolean> {
    if (this.cache.has(jti)) {
      // Move to end (most recently used)
      this.cache.delete(jti);
      this.cache.set(jti, exp);
      console.warn(`Replay detected for JTI ${jti.slice(0, 8)}...`);
      return false;
    }

    this.evictIfNeeded();
    this.cache.set(jti, exp);
    return true;
  }

  /**
   * Clear all cached tokens.
   */
  async clear(): Promise<void> {
    this.cache.clear();
  }

  /**
   * Check if JTI exists.
   *
   * @param jti - JWT ID to check
   * @returns Promise resolving to true if exists
   */
  async exists(jti: string): Promise<boolean> {
    return this.cache.has(jti);
  }

  /**
   * Get count of cached tokens.
   *
   * @returns Promise resolving to count
   */
  async count(): Promise<number> {
    return this.cache.size;
  }

  /**
   * Destroy the cache and clean up resources.
   */
  destroy(): void {
    if (this.cleanupIntervalId) {
      clearInterval(this.cleanupIntervalId);
      this.cleanupIntervalId = undefined;
    }
    this.cache.clear();
  }
}

// =============================================================================
// NOOP REPLAY CACHE (FOR TESTING)
// =============================================================================

/**
 * No-op replay cache that accepts all tokens.
 *
 * WARNING: This provides no replay protection!
 * Only use for testing or when replay protection is
 * handled externally.
 */
export class NoopReplayCache implements ReplayCache {
  async checkAndAdd(_jti: string, _exp: number): Promise<boolean> {
    return true;
  }

  async clear(): Promise<void> {
    // No-op
  }

  async exists(_jti: string): Promise<boolean> {
    return false;
  }

  async count(): Promise<number> {
    return 0;
  }
}
