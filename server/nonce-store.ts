/**
 * @fileoverview Simple NonceStore implementation for testing
 * 
 * This is a simplified wrapper around InMemoryNonceStore that provides
 * synchronous methods for testing purposes. The full async interface
 * is available in verify-api-request-signature.ts.
 * 
 * ⚠️ WARNING: This implementation is NOT suitable for production:
 * - Not distributed: works only with single server instance
 * - Not persistent: lost on restart
 * - Not atomic: race conditions possible with high concurrency
 * 
 * For production, use Redis, DynamoDB, or another distributed store.
 */

import { InvalidParameterError } from '../src/errors';

/**
 * Simple in-memory nonce store for testing.
 * This class provides synchronous methods that wrap the async functionality
 * needed for testing scenarios.
 */
export class NonceStore {
  #map = new Map<string, number>(); // key = `${kid}:${nonce}`, value = expiry unix ms

  /**
   * Check if a nonce has been used before (synchronous for testing).
   * @param kid - Key identifier for namespacing
   * @param nonce - The nonce value to check
   * @returns true if nonce exists (already used)
   */
  has(kid: string, nonce: string): boolean {
    this.#validateStoreParams(kid, nonce);
    const key = `${kid}:${nonce}`;
    const now = Date.now();
    const exp = this.#map.get(key);
    if (typeof exp === "number" && exp > now) return true;
    if (typeof exp === "number" && exp <= now) this.#map.delete(key);
    return false;
  }

  /**
   * Store a nonce with expiration (synchronous for testing).
   * @param kid - Key identifier for namespacing
   * @param nonce - The nonce value to store
   * @param ttlMs - Time-to-live in milliseconds
   */
  store(kid: string, nonce: string, ttlMs: number): void {
    this.#validateStoreParams(kid, nonce);
    if (typeof ttlMs !== 'number' || ttlMs < 1 || ttlMs > 86400000) {
      throw new InvalidParameterError('ttlMs must be between 1 and 86400000');
    }
    const key = `${kid}:${nonce}`;
    const exp = Date.now() + Math.max(0, Math.floor(ttlMs));
    this.#map.set(key, exp);
  }

  /**
   * Delete a nonce (synchronous for testing).
   * @param kid - Key identifier for namespacing
   * @param nonce - The nonce value to delete
   */
  delete(kid: string, nonce: string): void {
    this.#validateStoreParams(kid, nonce);
    const key = `${kid}:${nonce}`;
    this.#map.delete(key);
  }

  /**
   * Clean up expired entries (synchronous for testing).
   */
  cleanup(): void {
    const now = Date.now();
    for (const [k, exp] of this.#map.entries()) {
      if (exp <= now) this.#map.delete(k);
    }
  }

  /**
   * Get current size for testing purposes.
   * @internal
   */
  get size(): number {
    // Clean up expired entries first
    this.cleanup();
    return this.#map.size;
  }

  #validateStoreParams(kid: string, nonce: string): void {
    if (typeof kid !== 'string' || kid.length === 0 || kid.length > 128) {
      throw new InvalidParameterError('kid must be a non-empty string');
    }
    if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > 256) {
      throw new InvalidParameterError('nonce must be a non-empty string');
    }
    // For testing, we're more lenient on nonce format validation
    // The full base64 validation happens in the verify function
  }
}
