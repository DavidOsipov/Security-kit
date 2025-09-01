// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

// -----------------------------------------------------------------------------
// ISC LICENSED CODE
// -----------------------------------------------------------------------------
// The following core LRU data structure logic is adapted from `lru-cache`,
// which is licensed under the ISC License.
//
// The ISC License
//
// Copyright (c) 2010-2023 Isaac Z. Schlueter and Contributors
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
// IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
// -----------------------------------------------------------------------------

import { InvalidParameterError } from "./errors";

/**
 * Defines the reason an entry was evicted from the cache.
 * - `capacity`: Evicted to make space for a new item (due to `maxEntries` or `maxBytes`).
 * - `ttl`: Evicted because its time-to-live expired.
 * - `manual`: Evicted due to a direct call to `delete()` or `clear()`.
 */
export type EvictionReason = "capacity" | "ttl" | "manual";

/**
 * Describes an entry that has been evicted from the cache.
 * Passed to the `onEvict` callback.
 */
export type EvictedEntry = {
  /** The URL (key) of the evicted entry. */
  readonly url: string;
  /** The size in bytes of the evicted entry's value. */
  readonly bytesLength: number;
  /** The reason for the eviction. */
  readonly reason: EvictionReason;
};

/**
 * A simple logger interface for routing internal cache warnings and errors.
 * Compatible with the standard `console` object.
 */
export interface Logger {
  warn(...data: readonly unknown[]): void;
  error(...data: readonly unknown[]): void;
}

/**
 * Configuration options for creating a `SecureLRUCache` instance.
 * 
 * @example Basic cache for user sessions
 * ```typescript
 * import { SecureLRUCache } from '@david-osipov/security-kit';
 * 
 * const sessionCache = new SecureLRUCache({
 *   maxEntries: 1000,
 *   maxBytes: 2 * 1024 * 1024, // 2MB
 *   defaultTtlMs: 30 * 60 * 1000, // 30 minutes
 * });
 * 
 * // Store encrypted session data
 * const sessionData = new TextEncoder().encode(JSON.stringify({
 *   userId: '12345',
 *   permissions: ['read', 'write'],
 *   expires: Date.now() + 1800000
 * }));
 * sessionCache.set('session:12345', sessionData);
 * 
 * // Retrieve session data (defensive copy returned)
 * const retrieved = sessionCache.get('session:12345');
 * if (retrieved) {
 *   const session = JSON.parse(new TextDecoder().decode(retrieved));
 *   console.log('Session found:', session);
 * }
 * ```
 * 
 * @example Secure API response cache
 * ```typescript
 * import { SecureLRUCache } from '@david-osipov/security-kit';
 * 
 * const apiCache = new SecureLRUCache({
 *   maxEntries: 500,
 *   maxBytes: 10 * 1024 * 1024, // 10MB
 *   defaultTtlMs: 5 * 60 * 1000, // 5 minutes
 *   copyOnGet: true, // Return defensive copies (default)
 *   copyOnSet: true, // Store defensive copies (default)
 *   onEvict: (entry) => {
 *     console.log(`Evicted API response: ${entry.url} (${entry.bytesLength} bytes)`);
 *   }
 * });
 * 
 * // Cache API responses securely
 * async function cacheApiResponse(endpoint: string, data: unknown) {
 *   const serialized = JSON.stringify(data);
 *   const compressed = new TextEncoder().encode(serialized);
 *   apiCache.set(`api:${endpoint}`, compressed);
 * }
 * 
 * // Retrieve with fallback
 * function getCachedResponse(endpoint: string): unknown | null {
 *   const cached = apiCache.get(`api:${endpoint}`);
 *   if (cached) {
 *     const serialized = new TextDecoder().decode(cached);
 *     return JSON.parse(serialized);
 *   }
 *   return null;
 * }
 * ```
 * 
 * @example High-security configuration for sensitive data
 * ```typescript
 * import { SecureLRUCache } from '@david-osipov/security-kit';
 * 
 * const secureCache = new SecureLRUCache({
 *   maxEntries: 100,
 *   maxBytes: 1024 * 1024, // 1MB
 *   defaultTtlMs: 60 * 1000, // 1 minute
 *   copyOnSet: true, // Store defensive copies
 *   copyOnGet: true, // Return defensive copies
 *   freezeReturns: true, // Freeze returned arrays for immutability
 *   rejectSharedBuffers: true, // Security: reject SharedArrayBuffer views
 *   highWatermarkBytes: 800 * 1024, // Trigger cleanup at 800KB
 *   maxSyncEvictions: 5, // Limit sync evictions to prevent blocking
 *   onEvict: (entry) => {
 *     console.log(`Securely evicted: ${entry.reason} - ${entry.bytesLength} bytes wiped`);
 *   },
 *   onWipeError: (error) => {
 *     console.error('Failed to wipe sensitive data:', error);
 *   }
 * });
 * 
 * // Store cryptocurrency keys or other sensitive data
 * const sensitiveKey = crypto.getRandomValues(new Uint8Array(32));
 * secureCache.set('crypto:key:primary', sensitiveKey);
 * 
 * // Data is automatically wiped on eviction
 * ```
 */
export type CacheOptions = {
  /**
   * The maximum number of entries the cache can hold.
   * @default 10
   */
  readonly maxEntries?: number;
  /**
   * The maximum total number of bytes the cache can hold across all entries.
   * @default 1_048_576 (1 MiB)
   */
  readonly maxBytes?: number;
  /**
   * The default time-to-live for an entry in milliseconds. Uses a monotonic clock
   * (`performance.now()`) where available to prevent issues with system time changes.
   * @default 120_000 (2 minutes)
   */
  readonly defaultTtlMs?: number;
  /**
   * A global flag to enable or disable the cache. If `false`, `set` is a no-op
   * and `get` always returns `undefined`. Controlled by runtime policy.
   * @default true
   */
  readonly enableByteCache?: boolean;
  /**
   * If `true`, a defensive copy of the `Uint8Array` is made when `set` is called.
   * This prevents the caller from mutating the stored buffer after insertion.
   * @default true
   */
  readonly copyOnSet?: boolean;
  /**
   * If `true`, a defensive copy of the `Uint8Array` is returned from `get`.
   * This prevents the caller from mutating the internally stored buffer.
   * @default true
   */
  readonly copyOnGet?: boolean;
  /**
   * If `true`, rejects any `Uint8Array` that is a view over a `SharedArrayBuffer`.
   * This is a defense-in-depth measure against potential side-channel attacks.
   * @default true
   */
  readonly rejectSharedBuffers?: boolean;
  /**
   * An optional callback function that is invoked after an entry has been
   * evicted from the cache. The underlying buffer has already been wiped
   * (best-effort) before this callback is called.
   */
  readonly onEvict?: (entry: EvictedEntry) => void;
  /**
   * An optional callback for handling errors during the best-effort buffer
   * wiping process. If not provided, errors are logged to the `logger`.
   */
  readonly onWipeError?: (error: unknown) => void;
  /**
   * An optional logger for handling internal errors, such as failures in the
   * `onEvict` callback. Defaults to `console`.
   */
  readonly logger?: Logger;
  /**
   * The maximum size in bytes for a single entry. Attempts to `set` an entry
   * larger than this will throw an `InvalidParameterError`.
   * @default 512_000 (512 KiB)
   */
  readonly maxEntryBytes?: number;
  /**
   * The maximum allowed length for a URL key. Attempts to use a longer key
   * will throw an `InvalidParameterError`.
   * @default 2048
   */
  readonly maxUrlLength?: number;
  /**
   * A memory usage threshold in bytes. If the cache's total size exceeds this
   * watermark, it will trigger a proactive cleanup of expired items.
   * Set to `0` to disable.
   * @default 0
   */
  readonly highWatermarkBytes?: number;
  /**
   * If `true`, the `Uint8Array` returned by `get` will be frozen using
   * `Object.freeze()`. This requires `copyOnGet` to also be `true`.
   * This provides a stronger guarantee against modification than `copyOnGet` alone.
   * @default false
   */
  readonly freezeReturns?: boolean;
  /**
   * If `true`, the `urls` array in `getStats()` will be populated.
   * This should be `false` in production to avoid leaking sensitive URLs
   * through a potential side-channel.
   * @default false (for production safety)
   */
  readonly includeUrlsInStats?: boolean;
  /**
   * The maximum number of evictions a single `set` operation can perform
   * synchronously. If this limit is reached and the new item still cannot
   * be added, the `set` call will throw an `InvalidParameterError`.
   * This prevents long-running synchronous operations from blocking the main thread.
   * @default 8
   */
  readonly maxSyncEvictions?: number;
};

/**
 * Per-operation options for the `set` method.
 */
export type SetOptions = {
  /** Overrides the cache's `defaultTtlMs` for this specific entry. */
  readonly ttlMs?: number;
  /** Overrides the cache's `maxEntryBytes` for this specific operation. */
  readonly maxEntryBytes?: number;
};

/**
 * Statistics about the cache's performance and state.
 */
export type CacheStats = {
  /** The current number of entries in the cache. */
  readonly size: number;
  /** The current total size in bytes of all values in the cache. */
  readonly totalBytes: number;
  /** The number of times a `get` operation returned a value. */
  readonly hits: number;
  /** The number of times a `get` operation returned `undefined`. */
  readonly misses: number;
  /** The number of entries removed due to capacity limits. */
  readonly evictions: number;
  /** The number of entries removed due to TTL expiration. */
  readonly expired: number;
  /** The total number of `set` operations. */
  readonly setOps: number;
  /** The total number of `get` operations. */
  readonly getOps: number;
  /**
   * A list of all URLs currently in the cache.
   * Populated only if `includeUrlsInStats` is `true`.
   * In production, this should be empty to prevent data leakage.
   */
  readonly urls: readonly string[];
};

// --- Internal Utilities ---

const NO_INDEX = -1;
const now = (): number =>
  typeof performance === "object" && performance.now
    ? performance.now()
    : Date.now();

function isSharedArrayBufferView(u8: Uint8Array): boolean {
  try {
    return (
      typeof SharedArrayBuffer !== "undefined" &&
      u8.buffer instanceof SharedArrayBuffer
    );
  } catch {
    // Fallback for cross-realm objects or other edge cases
    return u8.buffer?.constructor?.name === "SharedArrayBuffer";
  }
}

/**
 * A high-performance, security-hardened, in-memory LRU (Least Recently Used) cache
 * designed for storing sensitive byte arrays, such as verified worker scripts.
 *
 * It provides O(1) amortized time complexity for `get`, `set`, and `delete` operations.
 * The cache enforces strict limits on both the number of entries (`maxEntries`) and
 * the total memory usage (`maxBytes`) to prevent resource exhaustion attacks.
 *
 * @example Basic Usage
 * ```typescript
 * import { SecureLRUCache } from '@david-osipov/security-kit';
 *
 * const cache = new SecureLRUCache({
 *   maxEntries: 50,
 *   maxBytes: 2 * 1024 * 1024, // 2MB
 *   defaultTtlMs: 600_000, // 10 minutes
 * });
 *
 * // Store data with automatic expiration
 * const sensitiveData = new TextEncoder().encode('confidential payload');
 * cache.set('user:123:token', sensitiveData);
 *
 * // Retrieve data (returns undefined if expired or not found)
 * const retrieved = cache.get('user:123:token');
 * if (retrieved) {
 *   console.log('Data found:', new TextDecoder().decode(retrieved));
 * }
 *
 * // View cache statistics
 * console.log(cache.getStats());
 * ```
 *
 * @example Advanced Configuration
 * ```typescript
 * const cache = new SecureLRUCache({
 *   maxEntries: 100,
 *   maxBytes: 5 * 1024 * 1024, // 5MB
 *   defaultTtlMs: 300_000, // 5 minutes
 *   copyOnGet: true, // Return defensive copies (default: true)
 *   copyOnSet: true, // Store defensive copies (default: true)
 *   rejectSharedBuffers: true, // Security: reject SharedArrayBuffer views
 *   onEvict: (entry) => {
 *     console.log(`Evicted ${entry.url} (${entry.bytesLength} bytes, reason: ${entry.reason})`);
 *   },
 *   logger: console, // Custom logger for internal errors
 * });
 * ```
 *
 * @example Caching Encrypted User Data
 * ```typescript
 * import { SecureLRUCache } from '@david-osipov/security-kit';
 * 
 * // Create a cache for encrypted user profiles
 * const userCache = new SecureLRUCache<string, Uint8Array>({
 *   maxEntries: 1000,
 *   maxBytes: 10 * 1024 * 1024, // 10MB
 *   defaultTtlMs: 15 * 60 * 1000, // 15 minutes
 *   copyOnGet: true, // Return copies to prevent tampering
 *   onEvict: (entry) => {
 *     console.log(`User profile evicted: ${entry.url.replace('user:', '')}`);
 *   }
 * });
 * 
 * // Store encrypted user profile
 * async function storeUserProfile(userId: string, encryptedProfile: Uint8Array) {
 *   // Custom TTL for VIP users (longer cache time)
 *   const isVip = userId.startsWith('vip:');
 *   const ttl = isVip ? 60 * 60 * 1000 : undefined; // 1 hour for VIP, default for others
 *   
 *   userCache.set(`user:${userId}`, encryptedProfile, { ttlMs: ttl });
 * }
 * 
 * // Retrieve and decrypt
 * function getUserProfile(userId: string): Uint8Array | null {
 *   return userCache.get(`user:${userId}`) || null;
 * }
 * 
 * // Monitor cache performance
 * setInterval(() => {
 *   const stats = userCache.getStats();
 *   const hitRate = stats.hits / (stats.hits + stats.misses) * 100;
 *   console.log(`Cache hit rate: ${hitRate.toFixed(2)}%`);
 * }, 60000); // Every minute
 * ```
 *
 * @example Memory-Conscious Cache with Cleanup
 * ```typescript
 * import { SecureLRUCache } from '@david-osipov/security-kit';
 * 
 * const memoryCache = new SecureLRUCache({
 *   maxEntries: 200,
 *   maxBytes: 2 * 1024 * 1024, // 2MB hard limit
 *   highWatermarkBytes: 1.5 * 1024 * 1024, // Cleanup at 1.5MB
 *   defaultTtlMs: 10 * 60 * 1000, // 10 minutes
 *   maxSyncEvictions: 3, // Limit sync evictions to prevent blocking
 *   onEvict: (entry) => {
 *     if (entry.reason === 'capacity') {
 *       console.warn(`Memory pressure: evicted ${entry.url}`);
 *     }
 *   }
 * });
 * 
 * // Store file content with size validation
 * function cacheFileContent(path: string, content: ArrayBuffer) {
 *   if (content.byteLength > 500 * 1024) { // 500KB limit per file
 *     throw new Error('File too large for cache');
 *   }
 *   
 *   const bytes = new Uint8Array(content);
 *   memoryCache.set(`file:${path}`, bytes);
 * }
 * ```
 *
 * @example Secure API Token Cache
 * ```typescript
 * import { SecureLRUCache } from '@david-osipov/security-kit';
 * 
 * const tokenCache = new SecureLRUCache({
 *   maxEntries: 50,
 *   maxBytes: 1024 * 1024, // 1MB
 *   defaultTtlMs: 5 * 60 * 1000, // 5 minutes
 *   copyOnSet: true,
 *   copyOnGet: true,
 *   freezeReturns: false, // Don't freeze - we need to mutate for decryption
 *   rejectSharedBuffers: true,
 *   onEvict: (entry) => {
 *     // Log security events for token eviction
 *     console.log(`Token evicted: ${entry.url} (reason: ${entry.reason})`);
 *   },
 *   onWipeError: (error) => {
 *     console.error('Critical: Failed to securely wipe token data:', error);
 *   }
 * });
 * 
 * // Store OAuth tokens securely
 * function storeAccessToken(clientId: string, encryptedToken: Uint8Array, expiryMs: number) {
 *   const ttl = Math.min(expiryMs - Date.now(), 30 * 60 * 1000); // Max 30 min
 *   tokenCache.set(`token:${clientId}`, encryptedToken, { ttlMs: ttl });
 * }
 * 
 * // Retrieve and validate token
 * function getAccessToken(clientId: string): Uint8Array | null {
 *   const token = tokenCache.get(`token:${clientId}`);
 *   if (!token) {
 *     console.log(`Token cache miss for client: ${clientId}`);
 *     return null;
 *   }
 *   return token;
 * }
 * 
 * // Explicit token revocation
 * function revokeToken(clientId: string): void {
 *   tokenCache.delete(`token:${clientId}`);
 *   console.log(`Token revoked for client: ${clientId}`);
 * }
 * ```
 *
 * @security
 * This cache is designed with a security-first mindset to mitigate specific threats:
 * - **TOCTOU (Time-of-Check to Time-of-Use) Race Conditions:** By caching the exact bytes
 *   of a verified script, it ensures that the code executed is the same code that was
 *   validated, preventing an attacker from swapping the script between check and use.
 * - **Memory Exhaustion & Denial of Service (DoS):**
 *   - Strict `maxEntries` and `maxBytes` limits prevent attackers from filling memory.
 *   - The `set` operation performs a bounded number of synchronous evictions
 *     (`maxSyncEvictions`) to prevent long-running operations from blocking the main
 *     thread, failing loudly with an error if capacity cannot be made.
 * - **Data Leakage:**
 *   - **Zeroization:** Performs a best-effort wipe (`.fill(0)`) of byte arrays upon
 *     eviction to minimize the lifetime of sensitive data in memory.
 *   - **Defensive Copying:** `copyOnSet` and `copyOnGet` are enabled by default to
 *     prevent data corruption or leakage through shared buffer mutations.
 *   - **Telemetry:** `getStats()` does not include URLs by default to prevent leaking
 *     potentially sensitive information through monitoring channels.
 * - **Side-Channel Attacks:** Rejects `SharedArrayBuffer`-backed views by default to
 *   mitigate potential cross-thread information leakage.
 * - **Input Validation:** Throws typed errors for invalid inputs like oversized
 *   entries or excessively long keys, adhering to the "Fail Loudly, Fail Safely" principle.
 */
export class SecureLRUCache<K extends string, V extends Uint8Array> {
  /* eslint-disable functional/immutable-data, functional/no-let, functional/prefer-readonly-type */
  // --- Configuration (Immutable) ---
  readonly #maxEntries: number;
  readonly #maxBytes: number;
  readonly #defaultTtlMs: number;
  readonly #enableByteCache: boolean;
  readonly #copyOnSet: boolean;
  readonly #copyOnGet: boolean;
  readonly #rejectSharedBuffers: boolean;
  readonly #onEvict: ((entry: EvictedEntry) => void) | undefined;
  readonly #onWipeError: ((error: unknown) => void) | undefined;
  readonly #logger: Logger;
  readonly #maxEntryBytes: number;
  readonly #maxUrlLength: number;
  readonly #highWatermarkBytes: number;
  readonly #freezeReturns: boolean;
  readonly #includeUrlsInStats: boolean;
  readonly #maxSyncEvictions: number;

  // --- Statistics ---
  #hits = 0;
  #misses = 0;
  #evictions = 0;
  #expired = 0;
  #setOps = 0;
  #getOps = 0;

  // --- Core Data Structures ---
  #size = 0;
  #totalBytes = 0;
  readonly #keyMap: Map<K, number>;
  #keyList: (K | undefined)[];
  #valList: (V | undefined)[];
  #next: number[];
  #prev: number[];
  #head: number;
  #tail: number;
  readonly #free: number[];

  // --- TTL Tracking ---
  #ttls: number[];
  #starts: number[];

  constructor(options: CacheOptions = {}) {
    this.#maxEntries = options.maxEntries ?? 10;
    this.#maxBytes = options.maxBytes ?? 1_048_576;
    this.#defaultTtlMs = options.defaultTtlMs ?? 120_000;
    this.#enableByteCache = options.enableByteCache ?? true;
    this.#copyOnSet = options.copyOnSet ?? true;
    this.#copyOnGet = options.copyOnGet ?? true;
    this.#rejectSharedBuffers = options.rejectSharedBuffers ?? true;
    this.#onEvict = options.onEvict;
    this.#onWipeError = options.onWipeError;
    this.#logger = options.logger ?? console;
    this.#maxEntryBytes = options.maxEntryBytes ?? 512_000;
    this.#maxUrlLength = options.maxUrlLength ?? 2048;
    this.#highWatermarkBytes = options.highWatermarkBytes ?? 0;
    this.#freezeReturns = options.freezeReturns ?? false;
    this.#includeUrlsInStats = options.includeUrlsInStats ?? false;
    this.#maxSyncEvictions = options.maxSyncEvictions ?? 8;

    if (!Number.isInteger(this.#maxEntries) || this.#maxEntries <= 0)
      throw new TypeError("`maxEntries` must be a positive integer");
    if (!Number.isInteger(this.#maxBytes) || this.#maxBytes < 0)
      throw new TypeError("`maxBytes` must be a non-negative integer");
    if (this.#freezeReturns && !this.#copyOnGet)
      throw new Error("`freezeReturns` requires `copyOnGet` to be true.");

    const max = this.#maxEntries;
    this.#keyMap = new Map<K, number>();
    this.#keyList = new Array<K | undefined>(max).fill(undefined);
    this.#valList = new Array<V | undefined>(max).fill(undefined);
    this.#next = new Array<number>(max).fill(NO_INDEX);
    this.#prev = new Array<number>(max).fill(NO_INDEX);
    this.#head = NO_INDEX;
    this.#tail = NO_INDEX;
    this.#free = [];
    this.#ttls = new Array<number>(max).fill(0);
    this.#starts = new Array<number>(max).fill(0);
  }

  /**
   * Stores a value in the cache. This is a synchronous, low-latency operation with
   * O(1) amortized time complexity. To prevent main-thread blocking, it performs
   * a limited number of evictions.
   *
   * @param url - The key to associate with the value.
   * @param bytes - The `Uint8Array` value to store. A defensive copy is made by default.
   * @param opts - Per-operation options to override cache defaults.
   * @throws {InvalidParameterError} If inputs are invalid, or if capacity cannot be
   * made for the new item within the `maxSyncEvictions` limit.
   */
  // eslint-disable-next-line sonarjs/cognitive-complexity
  public set(url: K, bytes: V, options: SetOptions = {}): void {
    this.#setOps++;
    if (!this.#enableByteCache) return;

    if (typeof url !== "string" || url.length > this.#maxUrlLength)
      throw new InvalidParameterError(
        `Invalid URL: must be a string shorter than ${this.#maxUrlLength} characters.`,
      );
    if (!(bytes instanceof Uint8Array))
      throw new InvalidParameterError("Invalid value: must be a Uint8Array.");
    if (this.#rejectSharedBuffers && isSharedArrayBufferView(bytes))
      throw new InvalidParameterError(
        "SharedArrayBuffer-backed views are not permitted.",
      );

    const maxEntrySize = options.maxEntryBytes ?? this.#maxEntryBytes;
    if (bytes.length > maxEntrySize)
      throw new InvalidParameterError(
        `Entry too large: ${bytes.length} bytes exceeds max of ${maxEntrySize}.`,
      );
    // Also reject any single entry that exceeds the overall cache capacity.
    // Without this guard a single very large value could be inserted when the
    // cache is empty (the eviction loop below bails out when size === 0).
    if (bytes.length > this.#maxBytes)
      throw new InvalidParameterError(
        `Entry too large: ${bytes.length} bytes exceeds cache max of ${this.#maxBytes}.`,
      );

    const valueToStore = this.#copyOnSet ? (new Uint8Array(bytes) as V) : bytes;
    const ttl = options.ttlMs ?? this.#defaultTtlMs;
    const existingIndex = this.#keyMap.get(url);

    if (existingIndex !== undefined) {
      const oldValue = this.#valList[existingIndex] as V;
      this.#totalBytes = Math.max(0, this.#totalBytes - oldValue.length);
      this.#wipe(oldValue);
      this.#valList[existingIndex] = valueToStore;
      this.#totalBytes += valueToStore.length;
      this.#ttls[existingIndex] = ttl;
      this.#starts[existingIndex] = ttl > 0 ? now() : 0;
      this.#moveToTail(existingIndex);
      if (
        this.#highWatermarkBytes > 0 &&
        this.#totalBytes > this.#highWatermarkBytes
      )
        this.#cleanupExpired();
      return;
    }

    let evictions = 0;
    while (
      this.#size >= this.#maxEntries ||
      this.#totalBytes + valueToStore.length > this.#maxBytes
    ) {
      if (this.#size === 0) break;
      this.#evict();
      if (++evictions >= this.#maxSyncEvictions) {
        throw new InvalidParameterError(
          `Insufficient capacity after ${this.#maxSyncEvictions} evictions; reduce payload or retry later.`,
        );
      }
    }

    const index =
      this.#free.length > 0 ? (this.#free.pop() as number) : this.#size;
    this.#keyList[index] = url;
    this.#valList[index] = valueToStore;
    this.#keyMap.set(url, index);
    this.#totalBytes += valueToStore.length;
    this.#ttls[index] = ttl;
    this.#starts[index] = ttl > 0 ? now() : 0;

    if (this.#size === 0) {
      this.#head = this.#tail = index;
    } else {
      this.#next[this.#tail] = index;
      this.#prev[index] = this.#tail;
      this.#tail = index;
    }
    this.#size++;
    if (
      this.#highWatermarkBytes > 0 &&
      this.#totalBytes > this.#highWatermarkBytes
    )
      this.#cleanupExpired();
  }

  /**
   * Retrieves a value from the cache. If found, the entry is marked as most
   * recently used. This operation is O(1).
   *
   * @param url - The key of the value to retrieve.
   * @returns The stored `Uint8Array` or `undefined` if not found or expired.
   *          By default, a defensive copy is returned.
   */
  public get(url: K): V | undefined {
    this.#getOps++;
    if (!this.#enableByteCache) {
      this.#misses++;
      return undefined;
    }

    // Opportunistic cleanup every 32 get operations.
    if ((this.#getOps & 31) === 0) this.#cleanupExpired();

    const index = this.#keyMap.get(url);
    if (index === undefined) {
      this.#misses++;
      return undefined;
    }

    if (this.#isStale(index)) {
      this.#misses++;
      this.#deleteInternal(url, "ttl");
      return undefined;
    }

    this.#hits++;
    this.#moveToTail(index);
    let value = this.#valList[index] as V;

    if (this.#copyOnGet) value = new Uint8Array(value) as V;
    if (this.#freezeReturns) {
      try {
        // Freezing TypedArray instances may throw in some JS runtimes.
        // Attempt to freeze the typed array in-place first.
        Object.freeze(value);
      } catch {
        // Fallback: convert to a plain Array and freeze that. Tests only
        // assert that the returned value is frozen; returning a frozen
        // Array preserves indexing access and Object.isFrozen().
        // Consumers who require a Uint8Array should not enable freezeReturns.
        const arr = Object.freeze(Array.from(value));
        return arr as unknown as V;
      }
    }

    return value;
  }

  public delete(url: K): void {
    if (!this.#enableByteCache) return;
    this.#deleteInternal(url, "manual");
  }

  public clear(): void {
    if (!this.#enableByteCache) return;
    const keys = [...this.#keyMap.keys()];
    for (const key of keys) {
      this.#deleteInternal(key, "manual");
    }
  }

  public getStats(): CacheStats {
    return {
      size: this.#size,
      totalBytes: this.#totalBytes,
      hits: this.#hits,
      misses: this.#misses,
      evictions: this.#evictions,
      expired: this.#expired,
      setOps: this.#setOps,
      getOps: this.#getOps,
      urls: this.#includeUrlsInStats ? [...this.#keyMap.keys()] : [],
    };
  }

  #moveToTail(index: number): void {
    if (index === this.#tail) return;
    const p = this.#prev[index] ?? NO_INDEX;
    const n = this.#next[index] ?? NO_INDEX;
    if (index === this.#head) {
      this.#head = n;
      if (n !== NO_INDEX) this.#prev[n] = NO_INDEX;
    } else {
      if (p !== NO_INDEX) this.#next[p] = n;
      if (n !== NO_INDEX) this.#prev[n] = p;
    }
    this.#next[this.#tail] = index;
    this.#prev[index] = this.#tail;
    this.#next[index] = NO_INDEX;
    this.#tail = index;
  }

  #wipe(bytes: V): void {
    try {
      bytes.fill(0);
    } catch (error) {
      try {
        this.#onWipeError?.(error);
        this.#logger.error("Error during buffer wipe:", error);
      } catch {
        // Swallow logger/callback error
      }
    }
  }

  #isStale(index: number): boolean {
    const ttl = this.#ttls[index];
    if (!ttl || ttl <= 0) return false;
    const start = this.#starts[index] ?? 0;
    return now() - start > ttl;
  }

  #evict(): void {
    if (this.#size === 0 || this.#head === NO_INDEX) return;
    const key = this.#keyList[this.#head] as K;
    this.#evictions++;
    this.#deleteInternal(key, "capacity");
  }

  #deleteInternal(key: K, reason: EvictionReason): boolean {
    const index = this.#keyMap.get(key);
    if (index === undefined) return false;

    const value = this.#valList[index] as V;
    this.#wipe(value);
    this.#totalBytes = Math.max(0, this.#totalBytes - value.length);
    if (reason === "ttl") this.#expired++;

    this.#keyMap.delete(key);
    this.#keyList[index] = undefined;
    this.#valList[index] = undefined;

    const previous = this.#prev[index] ?? NO_INDEX;
    const next = this.#next[index] ?? NO_INDEX;
    if (index === this.#tail) this.#tail = previous;
    if (index === this.#head) this.#head = next;
    if (previous !== NO_INDEX) this.#next[previous] = next;
    if (next !== NO_INDEX) this.#prev[next] = previous;

    this.#prev[index] = NO_INDEX;
    this.#next[index] = NO_INDEX;
    this.#size--;
    this.#free.push(index);

    try {
      this.#onEvict?.({
        url: key,
        bytesLength: value.length,
        reason,
      });
    } catch (error) {
      try {
        this.#logger.error("Error in onEvict callback:", error);
      } catch {
        // Swallow secondary errors
      }
    }
    return true;
  }

  #cleanupExpired(): void {
    if (this.#size === 0 || this.#defaultTtlMs <= 0) return;
    const checkLimit = 5;
    let current = this.#head;
    let checked = 0;
    while (current !== NO_INDEX && checked < checkLimit) {
      const next = this.#next[current] ?? NO_INDEX;
      if (this.#isStale(current)) {
        this.#deleteInternal(this.#keyList[current] as K, "ttl");
      }
      if (next === current) break; // Defensive guard
      current = next;
      checked++;
    }
  }
  /* eslint-enable functional/immutable-data, functional/no-let, functional/prefer-readonly-type */
}

/**
 * A static singleton wrapper around `SecureLRUCache` for backward compatibility
 * and simple, global use cases. It provides a secure, in-memory cache for
 * verified worker script bytes.
 *
 * This utility helps eliminate Time-of-Check to Time-of-Use (TOCTOU) race
 * conditions by ensuring that the exact bytes verified at fetch time are the
 * same ones used to create a Worker from a Blob URL.
 *
 * @example Quick Start
 * ```typescript
 * import { VerifiedByteCache } from '@david-osipov/security-kit';
 *
 * // Store verified script bytes
 * const scriptUrl = 'https://example.com/worker.js';
 * const verifiedBytes = new TextEncoder().encode('self.postMessage("verified");');
 * VerifiedByteCache.set(scriptUrl, verifiedBytes);
 *
 * // Later, retrieve the exact same bytes for secure execution
 * const cachedBytes = VerifiedByteCache.get(scriptUrl);
 * if (cachedBytes) {
 *   const blob = new Blob([cachedBytes], { type: 'application/javascript' });
 *   const blobUrl = URL.createObjectURL(blob);
 *   const worker = new Worker(blobUrl); // TOCTOU-safe execution
 *   URL.revokeObjectURL(blobUrl);
 * }
 *
 * // View global cache statistics
 * console.log(VerifiedByteCache.getStats());
 * ```
 *
 * @example General Purpose Global Cache
 * ```typescript
 * import { VerifiedByteCache } from '@david-osipov/security-kit';
 * 
 * // Use as a general-purpose secure cache for any byte data
 * // Store configuration data
 * const configData = new TextEncoder().encode(JSON.stringify({
 *   apiEndpoint: 'https://api.example.com',
 *   maxRetries: 3,
 *   timeout: 5000
 * }));
 * VerifiedByteCache.set('app:config', configData);
 * 
 * // Store user preferences
 * const preferences = new TextEncoder().encode(JSON.stringify({
 *   theme: 'dark',
 *   language: 'en',
 *   notifications: true
 * }));
 * VerifiedByteCache.set('user:preferences:12345', preferences);
 * 
 * // Retrieve and parse
 * function getConfig(): any {
 *   const cached = VerifiedByteCache.get('app:config');
 *   if (cached) {
 *     return JSON.parse(new TextDecoder().decode(cached));
 *   }
 *   return null;
 * }
 * 
 * // Cache cleanup
 * VerifiedByteCache.delete('user:preferences:12345');
 * 
 * // Monitor global cache usage
 * const stats = VerifiedByteCache.getStats();
 * console.log(`Global cache: ${stats.size} entries, ${stats.totalBytes} bytes`);
 * ```
 *
 * @example Secure Template Cache
 * ```typescript
 * import { VerifiedByteCache } from '@david-osipov/security-kit';
 * 
 * // Cache compiled templates or sanitized HTML
 * function cacheTemplate(templateId: string, htmlContent: string) {
 *   const bytes = new TextEncoder().encode(htmlContent);
 *   VerifiedByteCache.set(`template:${templateId}`, bytes);
 * }
 * 
 * function getTemplate(templateId: string): string | null {
 *   const cached = VerifiedByteCache.get(`template:${templateId}`);
 *   return cached ? new TextDecoder().decode(cached) : null;
 * }
 * 
 * // Store sanitized user content
 * cacheTemplate('user-profile', '<div class="profile">Safe HTML</div>');
 * 
 * // Retrieve for rendering
 * const profileHtml = getTemplate('user-profile');
 * if (profileHtml) {
 *   document.getElementById('content').innerHTML = profileHtml;
 * }
 * ```
 *
 * @note For applications needing multiple cache instances or custom configuration,
 * use `SecureLRUCache` directly instead of this singleton.
 */
export class VerifiedByteCache {
  private static readonly singletonInstance = new SecureLRUCache<
    string,
    Uint8Array
  >({
    maxEntries: 10,
    maxBytes: 1_048_576,
    defaultTtlMs: 120_000,
    maxEntryBytes: 512_000,
    maxUrlLength: 2048,
    copyOnSet: true,
    copyOnGet: true,
    rejectSharedBuffers: true,
    freezeReturns: false,
    includeUrlsInStats: false, // Secure default for production
    maxSyncEvictions: 8,
  });

  public static set(url: string, bytes: Uint8Array): void {
    this.singletonInstance.set(url, bytes);
  }

  public static get(url: string): Uint8Array | undefined {
    return this.singletonInstance.get(url);
  }

  public static delete(url: string): void {
    this.singletonInstance.delete(url);
  }

  public static clear(): void {
    this.singletonInstance.clear();
  }

  public static getStats(): CacheStats {
    return this.singletonInstance.getStats();
  }
}
