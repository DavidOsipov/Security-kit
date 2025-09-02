// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

// -----------------------------------------------------------------------------
// ISC LICENSED CODE
// -----------------------------------------------------------------------------
// The following core LRU data structure logic is adapted from `lru-cache`,
// which is licensed under the ISC License.
// -----------------------------------------------------------------------------

import { InvalidParameterError } from "./errors";
import { secureWipe, isSharedArrayBufferView } from "./utils";
import { resolveSecureLRUOptions } from "./config";

/**
 * Represents the reason why a cache entry was evicted.
 */
export type EvictionReason = "capacity" | "ttl" | "manual";

/**
 * Information about an evicted cache entry, passed to the onEvict callback.
 */
export type EvictedEntry = {
  /** The URL/key of the evicted entry */
  readonly url: string;
  /** The size in bytes of the evicted entry's value */
  readonly bytesLength: number;
  /** The reason for eviction */
  readonly reason: EvictionReason;
};

/**
 * Logger interface for cache operations. Provides a minimal interface
 * to avoid accidental logging of sensitive data.
 */
export interface Logger {
  /** Log a warning message */
  warn(...data: readonly unknown[]): void;
  /** Log an error message */
  error(...data: readonly unknown[]): void;
}

/**
 * Configuration options for the SecureLRUCache.
 * Provides comprehensive control over cache behavior, security, and performance.
 */
export type CacheOptions = {
  /** Maximum number of entries the cache can hold. Defaults to 10. */
  readonly maxEntries?: number;
  /** Maximum total bytes the cache can hold. Defaults to 1MB (1,048,576 bytes). */
  readonly maxBytes?: number;
  /** Default TTL in milliseconds for cache entries. Defaults to 2 minutes (120,000ms). */
  readonly defaultTtlMs?: number;
  /** Whether to enable byte caching. Defaults to true. */
  readonly enableByteCache?: boolean;
  /** Whether to copy data on set operations for immutability. Defaults to true. */
  readonly copyOnSet?: boolean;
  /** Whether to copy data on get operations for immutability. Defaults to true. */
  readonly copyOnGet?: boolean;
  /** Whether to reject SharedArrayBuffer-backed views for security. Defaults to true. */
  readonly rejectSharedBuffers?: boolean;
  /** Callback invoked when entries are evicted from the cache. */
  readonly onEvict?: (entry: EvictedEntry) => void;
  /** Callback invoked when buffer wiping fails. */
  readonly onWipeError?: (error: unknown) => void;
  /** Logger instance for cache operations. Defaults to console-based logger. */
  readonly logger?: Logger;
  /** Maximum bytes per individual cache entry. Defaults to 512KB (524,288 bytes). */
  readonly maxEntryBytes?: number;
  /** Maximum length of URL keys. Defaults to 2048 characters. */
  readonly maxUrlLength?: number;
  /** High watermark for triggering cleanup. Defaults to 0 (disabled). */
  readonly highWatermarkBytes?: number;
  /** Whether to freeze returned values for immutability. Defaults to false. */
  readonly freezeReturns?: boolean;
  /** Whether to include URLs in cache statistics. Defaults to false. */
  readonly includeUrlsInStats?: boolean;
  /** Maximum number of synchronous evictions per operation. Defaults to 8. */
  readonly maxSyncEvictions?: number;
  /** Whether to enable automatic TTL-based purging. Defaults to false. */
  readonly ttlAutopurge?: boolean;
  /** TTL resolution in milliseconds for batching. Defaults to 0 (disabled). */
  readonly ttlResolutionMs?: number;
  /** Buffer wiping strategy: "defer" or "sync". Defaults to "defer". */
  readonly wipeStrategy?: "defer" | "sync";
  /** Maximum deferred wipes per flush operation. Defaults to 64. */
  readonly maxDeferredWipesPerFlush?: number;
  /** Scheduler for deferred wipe operations. Defaults to "auto". */
  readonly deferredWipeScheduler?: "microtask" | "timeout" | "auto";
  /** Timeout for deferred wipe operations. Defaults to 0. */
  readonly deferredWipeTimeoutMs?: number;
  /** Auto threshold for switching to timeout scheduler. Defaults to 128. */
  readonly deferredWipeAutoThreshold?: number;
  /** Auto bytes threshold for switching to timeout scheduler. Defaults to 256KB. */
  readonly deferredWipeAutoBytesThreshold?: number;
  /** Recency mode for cache eviction policy. Defaults to "lru". */
  readonly recencyMode?: "lru" | "segmented" | "second-chance" | "sieve";
  /** Scan limit for segmented eviction. Defaults to 8. */
  readonly segmentedEvictScan?: number;
  /** Operations between segment rotations. Defaults to 10,000. */
  readonly segmentRotateEveryOps?: number;
  /** Promotion behavior on get operations. Defaults to "always". */
  readonly promoteOnGet?: "always" | "sampled";
  /** Sample rate for promoteOnGet when set to "sampled". Defaults to 1. */
  readonly promoteOnGetSampleRate?: number;
  /** Optional clock source for TTL; defaults to Date.now(). */
  readonly clock?: () => number;
  /** Hard cap on deferred wipe queue bytes before falling back to sync wipe. */
  readonly maxWipeQueueBytes?: number;
  /** Hard cap on deferred wipe queue entries before falling back to sync wipe. */
  readonly maxWipeQueueEntries?: number;
  /** If false, do not expose raw URL to onEvict; use mapper or "[redacted]". */
  readonly evictCallbackExposeUrl?: boolean;
  /** Optional key mapper for onEvict to sanitize or hash URLs. */
  readonly onEvictKeyMapper?: (url: string) => string;
  /**
   * Second-chance tuning: maximum number of second-chance rotations (move-to-tail) to perform per eviction.
   * If omitted, defaults to `segmentedEvictScan`.
   */
  readonly secondChanceMaxRotationsPerEvict?: number;
};

/**
 * Options for individual set operations, allowing per-entry customization.
 */
export type SetOptions = {
  /** TTL in milliseconds for this specific entry. Overrides default TTL. */
  readonly ttlMs?: number;
  /** Maximum bytes for this specific entry. Overrides default maxEntryBytes. */
  readonly maxEntryBytes?: number;
};

/**
 * Cache statistics providing insight into cache performance and state.
 */
export type CacheStats = {
  /** Current number of entries in the cache. */
  readonly size: number;
  /** Total bytes used by all cache entries. */
  readonly totalBytes: number;
  /** Number of successful cache hits. */
  readonly hits: number;
  /** Number of cache misses. */
  readonly misses: number;
  /** Number of entries evicted due to capacity constraints. */
  readonly evictions: number;
  /** Number of entries expired due to TTL. */
  readonly expired: number;
  /** Total number of set operations performed. */
  readonly setOps: number;
  /** Total number of get operations performed. */
  readonly getOps: number;
  /** List of cached URLs (only populated if includeUrlsInStats is true). */
  readonly urls: readonly string[];
};

/**
 * Extended cache statistics including debug information for advanced eviction policies.
 */
export type DebugCacheStats = CacheStats & {
  /** Number of SIEVE eviction scans performed (only for sieve/second-chance modes). */
  readonly sieveScans?: number;
  /** Number of SIEVE rotations performed (only for sieve/second-chance modes). */
  readonly sieveRotations?: number;
};

const NO_INDEX = -1;

// SAB detection centralized in utils.isSharedArrayBufferView

/**
 * Securely zeros out a Uint8Array buffer to prevent data leakage.
 *
 * Uses a loop-based approach to reduce the risk of compiler optimization
 * eliminating the zeroization for security purposes.
 *
 * @param buf - The buffer to zero out
 */
// secureZero replaced by unified secureWipe from utils

/**
 * Schedules a microtask using the most appropriate available method.
 *
 * Falls back to Promise.resolve().then() if queueMicrotask is not available.
 *
 * @param callback - The function to execute as a microtask
 */
function scheduleMicrotask(callback: () => void): void {
  if (typeof queueMicrotask === "function") {
    queueMicrotask(callback);
  } else {
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    Promise.resolve().then(callback);
  }
}

/**
 * Attempts to unref a timer in Node.js environments to prevent keeping
 * the event loop alive unnecessarily.
 *
 * @param t - The timer object (typically a setTimeout return value)
 */
function tryUnref(t: unknown): void {
  try {
    const maybe = t as { readonly unref?: () => void };
    if (maybe && typeof maybe.unref === "function") maybe.unref();
  } catch {
    /* noop */
  }
}

/**
 * A secure, high-performance LRU cache implementation with advanced eviction policies,
 * memory safety features, and comprehensive security controls.
 *
 * Key features:
 * - Multiple eviction policies: LRU, Segmented LRU, Second-Chance, and SIEVE
 * - Secure buffer wiping to prevent data leakage
 * - SharedArrayBuffer detection and rejection (rejectSharedBuffers defaults to true)
 * - TTL support with automatic expiration
 * - Cooperative eviction for large entries
 * - Comprehensive statistics and monitoring
 * - Memory pressure handling and bounds checking
 *
 * @template K - The key type (must extend string)
 * @template V - The value type (must extend Uint8Array)
 */
export class SecureLRUCache<K extends string, V extends Uint8Array> {
  /* eslint-disable functional/immutable-data, functional/no-let, functional/prefer-readonly-type */
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
  readonly #onEvictKeyMapper: ((url: string) => string) | undefined;
  readonly #evictCallbackExposeUrl: boolean;
  readonly #maxEntryBytes: number;
  readonly #maxUrlLength: number;
  readonly #highWatermarkBytes: number;
  readonly #freezeReturns: boolean;
  readonly #includeUrlsInStats: boolean;
  readonly #maxSyncEvictions: number;
  readonly #ttlAutopurge: boolean;
  readonly #ttlResolutionMs: number;
  readonly #wipeStrategy: "defer" | "sync";
  readonly #maxDeferredWipesPerFlush: number;
  readonly #deferredWipeScheduler: "microtask" | "timeout" | "auto";
  readonly #deferredWipeTimeoutMs: number;
  readonly #deferredWipeAutoThreshold: number;
  readonly #deferredWipeAutoBytesThreshold: number;
  /** Recency mode for cache eviction policy. Defaults to "lru". */
  readonly #recencyMode: "lru" | "segmented" | "second-chance" | "sieve";
  /** Scan limit for segmented eviction. Defaults to 8. */
  readonly #segmentedEvictScan: number;
  /** Operations between segment rotations. Defaults to 10,000. */
  readonly #segmentRotateEveryOps: number;
  /** Promotion behavior on get operations. Defaults to "always". */
  readonly #promoteOnGet: "always" | "sampled";
  /** Sample rate for promoteOnGet when set to "sampled". Defaults to 1. */
  readonly #promoteOnGetSampleRate: number;
  /** Hard cap on deferred wipe queue total bytes. */
  readonly #maxWipeQueueBytes: number;
  /** Hard cap on deferred wipe queue entries. */
  readonly #maxWipeQueueEntries: number;
  /** Second-chance tuning: maximum number of rotations per eviction. */
  readonly #secondChanceMaxRotationsPerEvict: number;

  // Stats
  #hits = 0;
  #misses = 0;
  #evictions = 0;
  #expired = 0;
  #setOps = 0;
  #getOps = 0;
  // SIEVE diagnostics
  #sieveScans = 0;
  #sieveRotations = 0;

  // Core structures
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

  // TTL tracking
  #ttls: number[];
  #starts: number[];

  // Recency policy state (segmented/second-chance/SIEVE)
  #gen: number[];
  #currentGen = 0;
  #sieveRef: Uint8Array;
  #sieveHand: number = NO_INDEX;

  // Deferred wiping
  readonly #wipeQueue: V[] = [];
  #wipeScheduled = false;
  #wipeQueueBytes = 0;
  #wipeTimer: ReturnType<typeof setTimeout> | undefined;
  // Coalesce noisy warnings when caps are exceeded in a tight loop
  #wipeFallbackBurstCount = 0;
  #wipeFallbackLogScheduled = false;

  // TTL autopurge & clock
  #nextExpiry = Number.POSITIVE_INFINITY;
  #expiryTimer: ReturnType<typeof setTimeout> | undefined;
  #nowTick = 0;
  #nowLast = 0;
  readonly #clock: () => number;

  // Deferred (asynchronous) callback queue to avoid reentrancy during mutations
  readonly #deferredCallbacks: Array<() => void> = [];

  /**
   * Creates a new SecureLRUCache instance with the specified configuration.
   *
   * @param options - Configuration options for the cache
   * @throws {TypeError} If maxEntries or maxBytes are invalid
   * @throws {Error} If freezeReturns is true but copyOnGet is false
   *
   * @example
   * ```typescript
   * const cache = new SecureLRUCache<string, Uint8Array>({
   *   maxEntries: 100,
   *   maxBytes: 10 * 1024 * 1024, // 10MB
   *   recencyMode: 'lru'
   * });
   * ```
   */
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
    // Minimal, namespaced default logger to discourage sensitive payload logging
    const safeDefaultLogger: Logger = {
      warn: (...data: readonly unknown[]) =>
        console.warn("[security-kit:cache]", ...data),
      error: (...data: readonly unknown[]) =>
        console.error("[security-kit:cache]", ...data),
    };
    this.#logger = options.logger ?? safeDefaultLogger;
    this.#onEvictKeyMapper = options.onEvictKeyMapper;
  // Backward compat: standalone class historically exposed raw URL to onEvict by default.
  // VerifiedByteCache explicitly overrides to false to preserve privacy-by-default at the facade.
  this.#evictCallbackExposeUrl = options.evictCallbackExposeUrl ?? true;
    this.#maxEntryBytes = options.maxEntryBytes ?? 512_000;
    this.#maxUrlLength = options.maxUrlLength ?? 2048;
    this.#highWatermarkBytes = options.highWatermarkBytes ?? 0;
    this.#freezeReturns = options.freezeReturns ?? false;
    this.#includeUrlsInStats = options.includeUrlsInStats ?? false;
    this.#maxSyncEvictions = options.maxSyncEvictions ?? 8;
    this.#ttlAutopurge = options.ttlAutopurge ?? false;
    this.#ttlResolutionMs = options.ttlResolutionMs ?? 0;
    this.#wipeStrategy = options.wipeStrategy ?? "defer";
    this.#maxDeferredWipesPerFlush = options.maxDeferredWipesPerFlush ?? 64;
    this.#deferredWipeScheduler = options.deferredWipeScheduler ?? "auto";
    this.#deferredWipeTimeoutMs = options.deferredWipeTimeoutMs ?? 0;
    this.#deferredWipeAutoThreshold = options.deferredWipeAutoThreshold ?? 128;
    this.#deferredWipeAutoBytesThreshold =
      options.deferredWipeAutoBytesThreshold ?? 256 * 1024;
    this.#maxWipeQueueBytes = options.maxWipeQueueBytes ?? 10 * 1024 * 1024; // 10MB
    this.#maxWipeQueueEntries = options.maxWipeQueueEntries ?? 4096;
    this.#recencyMode = options.recencyMode ?? "lru";
    this.#segmentedEvictScan = Math.max(1, options.segmentedEvictScan ?? 8);
    this.#segmentRotateEveryOps = Math.max(
      1,
      options.segmentRotateEveryOps ?? 10_000,
    );
    this.#secondChanceMaxRotationsPerEvict = Math.max(
      1,
      options.secondChanceMaxRotationsPerEvict ?? this.#segmentedEvictScan,
    );
    this.#promoteOnGet = options.promoteOnGet ?? "always";
    const sampleRate = Math.max(
      1,
      Math.floor(options.promoteOnGetSampleRate ?? 1),
    );
    if (!Number.isInteger(sampleRate))
      throw new TypeError("promoteOnGetSampleRate must be an integer ≥ 1");
    this.#promoteOnGetSampleRate = sampleRate;
    this.#clock = options.clock ?? (() => Date.now());

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
    this.#gen = new Array<number>(max).fill(0);
    this.#sieveRef = new Uint8Array(max);

    // Initialize time tick
    this.#nowTick = this.#readClock();
    this.#nowLast = this.#nowTick;
  }

  /**
   * Stores a value in the cache with the specified key.
   *
   * This method performs synchronous eviction if necessary to make room for the new entry.
   * If the eviction budget is exceeded, it throws an error rather than performing
   * excessive synchronous work.
   *
   * @param url - The key to store the value under (must be a string)
   * @param bytes - The Uint8Array value to store
   * @param options - Optional settings for this specific set operation
   * @throws {InvalidParameterError} If the URL is invalid, value is not a Uint8Array,
   *                                 SharedArrayBuffer is detected, or entry is too large
   * @throws {InvalidParameterError} If insufficient capacity after maxSyncEvictions
   *
   * @example
   * ```typescript
   * const data = new Uint8Array([1, 2, 3, 4, 5]);
   * cache.set('https://example.com/data', data, { ttlMs: 30000 });
   * ```
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
      this.#starts[existingIndex] = ttl > 0 ? this.#tickNow() : 0;
      switch (this.#recencyMode) {
        case "lru":
          this.#moveToTail(existingIndex);
          break;
        case "segmented":
          this.#gen[existingIndex] = this.#currentGen;
          break;
        case "second-chance":
        case "sieve":
    if (this.#sieveRef[existingIndex] !== 1) this.#sieveRef[existingIndex] = 1;
          break;
      }
      if (ttl > 0) this.#maybeScheduleExpiry(this.#starts[existingIndex] + ttl);
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
    this.#starts[index] = ttl > 0 ? this.#tickNow() : 0;
    switch (this.#recencyMode) {
      case "segmented":
        this.#gen[index] = this.#currentGen;
        break;
      case "second-chance":
      case "sieve":
        // New entries start unreferenced to evict one-hit-wonders quickly; no pointer moves on set
  if (this.#sieveRef[index] !== 0) this.#sieveRef[index] = 0;
        break;
      default:
        break;
    }

    if (this.#size === 0) {
      this.#head = this.#tail = index;
    } else {
      this.#next[this.#tail] = index;
      this.#prev[index] = this.#tail;
      this.#tail = index;
    }
    this.#size++;
    if (ttl > 0) this.#maybeScheduleExpiry(this.#starts[index] + ttl);
    if (
      this.#highWatermarkBytes > 0 &&
      this.#totalBytes > this.#highWatermarkBytes
    )
      this.#cleanupExpired();
  }

  /**
   * Retrieves a value from the cache by key.
   *
   * Returns a copy of the cached value if copyOnGet is enabled, or the original
   * value if disabled. The returned value may be frozen if freezeReturns is enabled.
   *
   * @param url - The key to retrieve
   * @returns The cached Uint8Array value, or undefined if not found or expired
   *
   * @example
   * ```typescript
   * const data = cache.get('https://example.com/data');
   * if (data) {
   *   console.log('Data length:', data.length);
   * }
   * ```
   */
  public get(url: K): V | undefined {
    this.#getOps++;
    if (!this.#enableByteCache) {
      this.#misses++;
      return undefined;
    }

    if (!this.#ttlAutopurge && (this.#getOps & 31) === 0) {
      this.#cleanupExpired();
    }

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
    switch (this.#recencyMode) {
      case "lru": {
        const shouldPromote =
          this.#promoteOnGet === "always" ||
          (this.#promoteOnGet === "sampled" &&
            this.#getOps % this.#promoteOnGetSampleRate === 0);
        if (shouldPromote) this.#moveToTail(index);
        break;
      }
      case "segmented":
        this.#gen[index] = this.#currentGen;
        if (this.#getOps % this.#segmentRotateEveryOps === 0) {
          this.#currentGen++;
        }
        break;
      case "second-chance":
      case "sieve":
        // Mark referenced; canonical SIEVE avoids pointer churn
  if (this.#sieveRef[index] !== 1) this.#sieveRef[index] = 1;
        break;
    }
    let value = this.#valList[index] as V;

    if (this.#copyOnGet) value = new Uint8Array(value) as V;
    if (this.#freezeReturns) {
      try {
        Object.freeze(value);
      } catch {
        // noop; do not violate return type with Array fallback
      }
    }

    return value;
  }

  /**
   * Asynchronously stores a value in the cache with cooperative eviction.
   *
   * Unlike the synchronous `set` method, this method yields control across microtasks
   * when performing evictions, preventing blocking of the event loop for large entries
   * or when many evictions are needed.
   *
   * @param url - The key to store the value under (must be a string)
   * @param bytes - The Uint8Array value to store
   * @param options - Optional settings for this specific set operation
   * @returns Promise that resolves when the operation is complete
   * @throws {InvalidParameterError} If the URL is invalid, value is not a Uint8Array,
   *                                 SharedArrayBuffer is detected, or entry is too large
   *
   * @example
   * ```typescript
   * const largeData = new Uint8Array(100000); // 100KB
   * await cache.setAsync('https://example.com/large-data', largeData);
   * console.log('Large data cached successfully');
   * ```
   */
  public async setAsync(
    url: K,
    bytes: V,
    options: SetOptions = {},
  ): Promise<void> {
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
      this.#starts[existingIndex] = ttl > 0 ? this.#tickNow() : 0;
      switch (this.#recencyMode) {
        case "lru":
          this.#moveToTail(existingIndex);
          break;
        case "segmented":
          this.#gen[existingIndex] = this.#currentGen;
          break;
        case "second-chance":
        case "sieve":
          if (this.#sieveRef[existingIndex] !== 1) this.#sieveRef[existingIndex] = 1;
          break;
      }
      if (ttl > 0) this.#maybeScheduleExpiry(this.#starts[existingIndex] + ttl);
      if (
        this.#highWatermarkBytes > 0 &&
        this.#totalBytes > this.#highWatermarkBytes
      )
        this.#cleanupExpired();
      return;
    }

    // Cooperatively evict across microtasks until enough capacity is available
    const needsCapacity = () =>
      this.#size >= this.#maxEntries ||
      this.#totalBytes + valueToStore.length > this.#maxBytes;

    // Limit work per turn using the same sync budget, then yield
    while (needsCapacity()) {
      if (this.#size === 0) break;
      let budget = this.#maxSyncEvictions;
      while (needsCapacity() && budget-- > 0) {
        this.#evict();
      }
      if (needsCapacity()) {
        await new Promise<void>((resolve) => scheduleMicrotask(resolve));
      }
    }

    const index =
      this.#free.length > 0 ? (this.#free.pop() as number) : this.#size;
    this.#keyList[index] = url;
    this.#valList[index] = valueToStore;
    this.#keyMap.set(url, index);
    this.#totalBytes += valueToStore.length;
    this.#ttls[index] = ttl;
    this.#starts[index] = ttl > 0 ? this.#tickNow() : 0;
    switch (this.#recencyMode) {
      case "segmented":
        this.#gen[index] = this.#currentGen;
        break;
      case "second-chance":
      case "sieve":
  if (this.#sieveRef[index] !== 0) this.#sieveRef[index] = 0;
        break;
      default:
        break;
    }

    if (this.#size === 0) {
      this.#head = this.#tail = index;
    } else {
      this.#next[this.#tail] = index;
      this.#prev[index] = this.#tail;
      this.#tail = index;
    }
    this.#size++;
    if (ttl > 0) this.#maybeScheduleExpiry(this.#starts[index] + ttl);
    if (
      this.#highWatermarkBytes > 0 &&
      this.#totalBytes > this.#highWatermarkBytes
    )
      this.#cleanupExpired();
  }

  /**
   * Removes a specific entry from the cache.
   *
   * The entry's buffer will be securely wiped according to the configured wipe strategy.
   *
   * @param url - The key of the entry to remove
   */
  public delete(url: K): void {
    if (!this.#enableByteCache) return;
    this.#deleteInternal(url, "manual");
  }

  /**
   * Removes all entries from the cache.
   *
   * All buffers will be securely wiped according to the configured wipe strategy.
   * This operation also resets the SIEVE hand pointer for proper eviction behavior.
   */
  public clear(): void {
    if (!this.#enableByteCache) return;
    const keys = [...this.#keyMap.keys()];
    for (const key of keys) {
      this.#deleteInternal(key, "manual");
    }
    // Reset canonical SIEVE hand as the list is empty now
    this.#sieveHand = NO_INDEX;
  }

  /**
   * Returns comprehensive statistics about cache performance and state.
   *
   * @returns Cache statistics including hits, misses, evictions, and current state
   *
   * @example
   * ```typescript
   * const stats = cache.getStats();
   * console.log(`Cache hit rate: ${stats.hits / (stats.hits + stats.misses)}`);
   * console.log(`Current entries: ${stats.size}`);
   * ```
   */
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

  /**
   * Returns extended statistics including debug information for advanced eviction policies.
   *
   * Includes SIEVE-specific metrics when using sieve or second-chance eviction modes.
   *
   * @returns Extended cache statistics with debug information
   */
  public getDebugStats(): DebugCacheStats {
    const base = this.getStats();
    if (this.#recencyMode !== "sieve" && this.#recencyMode !== "second-chance")
      return base;
    return {
      ...base,
      sieveScans: this.#sieveScans,
      sieveRotations: this.#sieveRotations,
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
    if (this.#wipeStrategy === "sync") {
      try {
        const ok = secureWipe(bytes, { forbidShared: true });
        if (!ok) {
          try {
            this.#onWipeError?.(new Error("secureWipe failed"));
            this.#logger.warn("secureWipe returned false during sync wipe");
          } catch {
            /* noop */
          }
        }
      } catch (error) {
        try {
          this.#onWipeError?.(error);
          this.#logger.error("Error during buffer wipe:", error);
        } catch {
          /* noop */
        }
      }
      return;
    }
    // Enforce hard caps to avoid unbounded memory growth
    if (
      this.#wipeQueueBytes + bytes.length > this.#maxWipeQueueBytes ||
      this.#wipeQueue.length + 1 > this.#maxWipeQueueEntries
    ) {
      // Try a quick local flush to free capacity before falling back
      if (this.#wipeQueue.length > 0) {
        this.#flushWipeQueue();
      }
      if (
        this.#wipeQueueBytes + bytes.length <= this.#maxWipeQueueBytes &&
        this.#wipeQueue.length + 1 <= this.#maxWipeQueueEntries
      ) {
        // Room freed, proceed with deferred path
        this.#wipeQueue.push(bytes);
        this.#wipeQueueBytes += bytes.length;
        if (!this.#wipeScheduled) {
          this.#wipeScheduled = true;
          this.#scheduleWipeFlush();
        }
        return;
      }

      // No room: perform synchronous wipe but coalesce noisy warnings
      try {
        const ok = secureWipe(bytes, { forbidShared: true });
        if (!ok) this.#onWipeError?.(new Error("secureWipe failed"));
      } catch (error) {
        try {
          this.#onWipeError?.(error);
          this.#logger.error("Error during sync wipe fallback:", error);
        } catch {
          /* noop */
        }
      }
      // Increment burst count and log immediately on first occurrence to satisfy
      // caller expectations/tests; coalesce subsequent occurrences into one summary.
      if (!this.#wipeFallbackLogScheduled && this.#wipeFallbackBurstCount === 0) {
        try {
          this.#logger.warn(
            "Deferred wipe caps exceeded; performed synchronous wipe.",
          );
        } catch {
          /* best-effort logging only */
        }
      }
      this.#wipeFallbackBurstCount++;
      if (!this.#wipeFallbackLogScheduled) {
        this.#wipeFallbackLogScheduled = true;
        scheduleMicrotask(() => {
          try {
            const count = this.#wipeFallbackBurstCount;
            this.#wipeFallbackBurstCount = 0;
            this.#wipeFallbackLogScheduled = false;
            if (count > 1) {
              this.#logger.warn(
                `Deferred wipe caps exceeded; performed synchronous wipes (${count}x).`,
                {
                  queueEntries: this.#wipeQueue.length,
                  queueBytes: this.#wipeQueueBytes,
                  caps: {
                    maxEntries: this.#maxWipeQueueEntries,
                    maxBytes: this.#maxWipeQueueBytes,
                  },
                  hint:
                    "For bulk deletions, consider calling flushWipes()/flushWipesSync() or increasing caps.",
                },
              );
            }
          } catch {
            /* best-effort logging only */
          }
        });
      }
      return;
    }
    this.#wipeQueue.push(bytes);
    this.#wipeQueueBytes += bytes.length;
    if (!this.#wipeScheduled) {
      this.#wipeScheduled = true;
      this.#scheduleWipeFlush();
    }
  }

  #isStale(index: number): boolean {
    const ttl = this.#ttls[index];
    if (!ttl || ttl <= 0) return false;
    const start = this.#starts[index] ?? 0;
    return this.#tickNow() - start > ttl;
  }

  // eslint-disable-next-line sonarjs/cognitive-complexity
  #evict(): void {
    if (this.#size === 0 || this.#head === NO_INDEX) return;
    switch (this.#recencyMode) {
      case "segmented": {
        let target = this.#head;
        let cursor = this.#head;
        let scanned = 0;
        const thresholdGen = this.#currentGen;
        while (cursor !== NO_INDEX && scanned < this.#segmentedEvictScan) {
          const g = this.#gen[cursor] ?? 0;
          if (g < thresholdGen) {
            target = cursor;
            break;
          }
          cursor = this.#next[cursor] ?? NO_INDEX;
          scanned++;
        }
        const key = this.#keyList[target] as K;
        this.#evictions++;
        this.#deleteInternal(key, "capacity");
        return;
      }
      case "second-chance": {
        let cursor = this.#head;
        let scanned = 0;
        let rotations = 0;
        while (cursor !== NO_INDEX && scanned < this.#segmentedEvictScan) {
          this.#sieveScans++;
          const next = this.#next[cursor] ?? NO_INDEX;
          if (this.#sieveRef[cursor] === 0) {
            const key = this.#keyList[cursor] as K;
            this.#evictions++;
            this.#deleteInternal(key, "capacity");
            return;
          }
          if (rotations < this.#secondChanceMaxRotationsPerEvict) {
            this.#sieveRef[cursor] = 0;
            this.#moveToTail(cursor);
            this.#sieveRotations++;
            rotations++;
          } else {
            break; // rotation budget exhausted for this eviction
          }
          cursor = next;
          scanned++;
        }
        const key = this.#keyList[this.#head] as K;
        this.#evictions++;
        this.#deleteInternal(key, "capacity");
        return;
      }
      case "sieve": {
        // Canonical SIEVE: persistent hand, do not move nodes; just flip bits
        if (this.#sieveHand === NO_INDEX) this.#sieveHand = this.#tail;
        let scanned = 0;
        let hand = this.#sieveHand;
        while (hand !== NO_INDEX && scanned < this.#segmentedEvictScan) {
          this.#sieveScans++;
          if (this.#sieveRef[hand] === 0) {
            const evictIndex = hand;
            const previousIndex = this.#prev[evictIndex] ?? this.#tail; // hand moves backwards
            const key = this.#keyList[evictIndex] as K;
            this.#evictions++;
            // advance hand to previous before deletion to avoid invalid index
            this.#sieveHand = previousIndex;
            this.#deleteInternal(key, "capacity");
            return;
          }
          // give second chance by clearing bit; move hand back one (towards head)
          if (this.#sieveRef[hand] !== 0) this.#sieveRef[hand] = 0;
          const previousIndex = this.#prev[hand] ?? this.#tail;
          hand = previousIndex;
          scanned++;
        }
        // Fallback: bounded work exhausted; evict head to guarantee progress
        const key = this.#keyList[this.#head] as K;
        this.#evictions++;
        this.#deleteInternal(key, "capacity");
        return;
      }
      default: {
        const key = this.#keyList[this.#head] as K;
        this.#evictions++;
        this.#deleteInternal(key, "capacity");
      }
    }
  }

  #deleteInternal(key: K, reason: EvictionReason): boolean {
    const index = this.#keyMap.get(key);
    if (index === undefined) return false;

    const value = this.#valList[index] as V;
    const bytesLength = value.length; // capture before wiping
    // Always use unified wipe policy; do not perform unexpected sync wipes in defer mode
    this.#wipe(value);
    this.#totalBytes = Math.max(0, this.#totalBytes - value.length);
    if (reason === "ttl") this.#expired++;

    // Maintain canonical SIEVE hand if it points to this index
    if (this.#recencyMode === "sieve") {
      if (this.#sieveHand === index) {
        // Move hand to predecessor only. If none (head), invalidate; it will
        // reset to the new tail lazily on the next eviction.
        this.#sieveHand = this.#prev[index] ?? NO_INDEX;
      }
    }

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
    if (
      this.#recencyMode === "sieve" ||
      this.#recencyMode === "second-chance"
    ) {
      this.#sieveRef[index] = 0;
    }

    // Defer callback execution to avoid reentrancy during mutation
    if (this.#onEvict) {
      this.#enqueueCallback(() => {
        let mappedUrl = "[redacted]";
        try {
          if (this.#onEvictKeyMapper) {
            mappedUrl = this.#onEvictKeyMapper(key);
          } else if (this.#evictCallbackExposeUrl) {
            mappedUrl = key;
          }
        } catch (mapError) {
          try {
            this.#logger.error("onEvictKeyMapper threw:", mapError);
          } catch {
            /* noop */
          }
          mappedUrl = "[mapper-error]";
        }
        try {
          this.#onEvict?.({ url: mappedUrl, bytesLength, reason });
        } catch (error) {
          try {
            this.#logger.error("Error in onEvict callback:", error);
          } catch {
            /* noop */
          }
        }
      });
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
      if (next === current) break;
      current = next;
      checked++;
    }
  }

  #flushWipeQueue(): void {
    this.#wipeScheduled = false;
    if (this.#wipeTimer) {
      clearTimeout(this.#wipeTimer);
      this.#wipeTimer = undefined;
    }
    const limit = this.#maxDeferredWipesPerFlush;
    let processed = 0;
    while (this.#wipeQueue.length > 0 && processed < limit) {
      const buf = this.#wipeQueue.shift() as V;
      try {
        const ok = secureWipe(buf, { forbidShared: true });
        if (!ok) this.#onWipeError?.(new Error("secureWipe failed"));
      } catch (error) {
        try {
          this.#onWipeError?.(error);
          this.#logger.error("Error during deferred buffer wipe:", error);
        } catch {
          /* noop */
        }
      }
      this.#wipeQueueBytes = Math.max(0, this.#wipeQueueBytes - buf.length);
      processed++;
    }
    if (this.#wipeQueue.length > 0) {
      this.#wipeScheduled = true;
      this.#scheduleWipeFlush();
    }
  }

  #scheduleWipeFlush(): void {
    const useTimeout = (() => {
      if (this.#deferredWipeScheduler === "timeout") return true;
      if (this.#deferredWipeScheduler === "microtask") return false;
      return (
        this.#wipeQueue.length >= this.#deferredWipeAutoThreshold ||
        this.#wipeQueueBytes >= this.#deferredWipeAutoBytesThreshold
      );
    })();

    if (useTimeout) {
      if (this.#wipeTimer) return;
      this.#wipeTimer = setTimeout(
        () => this.#flushWipeQueue(),
        this.#deferredWipeTimeoutMs,
      );
      tryUnref(this.#wipeTimer);
    } else {
      scheduleMicrotask(() => this.#flushWipeQueue());
    }
  }

  #readClock(): number {
    // Maintainer note: TTL clock source
    // We intentionally use Date.now() instead of performance.now().
    // - Date.now() aligns with wall-clock time and advances under typical test
    //   fake timers/mocks used in Node, ensuring TTL expiry progresses.
    // - performance.now() is monotonic and immune to system time changes, but
    //   many test frameworks do not advance it with fake timers, leading to
    //   perceived "stuck" TTLs and flaky tests.
    // This is a pragmatic trade-off compatible with server environments and
    // preserves reliable TTL behavior under tests.
    return this.#clock();
  }

  #tickNow(): number {
    if (this.#ttlResolutionMs <= 0) return this.#readClock();
    const t = this.#readClock();
    // Also update if the clock moved backwards (e.g., fake timers swapped in)
    if (t - this.#nowLast >= this.#ttlResolutionMs || t < this.#nowLast) {
      this.#nowTick = t;
      this.#nowLast = t;
    }
    return this.#nowTick;
  }

  #maybeScheduleExpiry(expiry: number): void {
    if (!this.#ttlAutopurge || expiry <= 0 || !Number.isFinite(expiry)) return;
    if (expiry >= this.#nextExpiry) return;
    this.#nextExpiry = expiry;
    this.#scheduleExpiryTimer();
  }

  #scheduleExpiryTimer(): void {
    if (!this.#ttlAutopurge) return;
    if (this.#expiryTimer) {
      clearTimeout(this.#expiryTimer);
      this.#expiryTimer = undefined;
    }
    const delay = Math.max(0, this.#nextExpiry - this.#tickNow());
    this.#expiryTimer = setTimeout(() => {
      this.#runTtlPurgeBatch();
    }, delay);
    tryUnref(this.#expiryTimer);
  }

  /**
   * Checks if a key exists in the cache without promoting its recency.
   *
   * This method does not trigger eviction callbacks or recency updates.
   * If the entry exists but is expired, it will be removed and false returned.
   *
   * @param url - The key to check for existence
   * @returns true if the key exists and is not expired, false otherwise
   */
  public has(url: K): boolean {
    if (!this.#enableByteCache) return false;
    const index = this.#keyMap.get(url);
    if (index === undefined) return false;
    if (this.#isStale(index)) {
      this.#deleteInternal(url, "ttl");
      return false;
    }
    return true;
  }

  /**
   * Retrieves a value from the cache without promoting its recency.
   *
   * This method applies the same copy and freeze options as get() but does not
   * update the entry's position in the eviction order.
   *
   * @param url - The key to retrieve
   * @returns The cached value with copy/freeze applied, or undefined if not found or expired
   */
  public peek(url: K): V | undefined {
    if (!this.#enableByteCache) return undefined;
    const index = this.#keyMap.get(url);
    if (index === undefined) return undefined;
    if (this.#isStale(index)) {
      this.#deleteInternal(url, "ttl");
      return undefined;
    }
    let value = this.#valList[index] as V;
    if (this.#copyOnGet) value = new Uint8Array(value) as V;
    if (this.#freezeReturns) {
      try {
        Object.freeze(value);
      } catch {
        /* noop */
      }
    }
    return value;
  }

  /**
   * Immediately removes all expired entries from the cache.
   *
   * This method scans the entire cache and removes any entries that have exceeded
   * their TTL. It returns the number of entries removed.
   *
   * @returns The number of expired entries that were removed
   */
  public purgeExpired(): number {
    if (!this.#enableByteCache) return 0;
    if (this.#size === 0) return 0;
    let purged = 0;
    let current = this.#head;
    while (current !== NO_INDEX) {
      const next = this.#next[current] ?? NO_INDEX;
      if (this.#isStale(current)) {
        this.#deleteInternal(this.#keyList[current] as K, "ttl");
        purged++;
      }
      current = next;
    }
    return purged;
  }

  /**
   * Asynchronously flushes all pending deferred wipes.
   *
   * This method processes the wipe queue in chunks, yielding control between
   * chunks to avoid blocking the event loop. It resolves when all wipes are complete.
   *
   * @returns Promise that resolves when all pending wipes have been processed
   */
  public async flushWipes(): Promise<void> {
    // Drain in chunks respecting maxDeferredWipesPerFlush
    while (this.#wipeQueue.length > 0 || this.#wipeScheduled) {
      this.#flushWipeQueue();
      // Yield to allow timers/microtasks to schedule additional work

      await Promise.resolve();
    }
  }

  /**
   * Synchronously flushes all pending deferred wipes.
   *
   * This method processes the entire wipe queue immediately, which may block
   * briefly for large queues. Use with caution in performance-critical paths.
   */
  public flushWipesSync(): void {
    // Drain fully regardless of batch limit
    // Guard against runaway loops by also checking processed growth

    let safety = 1_000_000;
    while (
      (this.#wipeQueue.length > 0 || this.#wipeScheduled) &&
      safety-- > 0
    ) {
      this.#flushWipeQueue();
    }
  }

  /**
   * Returns statistics about the deferred wipe queue.
   *
   * This provides visibility into the current state of pending wipes without
   * exposing the actual buffer contents.
   *
   * @returns Object containing queue length, total bytes, and scheduling status
   */
  public getWipeQueueStats(): {
    readonly entries: number;
    readonly totalBytes: number;
    readonly scheduled: boolean;
  } {
    return {
      entries: this.#wipeQueue.length,
      totalBytes: this.#wipeQueueBytes,
      scheduled: this.#wipeScheduled,
    };
  }

  #runTtlPurgeBatch(): void {
    if (!this.#ttlAutopurge) return;
    const batchLimit = 64;
    let purged = 0;
    let current = this.#head;
    let nextSoonest = Number.POSITIVE_INFINITY;
    const nowTick = this.#tickNow();
    while (current !== NO_INDEX && purged < batchLimit) {
      const next = this.#next[current] ?? NO_INDEX;
      const ttl = this.#ttls[current] ?? 0;
      const start = this.#starts[current] ?? 0;
      if (ttl > 0) {
        const exp = start + ttl;
        if (nowTick - start > ttl) {
          this.#deleteInternal(this.#keyList[current] as K, "ttl");
          purged++;
        } else if (exp < nextSoonest) {
          nextSoonest = exp;
        }
      }
      current = next;
    }
    this.#nextExpiry = nextSoonest;
    if (Number.isFinite(this.#nextExpiry)) this.#scheduleExpiryTimer();
  }
  // Enqueue a user callback to run asynchronously post-mutation
  #enqueueCallback(callback: () => void): void {
    this.#deferredCallbacks.push(callback);
    if (this.#deferredCallbacks.length === 1) {
      scheduleMicrotask(() => {
        const toRun = this.#deferredCallbacks.splice(0);
        for (const function_ of toRun) {
          try {
            function_();
          } catch (error) {
            try {
              this.#logger.error("Deferred callback error:", error);
            } catch {
              /* noop */
            }
          }
        }
      });
    }
  }
  /* eslint-enable functional/immutable-data, functional/no-let, functional/prefer-readonly-type */
}

/**
 * A singleton byte cache providing secure, high-performance caching for binary data.
 *
 * This class provides a global cache instance with sensible defaults optimized for
 * security and performance. It uses the SecureLRUCache internally with pre-configured
 * settings suitable for most web security applications.
 *
 * Key features:
 * - Singleton pattern ensuring consistent global state
 * - Pre-configured security settings (SharedArrayBuffer rejection, secure wiping)
 * - Optimized defaults for web security use cases
 * - Simple API for common caching operations
 * - Comprehensive statistics and monitoring
 *
 * @example
 * ```typescript
 * // Store binary data
 * const data = new Uint8Array([1, 2, 3, 4, 5]);
 * VerifiedByteCache.set('https://api.example.com/data', data);
 *
 * // Retrieve data
 * const cached = VerifiedByteCache.get('https://api.example.com/data');
 *
 * // Async storage for large data
 * await VerifiedByteCache.setAsync('https://api.example.com/large-file', largeData);
 *
 * // Check cache statistics
 * const stats = VerifiedByteCache.getStats();
 * console.log(`Cache size: ${stats.size} entries`);
 * ```
 */
export class VerifiedByteCache {
  /**
   * Private singleton instance with optimized configuration for security applications.
   */
  private static readonly singletonInstance = new SecureLRUCache<
    string,
    Uint8Array
  >({
    maxEntries: 10,
    maxBytes: 1_048_576,
    maxEntryBytes: 512_000,
    maxUrlLength: 2048,
    includeUrlsInStats: false,
    evictCallbackExposeUrl: false,
    recencyMode: "sieve", // Optimal for worker script caching based on performance analysis
    ...(resolveSecureLRUOptions() as unknown as Partial<CacheOptions>),
    // Always promote on get to satisfy strict LRU semantics for the shared cache,
    // and to ensure deterministic behavior in tests regardless of profile defaults.
    promoteOnGet: "always",
  });

  /**
   * Stores binary data in the cache with the specified URL as the key.
   *
   * This method performs synchronous eviction if necessary. For large data that may
   * require extensive eviction, consider using `setAsync` instead.
   *
   * @param url - The URL key to store the data under
   * @param bytes - The binary data to cache
   * @throws {InvalidParameterError} If validation fails (invalid URL, wrong data type, etc.)
   *
   * @example
   * ```typescript
   * const response = await fetch('https://api.example.com/data');
   * const data = new Uint8Array(await response.arrayBuffer());
   * VerifiedByteCache.set('https://api.example.com/data', data);
   * ```
   */
  public static set(url: string, bytes: Uint8Array): void {
    this.singletonInstance.set(url, bytes);
  }

  /**
   * Asynchronously stores binary data in the cache with cooperative eviction.
   *
   * This method is preferred for large data or when extensive eviction may be needed,
   * as it yields control to prevent blocking the event loop.
   *
   * @param url - The URL key to store the data under
   * @param bytes - The binary data to cache
   * @returns Promise that resolves when the operation is complete
   * @throws {InvalidParameterError} If validation fails
   *
   * @example
   * ```typescript
   * const largeFile = await fetch('https://example.com/large-file.zip');
   * const data = new Uint8Array(await largeFile.arrayBuffer());
   * await VerifiedByteCache.setAsync('https://example.com/large-file.zip', data);
   * ```
   */
  public static async setAsync(url: string, bytes: Uint8Array): Promise<void> {
    await this.singletonInstance.setAsync(url, bytes);
  }

  /**
   * Retrieves binary data from the cache by URL key.
   *
   * @param url - The URL key to retrieve data for
   * @returns The cached binary data, or undefined if not found
   *
   * @example
   * ```typescript
   * const data = VerifiedByteCache.get('https://api.example.com/data');
   * if (data) {
   *   // Use the cached data
   *   processData(data);
   * }
   * ```
   */
  public static get(url: string): Uint8Array | undefined {
    return this.singletonInstance.get(url);
  }

  /**
   * Checks if a key exists in the cache without promoting its recency.
   *
   * @param url - The URL key to check
   * @returns true if the key exists and is valid, false otherwise
   */
  public static has(url: string): boolean {
    return this.singletonInstance.has(url);
  }

  /**
   * Retrieves a value from the cache without promoting its recency.
   *
   * @param url - The URL key to retrieve
   * @returns The cached value or undefined if not found
   */
  public static peek(url: string): Uint8Array | undefined {
    return this.singletonInstance.peek(url);
  }

  /**
   * Removes specific data from the cache by URL key.
   *
   * @param url - The URL key of the data to remove
   *
   * @example
   * ```typescript
   * VerifiedByteCache.delete('https://api.example.com/outdated-data');
   * ```
   */
  public static delete(url: string): void {
    this.singletonInstance.delete(url);
  }

  /**
   * Removes all data from the cache.
   *
   * @example
   * ```typescript
   * VerifiedByteCache.clear(); // Cache is now empty
   * ```
   */
  public static clear(): void {
    this.singletonInstance.clear();
  }

  /**
   * Returns comprehensive statistics about the cache's performance and state.
   *
   * @returns Cache statistics including hit rate, size, and operation counts
   *
   * @example
   * ```typescript
   * const stats = VerifiedByteCache.getStats();
   * const hitRate = stats.hits / (stats.hits + stats.misses);
   * console.log(`Cache hit rate: ${(hitRate * 100).toFixed(1)}%`);
   * console.log(`Total entries: ${stats.size}`);
   * ```
   */
  public static getStats(): CacheStats {
    return this.singletonInstance.getStats();
  }

  /**
   * Immediately removes all expired entries from the cache.
   *
   * @returns The number of expired entries removed
   */
  public static purgeExpired(): number {
    return this.singletonInstance.purgeExpired();
  }

  /**
   * Asynchronously flushes all pending deferred wipes.
   *
   * @returns Promise that resolves when all wipes are complete
   */
  public static async flushWipes(): Promise<void> {
    await this.singletonInstance.flushWipes();
  }

  /**
   * Synchronously flushes all pending deferred wipes.
   */
  public static flushWipesSync(): void {
    this.singletonInstance.flushWipesSync();
  }

  /**
   * Returns statistics about the deferred wipe queue.
   *
   * @returns Object with queue entries, total bytes, and scheduling status
   */
  public static getWipeQueueStats(): {
    readonly entries: number;
    readonly totalBytes: number;
    readonly scheduled: boolean;
  } {
    return this.singletonInstance.getWipeQueueStats();
  }
}
