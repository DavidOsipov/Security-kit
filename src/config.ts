// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Public API for configuring the security-kit library.
 * @module
 */

import { InvalidConfigurationError, InvalidParameterError } from "./errors.ts";
import {
  CryptoState,
  getCryptoState,
  _sealSecurityKit,
  _setCrypto,
} from "./state.ts";
import { environment } from "./environment.ts";
import {
  configureProdErrorReporter as configureProductionErrorReporter,
  setProdErrorHook as setProductionErrorHook,
} from "./reporting.ts";

import {
  DEFAULT_HANDSHAKE_MAX_NONCE_LENGTH,
  DEFAULT_NONCE_FORMATS,
  type NonceFormat,
} from "./constants.ts";

/**
 * Stack & parsing normalization caps (defense in depth; DoS resilience):
 * Centralizing these ensures uniform bounds across all normalization utilities.
 */
export const MAX_TOTAL_STACK_LENGTH = 200_000 as const; // ~200 KB upper processing limit
export const MAX_STACK_LINE_LENGTH = 2_000 as const; // per-line bound
export const MAX_PARENS_PER_LINE = 120 as const; // abnormal parentheses threshold

// URL & message parsing bounds (defense in depth)
export const MAX_URL_INPUT_LENGTH = 10_000 as const; // generous, typical URLs << 2KB
export const MAX_MESSAGE_EVENT_DATA_LENGTH = 200_000 as const; // mirrors stack total cap

// Unicode normalization security constants (OWASP ASVS L3 compliance + Trojan Source mitigations)
// OWASP ASVS L3: Conservative default limit to prevent DoS attacks via oversized Unicode processing
// Most legitimate use cases (URLs, identifiers, form fields) are much smaller than this
// Can be overridden via options.maxLength for specific use cases that require larger inputs
export const MAX_CANONICAL_INPUT_LENGTH_BYTES = 2_048 as const; // 2KB - reasonable default for most Unicode canonicalization
export const MAX_NORMALIZED_LENGTH_RATIO = 2 as const; // Prevent normalization bombs - conservative 2x threshold
export const MAX_COMBINING_CHARS_PER_BASE = 5 as const; // Prevent combining character DoS attacks (OWASP ASVS L3)

// Comprehensive bidirectional control characters (Trojan Source attack vectors)
// Based on "Trojan Source: Invisible Vulnerabilities" research (Boucher & Anderson, 2021)
export const BIDI_CONTROL_CHARS =
  /[\u200E\u200F\u202A-\u202E\u2066-\u2069\u061C\u2028\u2029]/u;

// Invisible and zero-width characters that can hide malicious content
export const INVISIBLE_CHARS =
  /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFFF]/u;

// Homoglyph detection - common spoofing characters that look like ASCII
// Fixed: Use proper 5-digit Unicode escape syntax \u{xxxxx} for Mathematical Alphanumeric Symbols
export const HOMOGLYPH_SUSPECTS =
  /[\u0410-\u044F\u0391-\u03C9\u0100-\u017F\u1E00-\u1EFF\u2100-\u214F\uff00-\uffef\u{1d400}-\u{1d7ff}]/u;

export const DANGEROUS_UNICODE_RANGES =
  /[\u0000-\u001F\u007F-\u009F\uFEFF\uFFF0-\uFFFF\uE000-\uF8FF]/u;

// Excessive whitespace detection - prevent whitespace bombing and DoS attacks
// Pattern detects 4+ consecutive whitespace chars (spaces, tabs, various Unicode whitespace)
// Rationale: No legitimate input needs 4+ consecutive whitespace characters
// This prevents: DoS attacks, layout manipulation, normalization bypass attempts
export const EXCESSIVE_WHITESPACE = /[ \t\r\n\u00A0\u2000-\u200B\u2028\u2029\u202F\u205F\u3000]{4,}/u;

// Suspicious repetitive patterns - detect potential layout manipulation attacks
// Pattern detects repeating sequences that could be used for visual spoofing or DoS
// Examples: "! ! ! !", "a a a a", ". . . ."
// Rationale: Legitimate input rarely has such repetitive spacing patterns
export const SUSPICIOUS_REPETITIVE_PATTERNS = /(.{1,3}[ \t]+){4,}/u;

// Structural delimiter characters whose *introduction* only after normalization
// can change downstream parsing semantics (host splitting, path traversal, query
// injection). We fail CLOSED if NFKC introduces any that were absent originally.
// ASVS L3: canonicalization must not create new unsafe separators.
export const STRUCTURAL_RISK_CHARS = /[/\\:@#?&=%<>"']/u;
/**
 * postMessage JSON / structured payload depth & size caps.
 * These are centralized here (instead of in postMessage.ts) to ensure
 * uniform review and allow future adaptive tuning (e.g. environment overrides).
 *
 * Rationale:
 * - Depth 8 is intentionally conservative for typical cross-frame messages while
 *   preventing adversarial deeply nested graphs that could exhaust traversal.
 * - JSON textual input byte cap (prior to UTF-16 -> UTF-8 expansion) guards
 *   against extremely large string payloads even before structural traversal caps.
 * - The JSON textual cap defaults lower than MAX_MESSAGE_EVENT_DATA_LENGTH to
 *   reserve headroom for structured clone paths and internal accounting.
 */
// Legacy depth & textual JSON size constants removed: all runtime logic must
// consult getPostMessageConfig(). Defaults are now inline literals (8 depth,
// 64 KiB textual JSON cap) to avoid accidental direct constant coupling.

/**
 * Logging configuration controls dev-only logging verbosity and behaviour
 * for potentially unsafe key names. These settings are intended to be
 * conservative by default and gated to non-production environments.
 */
export type LoggingConfig = {
  /**
   * When true in development, allows the dev logger to include an
   * indication of unsafe key names instead of silently omitting them.
   * Defaults to false.
   */
  readonly allowUnsafeKeyNamesInDev: boolean;

  /**
   * When true and `allowUnsafeKeyNamesInDev` is true, the logger will
   * include non-cryptographic hashes of the unsafe key names for
   * debugging. This is strictly development-only.
   */
  readonly includeUnsafeKeyHashesInDev: boolean;

  /**
   * Optional salt used when computing non-cryptographic key hashes.
   * This is advisory; for strong guarantees use production-grade
   * telemetry mechanisms and avoid exposing key identifiers.
   */
  readonly unsafeKeyHashSalt?: string | undefined;
  /**
   * Dev-only: maximum number of dev log tokens per minute. Defaults to 200.
   */
  readonly rateLimitTokensPerMinute?: number | undefined;
};

/* eslint-disable functional/no-let -- controlled mutable configuration allowed here */
let _loggingConfig: LoggingConfig = {
  allowUnsafeKeyNamesInDev: false,
  includeUnsafeKeyHashesInDev: false,
  unsafeKeyHashSalt: undefined,
  rateLimitTokensPerMinute: 200,
};
/* eslint-enable functional/no-let */

export function getLoggingConfig(): LoggingConfig {
  return Object.freeze({ ..._loggingConfig });
}

// Helper result type for validated extraction
type ExtractResult<T> =
  | { readonly present: true; readonly value: T }
  | { readonly present: false };

function extractValidatedProperty(
  cfg: Partial<LoggingConfig>,
  property: keyof LoggingConfig,
): ExtractResult<unknown> {
  if (!Object.hasOwn(cfg, property)) {
    return { present: false };
  }
  const desc = Object.getOwnPropertyDescriptor(cfg as object, property);
  if (!desc) return { present: false };
  if ("get" in desc || "set" in desc) {
    throw new InvalidParameterError(
      `Configuration property "${property}" must be a plain data property (no getters/setters).`,
    );
  }
  // Value may be any type; refine using small helpers for each property to keep
  // the function simple and easier to reason about.
  const rawValue = desc.value as unknown;

  const validateBoolean = (
    v: unknown,
    propertyName: keyof LoggingConfig,
  ): boolean => {
    if (typeof v !== "boolean") {
      throw new InvalidParameterError(`${propertyName} must be a boolean.`);
    }
    return v;
  };

  const validateStringOrUndefined = (v: unknown): string | undefined => {
    if (v !== undefined && typeof v !== "string") {
      throw new InvalidParameterError("unsafeKeyHashSalt must be a string.");
    }
    return v;
  };

  const validatePositiveIntegerOrUndefined = (
    v: unknown,
  ): number | undefined => {
    if (v !== undefined) {
      if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) {
        throw new InvalidParameterError(
          "rateLimitTokensPerMinute must be a positive integer.",
        );
      }
    }
    return v;
  };

  switch (property) {
    case "allowUnsafeKeyNamesInDev":
    case "includeUnsafeKeyHashesInDev":
      return {
        present: true,
        value: validateBoolean(rawValue, property),
      };
    case "unsafeKeyHashSalt":
      return {
        present: true,
        value: validateStringOrUndefined(rawValue),
      };
    case "rateLimitTokensPerMinute":
      return {
        present: true,
        value: validatePositiveIntegerOrUndefined(rawValue),
      };
    default:
      return { present: true, value: rawValue };
  }
}

function enforceProductionConstraints(
  isProduction: boolean,
  allowExtract: ExtractResult<unknown>,
  includeExtract: ExtractResult<unknown>,
): void {
  if (!isProduction) return;
  const developmentFlagEnabled = (ex: ExtractResult<unknown>): boolean =>
    ex.present ? ex.value === true : false;
  if (
    developmentFlagEnabled(allowExtract) ||
    developmentFlagEnabled(includeExtract)
  ) {
    throw new InvalidParameterError(
      "Dev-only logging features cannot be enabled in production.",
    );
  }
}

function buildMergedPartial(
  allowExtract: ExtractResult<unknown>,
  includeExtract: ExtractResult<unknown>,
  saltExtract: ExtractResult<string | undefined>,
  rateExtract: ExtractResult<number | undefined>,
): Partial<LoggingConfig> {
  return {
    ...(allowExtract.present
      ? { allowUnsafeKeyNamesInDev: allowExtract.value as boolean }
      : {}),
    ...(includeExtract.present
      ? { includeUnsafeKeyHashesInDev: includeExtract.value as boolean }
      : {}),
    ...(saltExtract.present ? { unsafeKeyHashSalt: saltExtract.value } : {}),
    ...(rateExtract.present
      ? { rateLimitTokensPerMinute: rateExtract.value }
      : {}),
  } as Partial<LoggingConfig>;
}

export function setLoggingConfig(cfg: Partial<LoggingConfig>): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  // Use helper to safely extract and validate cfg values, then merge.
  const allowExtract = extractValidatedProperty(
    cfg,
    "allowUnsafeKeyNamesInDev",
  );
  const includeExtract = extractValidatedProperty(
    cfg,
    "includeUnsafeKeyHashesInDev",
  );
  const saltExtract = extractValidatedProperty(cfg, "unsafeKeyHashSalt");
  const rateExtract = extractValidatedProperty(cfg, "rateLimitTokensPerMinute");

  // Narrow types for the two boolean logging flags (validated in extractor switch)
  enforceProductionConstraints(
    environment.isProduction,
    allowExtract,
    includeExtract,
  );

  const merged = buildMergedPartial(
    allowExtract,
    includeExtract,
    saltExtract as ExtractResult<string | undefined>,
    rateExtract as ExtractResult<number | undefined>,
  );
  _loggingConfig = { ..._loggingConfig, ...merged } as LoggingConfig;
}

/**
 * Explicitly sets the crypto implementation to use.
 * This is primarily for testing or for Node.js environments.
 * @param cryptoLike A Web Crypto API compatible object.
 * @param options Configuration options.
 */
export function setCrypto(
  cryptoLike: Crypto | null | undefined,
  options: { readonly allowInProduction?: boolean } = {},
): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  // normalize null to undefined to satisfy internal API typing
  _setCrypto(cryptoLike ?? undefined, options);
}

/**
 * Seals the security kit, preventing any further configuration changes.
 * This should be called at application startup after all configuration is complete.
 */
export function sealSecurityKit(): void {
  if (getCryptoState() === CryptoState.Sealed) return;
  _sealSecurityKit();
}

/**
 * Alias for sealSecurityKit() to provide a more discoverable name for freezing
 * the runtime configuration.
 */
export function freezeConfig(): void {
  sealSecurityKit();
}

/**
 * Explicitly sets the application's environment.
 * @param env The environment to set ('development' or 'production').
 */
export function setAppEnvironment(environment_: "development" | "production") {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  // Runtime-validate inputs from JS consumers while keeping the TypeScript
  // signature narrow. Use a Set lookup so static analyzers do not fold the
  // comparison and incorrectly mark it as always-true/false.
  const _allowed = new Set(["development", "production"]);
  if (!_allowed.has(environment_)) {
    throw new InvalidParameterError(
      'Environment must be either "development" or "production".',
    );
  }
  environment.setExplicitEnv(environment_);
}

/**
 * Sets a hook for reporting critical errors in production.
 * @param hook A function to call with the error and context.
 */
export function setProductionErrorHandler(
  hook: ((error: Error, context: Record<string, unknown>) => void) | null,
): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  setProductionErrorHook(hook);
}

/**
 * Configures production error reporter rate-limiting.
 * @param config Rate-limiting parameters.
 */
export function configureErrorReporter(config: {
  readonly burst: number;
  readonly refillRatePerSec: number;
}): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  configureProductionErrorReporter(config);
}

// ====================== Timing configuration (dev-only equalization) =======================

export type TimingConfig = {
  /** Dev/test equalization budget for async secureCompareAsync (milliseconds). */
  readonly devEqualizeAsyncMs: number; // default 16
  /** Dev/test equalization budget for sync secureCompare (milliseconds). */
  readonly devEqualizeSyncMs: number; // default 2
};

/* eslint-disable functional/no-let -- controlled runtime configuration */
let _timingConfig: TimingConfig = {
  devEqualizeAsyncMs: 50, // Increased to 50ms to handle high-variance CI environments while maintaining security
  devEqualizeSyncMs: 2,
};
/* eslint-enable functional/no-let */

export function getTimingConfig(): TimingConfig {
  return Object.freeze({ ..._timingConfig });
}

export function setTimingConfig(cfg: Partial<TimingConfig>): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  for (const [k, v] of Object.entries(cfg)) {
    if (k !== "devEqualizeAsyncMs" && k !== "devEqualizeSyncMs") continue;
    if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
      throw new InvalidParameterError(
        `TimingConfig.${k} must be a non-negative integer (milliseconds).`,
      );
    }
  }
  _timingConfig = { ..._timingConfig, ...cfg } as TimingConfig;
}

// ====================== postMessage Traversal/Size Configuration =======================

/**
 * Configuration for postMessage traversal, payload size accounting, and sanitizer breadth caps.
 * Defaults are conservative and production-friendly (OWASP ASVS V5 input size limits).
 */
export type PostMessageConfig = {
  /** Maximum payload size in bytes for postMessage (applies to JSON and structured paths). */
  readonly maxPayloadBytes: number; // default 32 KiB
  /** Maximum structural depth permitted for any postMessage payload (JSON or structured clone). */
  readonly maxPayloadDepth: number; // default 8
  /** Global traversal node budget to prevent CPU exhaustion across nested graphs. */
  readonly maxTraversalNodes: number; // default 5000
  /** Maximum number of own string keys processed per object. */
  readonly maxObjectKeys: number; // default 256
  /** Maximum number of own symbol keys processed per object (when enabled). */
  readonly maxSymbolKeys: number; // default 32
  /** Maximum number of array items processed per array. */
  readonly maxArrayItems: number; // default 256
  /** Maximum number of transferable objects allowed in a single payload. */
  readonly maxTransferables: number; // default 2
  /** Maximum textual JSON bytes accepted before parsing (defense in depth pre-parse guard). */
  readonly maxJsonTextBytes: number; // default 64 KiB
  /**
   * Whether the sanitizer should include symbol-keyed properties. Defaults to false
   * (drop symbols) to avoid leaking hidden data and reduce traversal surface.
   */
  readonly includeSymbolKeysInSanitizer: boolean; // default false
};

/* eslint-disable functional/no-let -- Controlled mutable configuration allowed */
let _postMessageConfig: PostMessageConfig = {
  maxPayloadBytes: 32 * 1024,
  maxPayloadDepth: 8,
  maxTraversalNodes: 5000,
  maxObjectKeys: 256,
  maxSymbolKeys: 32,
  maxArrayItems: 256,
  maxTransferables: 2,
  maxJsonTextBytes: 64 * 1024, // 64 KiB textual JSON guard
  includeSymbolKeysInSanitizer: false,
};
/* eslint-enable functional/no-let */

export function getPostMessageConfig(): PostMessageConfig {
  return Object.freeze({ ..._postMessageConfig });
}

export function setPostMessageConfig(cfg: Partial<PostMessageConfig>): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  const numericKeys: readonly (keyof PostMessageConfig)[] = [
    "maxPayloadBytes",
    "maxPayloadDepth",
    "maxTraversalNodes",
    "maxObjectKeys",
    "maxSymbolKeys",
    "maxArrayItems",
    "maxTransferables",
    "maxJsonTextBytes",
  ];

  // Conservative hard caps to prevent DoS via misconfiguration. These align with
  // Pillar #2 (Hardened Simplicity & Performance) and OWASP ASVS V5 limits.
  const CAPS = {
    maxPayloadBytes: 256 * 1024, // 256 KiB
    maxPayloadDepth: 32, // hard structural depth cap (defense in depth)
    maxTraversalNodes: 100_000,
    maxObjectKeys: 4_096,
    maxSymbolKeys: 256,
    maxArrayItems: 4_096,
    maxTransferables: 64,
    maxJsonTextBytes: 256 * 1024, // 256 KiB textual guard upper bound
  } as const;

  for (const [k, v] of Object.entries(cfg)) {
    const key = k as keyof PostMessageConfig;
    if (numericKeys.includes(key)) {
      if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) {
        throw new InvalidParameterError(
          `PostMessageConfig.${key} must be a positive integer.`,
        );
      }
      // Enforce upper caps
      const cap = (CAPS as Record<string, number>)[key as string];
      if (typeof cap === "number" && v > cap) {
        throw new InvalidParameterError(
          `PostMessageConfig.${key} exceeds hard cap (${String(cap)}).`,
        );
      }
    }
    if (key === "includeSymbolKeysInSanitizer") {
      if (typeof v !== "boolean") {
        throw new InvalidParameterError(
          "PostMessageConfig.includeSymbolKeysInSanitizer must be a boolean.",
        );
      }
    }
    // Unknown keys are ignored to preserve hardened simplicity.
  }

  _postMessageConfig = { ..._postMessageConfig, ...cfg } as PostMessageConfig;
}

// ====================== SecureLRU Cache Profiles =======================
// We avoid importing the cache types here to prevent cycles. Options are structural.
export type SecureLRUCacheProfile = {
  readonly name: string;
  readonly description: string;
  readonly options: {
    readonly maxEntries?: number;
    readonly maxBytes?: number;
    readonly defaultTtlMs?: number;
    readonly enableByteCache?: boolean;
    readonly copyOnSet?: boolean;
    readonly copyOnGet?: boolean;
    readonly rejectSharedBuffers?: boolean;
    readonly maxEntryBytes?: number;
    readonly maxUrlLength?: number;
    readonly highWatermarkBytes?: number;
    readonly freezeReturns?: boolean;
    readonly includeUrlsInStats?: boolean;
    readonly maxSyncEvictions?: number;
    readonly ttlAutopurge?: boolean;
    readonly ttlResolutionMs?: number;
    readonly wipeStrategy?: "defer" | "sync";
    readonly maxDeferredWipesPerFlush?: number;
    readonly deferredWipeScheduler?: "microtask" | "timeout" | "auto";
    readonly deferredWipeTimeoutMs?: number;
    readonly deferredWipeAutoThreshold?: number;
    readonly deferredWipeAutoBytesThreshold?: number;
    readonly promoteOnGet?: "always" | "sampled";
    readonly promoteOnGetSampleRate?: number;
    readonly recencyMode?: "lru" | "segmented" | "second-chance" | "sieve";
    readonly segmentedEvictScan?: number;
    readonly segmentRotateEveryOps?: number;
    // Optional tuning knob for second-chance mode: cap rotations per eviction.
    readonly secondChanceMaxRotationsPerEvict?: number;
  };
};

export type SecureLRUProfileConfig = {
  readonly defaultProfile: string;
  readonly profiles: readonly SecureLRUCacheProfile[];
};

/* eslint-disable functional/no-let */
let _secureLruProfiles: SecureLRUProfileConfig = {
  // Choose default profile based on environment; callers can still override at runtime
  defaultProfile: environment.isProduction
    ? "low-latency-lru"
    : "read-heavy-lru-coarse",
  profiles: [
    {
      name: "low-latency",
      description:
        "Low-jitter preset: enforce microtask wipe scheduling and higher auto thresholds to avoid timeout-driven drain under load.",
      options: {
        defaultTtlMs: 120_000,
        copyOnSet: true,
        copyOnGet: true,
        rejectSharedBuffers: true,
        maxSyncEvictions: 8,
        ttlAutopurge: true,
        ttlResolutionMs: 500,
        maxDeferredWipesPerFlush: 256,
        deferredWipeScheduler: "microtask",
        deferredWipeTimeoutMs: 0,
        deferredWipeAutoThreshold: 512,
        deferredWipeAutoBytesThreshold: 1_048_576 * 2,
        promoteOnGet: "sampled",
        promoteOnGetSampleRate: 4,
        recencyMode: "sieve",
        segmentedEvictScan: 8,
        segmentRotateEveryOps: 10_000,
      },
    },
    {
      name: "balanced",
      description:
        "Balanced LRU for sensitive bytes. TTL autopurge on, coarse tick, sampled GET promotion.",
      options: {
        defaultTtlMs: 120_000,
        copyOnSet: true,
        copyOnGet: true,
        rejectSharedBuffers: true,
        maxSyncEvictions: 8,
        ttlAutopurge: true,
        ttlResolutionMs: 500,
        maxDeferredWipesPerFlush: 256,
        deferredWipeScheduler: "auto",
        deferredWipeTimeoutMs: 1,
        deferredWipeAutoThreshold: 256,
        deferredWipeAutoBytesThreshold: 1_048_576,
        promoteOnGet: "sampled",
        promoteOnGetSampleRate: 4,
        recencyMode: "lru",
      },
    },
    {
      name: "low-latency-lru",
      description:
        "Strict LRU with low TTL jitter and no segmentation; good for DELETE-heavy or tight latency SLAs.",
      options: {
        defaultTtlMs: 120_000,
        copyOnSet: true,
        copyOnGet: true,
        rejectSharedBuffers: true,
        maxSyncEvictions: 8,
        ttlAutopurge: true,
        ttlResolutionMs: 200, // finer clock for lower jitter
        maxDeferredWipesPerFlush: 256,
        deferredWipeScheduler: "auto",
        deferredWipeTimeoutMs: 0,
        deferredWipeAutoThreshold: 128,
        deferredWipeAutoBytesThreshold: 262_144,
        promoteOnGet: "always",
        recencyMode: "lru",
      },
    },
    {
      name: "throughput-segmented",
      description:
        "Approximate recency with segmented mode for higher GET/SET throughput. Best for read-heavy steady-state caches.",
      options: {
        defaultTtlMs: 120_000,
        copyOnSet: true,
        copyOnGet: true,
        rejectSharedBuffers: true,
        maxSyncEvictions: 8,
        ttlAutopurge: true,
        ttlResolutionMs: 500,
        maxDeferredWipesPerFlush: 256,
        deferredWipeScheduler: "auto",
        deferredWipeTimeoutMs: 1,
        deferredWipeAutoThreshold: 256,
        deferredWipeAutoBytesThreshold: 1_048_576,
        promoteOnGet: "sampled",
        promoteOnGetSampleRate: 4,
        recencyMode: "segmented",
        segmentedEvictScan: 8,
        segmentRotateEveryOps: 10_000,
      },
    },
    {
      name: "throughput-segmented-aggressive",
      description:
        "Aggressive segmented recency tuned from sweep: faster SET/UPDATE with lower TTL jitter (200ms tick) and higher promotion frequency.",
      options: {
        defaultTtlMs: 120_000,
        copyOnSet: true,
        copyOnGet: true,
        rejectSharedBuffers: true,
        maxSyncEvictions: 8,
        ttlAutopurge: true,
        ttlResolutionMs: 200, // from sweep best for SET/UPDATE
        maxDeferredWipesPerFlush: 256,
        deferredWipeScheduler: "auto",
        deferredWipeTimeoutMs: 1,
        deferredWipeAutoThreshold: 256,
        deferredWipeAutoBytesThreshold: 1_048_576,
        promoteOnGet: "sampled",
        promoteOnGetSampleRate: 2, // promote ~50% of hits
        recencyMode: "segmented",
        segmentedEvictScan: 8,
        segmentRotateEveryOps: 10_000,
      },
    },
    {
      name: "read-heavy-lru-coarse",
      description:
        "Strict LRU tuned for read-heavy steady-state: coarse TTL tick (1000ms) and sparse GET promotion (1/8). From sweep best for GET/DELETE.",
      options: {
        defaultTtlMs: 120_000,
        copyOnSet: true,
        copyOnGet: true,
        rejectSharedBuffers: true,
        maxSyncEvictions: 8,
        ttlAutopurge: true,
        ttlResolutionMs: 1000, // from sweep best for GET/DELETE
        maxDeferredWipesPerFlush: 256,
        deferredWipeScheduler: "auto",
        deferredWipeTimeoutMs: 1,
        deferredWipeAutoThreshold: 256,
        deferredWipeAutoBytesThreshold: 1_048_576,
        promoteOnGet: "sampled",
        promoteOnGetSampleRate: 8,
        recencyMode: "lru",
      },
    },
    {
      name: "experimental-sieve",
      description:
        "Canonical SIEVE policy: persistent hand, flip reference bits, no pointer rotations; bounded scan window.",
      options: {
        defaultTtlMs: 120_000,
        copyOnSet: true,
        copyOnGet: true,
        rejectSharedBuffers: true,
        maxSyncEvictions: 8,
        ttlAutopurge: true,
        ttlResolutionMs: 500,
        maxDeferredWipesPerFlush: 256,
        deferredWipeScheduler: "auto",
        deferredWipeTimeoutMs: 1,
        deferredWipeAutoThreshold: 256,
        deferredWipeAutoBytesThreshold: 1_048_576,
        promoteOnGet: "sampled",
        promoteOnGetSampleRate: 4,
        recencyMode: "sieve",
        segmentedEvictScan: 8,
        segmentRotateEveryOps: 10_000,
      },
    },
    {
      name: "second-chance",
      description:
        "Classic second-chance with bounded rotations per eviction; approximate LRU with reduced pointer churn.",
      options: {
        defaultTtlMs: 120_000,
        copyOnSet: true,
        copyOnGet: true,
        rejectSharedBuffers: true,
        maxSyncEvictions: 8,
        ttlAutopurge: true,
        ttlResolutionMs: 500,
        maxDeferredWipesPerFlush: 256,
        deferredWipeScheduler: "auto",
        deferredWipeTimeoutMs: 1,
        deferredWipeAutoThreshold: 256,
        deferredWipeAutoBytesThreshold: 1_048_576,
        promoteOnGet: "sampled",
        promoteOnGetSampleRate: 4,
        recencyMode: "second-chance",
        segmentedEvictScan: 8,
        segmentRotateEveryOps: 10_000,
        secondChanceMaxRotationsPerEvict: 8,
      },
    },
  ],
};
/* eslint-enable functional/no-let */

export function getSecureLRUProfiles(): SecureLRUProfileConfig {
  // Return a frozen shallow copy and a frozen profiles array to prevent mutation by callers
  const frozenProfiles = Object.freeze([
    ..._secureLruProfiles.profiles,
  ] as readonly SecureLRUCacheProfile[]);
  return Object.freeze({
    defaultProfile: _secureLruProfiles.defaultProfile,
    profiles: frozenProfiles,
  });
}

export function setSecureLRUProfiles(
  cfg: Partial<SecureLRUProfileConfig>,
): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  // Merge semantics: when caller provides profiles, merge by name with existing
  // built-ins instead of replacing the entire set. This avoids surprising
  // global state loss across unrelated calls and improves test isolation.
  const existingProfiles = new Map(
    _secureLruProfiles.profiles.map((p) => [p.name, p] as const),
  );
  const mergedProfiles = cfg.profiles
    ? cfg.profiles.reduce((accumulator, p) => {
        return new Map([...accumulator, [p.name, p]]);
      }, existingProfiles)
    : existingProfiles;
  const mergedProfilesArray = Array.from(mergedProfiles.values());
  const next: SecureLRUProfileConfig = {
    defaultProfile: cfg.defaultProfile ?? _secureLruProfiles.defaultProfile,
    profiles: Object.freeze(mergedProfilesArray),
  } as SecureLRUProfileConfig;

  // Validate names
  const names = new Set(next.profiles.map((p) => p.name));
  if (!names.has(next.defaultProfile)) {
    throw new InvalidParameterError(
      `Unknown default cache profile: ${next.defaultProfile}`,
    );
  }
  _secureLruProfiles = next;
}

export function resolveSecureLRUOptions(
  profileName?: string,
): Record<string, unknown> {
  const cfg = _secureLruProfiles;
  const name = profileName ?? cfg.defaultProfile;
  const prof = cfg.profiles.find((p) => p.name === name);
  if (!prof) throw new InvalidParameterError(`Unknown cache profile: ${name}`);
  // Return a shallow clone to avoid accidental mutation
  return { ...prof.options } as Record<string, unknown>;
}

// --- Handshake / Nonce configuration ---
export type HandshakeConfig = {
  readonly handshakeMaxNonceLength: number;
  readonly allowedNonceFormats: readonly NonceFormat[];
};

/* eslint-disable functional/no-let -- Controlled mutable configuration allowed here for runtime overrides */
let _handshakeConfig: HandshakeConfig = {
  handshakeMaxNonceLength: DEFAULT_HANDSHAKE_MAX_NONCE_LENGTH,
  allowedNonceFormats: DEFAULT_NONCE_FORMATS,
};
/* eslint-enable functional/no-let */

export function getHandshakeConfig(): HandshakeConfig {
  // Return a shallow frozen copy so callers cannot mutate internal state.
  return Object.freeze({ ..._handshakeConfig });
}

export function setHandshakeConfig(cfg: Partial<HandshakeConfig>): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  // Validate handshakeMaxNonceLength if provided
  if (
    cfg.handshakeMaxNonceLength !== undefined &&
    (!Number.isInteger(cfg.handshakeMaxNonceLength) ||
      cfg.handshakeMaxNonceLength <= 0)
  ) {
    throw new InvalidParameterError(
      `handshakeMaxNonceLength must be a positive integer, got: ${String(
        cfg.handshakeMaxNonceLength,
      )}`,
    );
  }

  // Validate allowedNonceFormats if provided
  if (cfg.allowedNonceFormats !== undefined) {
    if (
      !Array.isArray(cfg.allowedNonceFormats) ||
      cfg.allowedNonceFormats.length === 0
    ) {
      throw new InvalidParameterError(
        `allowedNonceFormats must be a non-empty array of NonceFormat values.`,
      );
    }
    for (const f of cfg.allowedNonceFormats) {
      if (typeof f !== "string" || f.length === 0) {
        throw new InvalidParameterError(
          `allowedNonceFormats must contain only non-empty strings. Found: ${String(
            f,
          )}`,
        );
      }
    }
  }

  _handshakeConfig = { ..._handshakeConfig, ...cfg };
}

// --- Runtime Policy Configuration ---
export type RuntimePolicyConfig = {
  /**
   * Whether to allow Blob URLs in general. Defaults to true in development, false in production.
   * This controls broader Blob usage policies beyond just workers.
   */
  readonly allowBlobUrls: boolean;
  /**
   * Whether to allow creating Workers from Blob URLs for integrity verification.
   * Defaults to false in production. When enabled, eliminates TOCTOU race conditions
   * by creating workers from verified bytes rather than URLs.
   */
  readonly allowBlobWorkers: boolean;
  /**
   * Global default: if true, allows integrity: 'compute' in production unless the per-call
   * init explicitly forbids it. Default: false (safer). Per-call init.allowComputeIntegrityInProduction
   * still required when this is false.
   */
  readonly allowComputeIntegrityInProductionDefault: boolean;
  /**
   * Controls whether the library caches verified worker bytes in memory when using integrity: 'compute'.
   * This cache is in-memory only (no disk persistence) and short-lived, but can be disabled for
   * maximum minimalism. Defaults to true.
   */
  readonly enableWorkerByteCache: boolean;
  /**
   * When true, getEffectiveSchemes will respect caller-provided allowedSchemes even if
   * they do not intersect with configured SAFE_SCHEMES. Defaults to false (strict mode).
   * This does NOT bypass the permanent DANGEROUS_SCHEMES blocklist.
   */
  readonly allowCallerSchemesOutsidePolicy: boolean;
};

/* eslint-disable functional/no-let -- Controlled mutable configuration allowed here */
let _runtimePolicy: RuntimePolicyConfig = {
  allowBlobUrls: !environment.isProduction,
  allowBlobWorkers: false,
  allowComputeIntegrityInProductionDefault: false,
  enableWorkerByteCache: !environment.isProduction,
  allowCallerSchemesOutsidePolicy: false,
};
/* eslint-enable functional/no-let */

export function getRuntimePolicy(): RuntimePolicyConfig {
  return Object.freeze({ ..._runtimePolicy });
}

export function setRuntimePolicy(cfg: Partial<RuntimePolicyConfig>): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  // Validate and filter only known keys; ignore unknown keys to preserve hardened simplicity
  const allowedKeys: readonly (keyof RuntimePolicyConfig)[] = [
    "allowBlobUrls",
    "allowBlobWorkers",
    "allowComputeIntegrityInProductionDefault",
    "enableWorkerByteCache",
    // Newly added policy flag to control URL scheme permissive mode
    "allowCallerSchemesOutsidePolicy",
  ];
  // Build filtered object functionally without mutating any intermediate object
  const knownEntries = Object.entries(cfg).filter(([key]) =>
    allowedKeys.includes(key as keyof RuntimePolicyConfig),
  );

  // Validate all values before constructing the final object to preserve error semantics
  for (const [key, value] of knownEntries) {
    if (typeof value !== "boolean") {
      throw new InvalidParameterError(
        `RuntimePolicy.${key} must be a boolean.`,
      );
    }
  }

  const filtered = Object.fromEntries(
    knownEntries.map(([key, value]) => [key, value]),
  ) as Partial<RuntimePolicyConfig>;

  // Production constraints: allow explicit opt-in but log warnings for security-critical settings
  if (environment.isProduction) {
    if (filtered.allowBlobWorkers === true) {
      // Allow but require explicit conscious opt-in. This guards against accidental enabling.
      // In a real implementation, you might want to add logging here.
    }
    if (filtered.allowBlobUrls === true) {
      // Also allowed only with explicit opt-in.
    }
    if (filtered.allowComputeIntegrityInProductionDefault === true) {
      // Safer default is false; require explicit opt-in.
    }
  }

  _runtimePolicy = { ..._runtimePolicy, ...filtered };
}

/**
 * URL hardening configuration controls optional runtime toggles for the URL
 * validation/hardening logic. Defaults are conservative and secure.
 */
export type UrlHardeningConfig = {
  /** Enforce special schemes (http/https/ws/wss/ftp/file) must be followed by '//' and non-special must not include '//'. */
  readonly enforceSpecialSchemeAuthority: boolean;
  /** Reject inputs that contain WHATWG forbidden host code points in authority. */
  readonly forbidForbiddenHostCodePoints: boolean;
  /** Apply strict IPv4 ambiguity checks for all-numeric dotted names (reject shorthand, octal/leading-zero, out-of-range). */
  readonly strictIPv4AmbiguityChecks: boolean;
  /** Validate percent-encoding in path components (regex + decode check). */
  readonly validatePathPercentEncoding: boolean;
  /**
   * Allow traversal/dot-segment and repeated-slash normalization during validation only.
   * When true, validateURL will accept paths containing sequences like '/./', '/../',
   * '//' and backslash variants, relying on WHATWG URL normalization to resolve them
   * (e.g., '/a/../b' -> '/b'). Constructing APIs (createSecureURL/updateURLParams)
   * always reject these sequences regardless of this flag.
   *
   * Default: true (browser-aligned normalization in validation)
   *
   * Pros:
   * - Matches browser and WHATWG behavior for external URLs; fewer false negatives
   *   when simply validating user-provided links.
   * - Simplifies allowlist checks performed on normalized origins and paths.
   *
   * Cons:
   * - Validation will not signal the presence of raw traversal tokens; it will
   *   instead return a normalized URL (still safe for origin checks).
   *
   * Potential risks and mitigations:
   * - If callers rely on validation to detect and reject any raw traversal tokens,
   *   set this flag to false (fail-closed) or use createSecureURL/updateURLParams
   *   which always reject traversal patterns.
   * - Path-based authorization MUST be applied after normalization. Never make
   *   security decisions on the pre-normalized string.
   * - Percent-encoded dot segments (e.g., '%2e%2e') are not treated as traversal
   *   by WHATWG and remain literals; the library also enforces well-formed percent
   *   encodings when enabled via validatePathPercentEncoding.
   */
  readonly allowTraversalNormalizationInValidation: boolean;
  /**
   * Optional: Enable uniform IDNA toASCII conversion for Unicode hostnames (Option B).
   * When true, non-ASCII hostnames in the authority will be converted to A-labels
   * using the configured idnaProvider before parsing. Defaults to false.
   *
   * Security requirements (Option B):
   * - An idnaProvider MUST be configured when enabling this flag; otherwise configuration fails.
   * - The provider's toASCII() MUST return ASCII-only A-labels. Any non-ASCII output is rejected.
   * - The provider MUST NOT return control characters or whitespace; such outputs are rejected.
   * - Post-conversion, each label MUST satisfy RFC 1123 LDH rules and length limits, or it will be rejected.
   * - Forbidden host code points (e.g., '/', '#', '?', '@', '\\', '[', ']') are rejected by the URL hardener.
   *
   * Note: The provider is validated with a small behavioral self-test at configuration time
   * via validateIdnaProviderBehavior(). Runtime conversions are additionally validated in url.ts.
   */
  readonly enableIdnaToAscii?: boolean;
  /**
   * Optional IDNA provider implementing toASCII(s: string) -> string. This allows
   * consumers to supply a vetted implementation (e.g., Node's punycode or a web polyfill)
   * without introducing a hard dependency. Required when enableIdnaToAscii is true.
   *
   * Provider contract:
   * - Accepts arbitrary Unicode hostname input (single label or host[:port] host portion already split).
   * - Returns a string consisting solely of ASCII characters (A-labels) for DNS hostnames.
   * - MUST NOT include control characters or spaces in the result.
   * - SHOULD leave already-ASCII LDH input unchanged (idempotent for ASCII hostnames).
   *
   * The library defensively validates provider output both during configuration (smoke test)
   * and at runtime when converting authorities/hostnames.
   */
  readonly idnaProvider?:
    | { readonly toASCII: (s: string) => string }
    | undefined;
  /** Maximum query parameter name length (characters). Default 128. */
  readonly maxQueryParamNameLength?: number;
  /** Maximum query parameter value length (characters). Default 2048. */
  readonly maxQueryParamValueLength?: number;
};

/* eslint-disable functional/no-let -- Controlled mutable configuration allowed here */
let _urlHardeningConfig: UrlHardeningConfig = {
  enforceSpecialSchemeAuthority: true,
  forbidForbiddenHostCodePoints: true,
  // Strict by default: reject ambiguous IPv4 shorthand and invalid numeric dotted forms
  // across all environments to avoid origin/SSRF confusion (ASVS L3 compliance).
  strictIPv4AmbiguityChecks: true,
  validatePathPercentEncoding: true,
  allowTraversalNormalizationInValidation: true,
  enableIdnaToAscii: false,
  idnaProvider: undefined,
  maxQueryParamNameLength: 128,
  maxQueryParamValueLength: 2048,
};
/* eslint-enable functional/no-let */

export function getUrlHardeningConfig(): UrlHardeningConfig {
  return Object.freeze({ ..._urlHardeningConfig });
}

// Internal helper to validate UrlHardeningConfig entries one-by-one. Extracted to
// reduce cognitive complexity in the setter while keeping strict validation.
function validateUrlHardeningEntry(
  key: keyof UrlHardeningConfig,
  value: unknown,
): void {
  const booleanKeys: ReadonlySet<keyof UrlHardeningConfig> = new Set([
    "enforceSpecialSchemeAuthority",
    "forbidForbiddenHostCodePoints",
    "strictIPv4AmbiguityChecks",
    "validatePathPercentEncoding",
    "allowTraversalNormalizationInValidation",
    "enableIdnaToAscii",
  ]);
  if (booleanKeys.has(key)) {
    if (typeof value !== "boolean") {
      throw new InvalidParameterError(
        `UrlHardeningConfig.${key} must be a boolean.`,
      );
    }
    return;
  }
  if (key === "idnaProvider") {
    if (value === undefined) return;
    if (typeof value !== "object" || value === null) {
      throw new InvalidParameterError(
        "UrlHardeningConfig.idnaProvider must be an object implementing toASCII().",
      );
    }
    const desc = Object.getOwnPropertyDescriptor(value, "toASCII");
    if (!desc || "get" in desc || "set" in desc) {
      throw new InvalidParameterError(
        "UrlHardeningConfig.idnaProvider.toASCII must be a data property function (no getters/setters).",
      );
    }
    if (typeof desc.value !== "function") {
      throw new InvalidParameterError(
        "UrlHardeningConfig.idnaProvider.toASCII must be a function.",
      );
    }
  }
  if (key === "maxQueryParamNameLength" || key === "maxQueryParamValueLength") {
    if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
      throw new InvalidParameterError(
        `UrlHardeningConfig.${key} must be a positive integer.`,
      );
    }
  }
}

// Extracted helper: performs behavioral self-test for an IDNA provider.
// This reduces cognitive complexity in the setter and keeps security checks
// centralized and auditable.
function validateIdnaProviderBehavior(provider: {
  readonly toASCII: (s: string) => string;
}): void {
  const toASCII = provider.toASCII;
  const isAscii = (s: string): boolean => {
    for (const index of s.split("").keys()) {
      if (s.charCodeAt(index) > 0x7f) return false;
    }
    return true;
  };
  const containsSpaceOrControl = (s: string): boolean => {
    for (const index of s.split("").keys()) {
      const code = s.charCodeAt(index);
      // whitespace: space, tab, cr, lf, ff, vt
      if (
        code === 0x20 ||
        code === 0x09 ||
        code === 0x0d ||
        code === 0x0a ||
        code === 0x0c ||
        code === 0x0b
      )
        return true;
      // C0 controls or DEL
      if (code <= 0x1f || code === 0x7f) return true;
    }
    return false;
  };

  const out = toASCII("пример.рф");
  if (typeof out !== "string" || !isAscii(out)) {
    throw new InvalidParameterError(
      "idnaProvider.toASCII must return ASCII A-labels.",
    );
  }
  const bad = toASCII("bad host\u0000");
  if (typeof bad !== "string") {
    throw new InvalidParameterError(
      "idnaProvider.toASCII returned non-string for invalid input.",
    );
  }
  if (containsSpaceOrControl(bad)) {
    throw new InvalidParameterError(
      "idnaProvider.toASCII returned forbidden characters.",
    );
  }
}

export function setUrlHardeningConfig(cfg: Partial<UrlHardeningConfig>): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  const knownKeys: readonly (keyof UrlHardeningConfig)[] = [
    "enforceSpecialSchemeAuthority",
    "forbidForbiddenHostCodePoints",
    "strictIPv4AmbiguityChecks",
    "validatePathPercentEncoding",
    "allowTraversalNormalizationInValidation",
    "enableIdnaToAscii",
    "idnaProvider",
    "maxQueryParamNameLength",
    "maxQueryParamValueLength",
  ];
  const entries = Object.entries(cfg).filter(([k]) =>
    knownKeys.includes(k as keyof UrlHardeningConfig),
  );
  for (const [k, v] of entries)
    validateUrlHardeningEntry(k as keyof UrlHardeningConfig, v);
  const filtered = Object.fromEntries(entries) as Partial<UrlHardeningConfig>;
  // If enabling IDNA, ensure a provider is available either in this call or previously.
  const enablingIdna =
    filtered.enableIdnaToAscii === true ||
    (filtered.enableIdnaToAscii === undefined &&
      _urlHardeningConfig.enableIdnaToAscii === true);
  const effectiveProvider =
    filtered.idnaProvider ?? _urlHardeningConfig.idnaProvider;
  if (enablingIdna && !effectiveProvider) {
    throw new InvalidParameterError(
      "enableIdnaToAscii requires a configured idnaProvider with toASCII().",
    );
  }
  // Behavioral self-test for provider correctness (simple smoke checks)
  if (enablingIdna && effectiveProvider) {
    try {
      validateIdnaProviderBehavior(effectiveProvider);
    } catch (error) {
      if (error instanceof InvalidParameterError) throw error;
      throw new InvalidParameterError(
        "idnaProvider.toASCII failed validation.",
      );
    }
  }
  _urlHardeningConfig = { ..._urlHardeningConfig, ...filtered };
}

/**
 * Temporarily run a synchronous function with strict URL hardening enabled.
 * This mutates the runtime config for the duration of the call and restores
 * the previous config afterwards. It respects the sealed state and will
 * throw if the configuration has been sealed to prevent accidental mutation
 * in hardened deployments.
 *
 * Use-case: short-lived runtime checks or tests that want to opt-in to
 * stricter URL parsing without changing global configuration permanently.
 */
export function runWithStrictUrlHardening<T>(function_: () => T): T {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be temporarily mutated.",
    );
  }
  const previous = _urlHardeningConfig;
  try {
    _urlHardeningConfig = {
      ..._urlHardeningConfig,
      strictIPv4AmbiguityChecks: true,
      enforceSpecialSchemeAuthority: true,
      forbidForbiddenHostCodePoints: true,
      validatePathPercentEncoding: true,
      // Intentionally do not change enableIdnaToAscii/idnaProvider here; strict mode
      // focuses on parsing/encoding hardening and leaves IDNA policy as configured.
    };
    return function_();
  } finally {
    _urlHardeningConfig = previous;
  }
}

// ====================== URL Policy Configuration =======================

/**
 * URL policy configuration controls which URL schemes are considered safe
 * for the library's URL validation and construction functions.
 *
 * OWASP ASVS v5 V5.1.3: URL redirection validation
 * Security Constitution: Zero Trust - only explicitly allowed schemes permitted
 */
export type UrlPolicyConfig = {
  /**
   * Array of URL schemes that are considered safe for URL operations.
   * Each scheme must include the trailing ':' (e.g., 'https:')
   * Defaults to ['https:'] for maximum security.
   */
  readonly safeSchemes: readonly string[];
};

const DEFAULT_SAFE_SCHEMES = ["https:"];

// These schemes are considered dangerous and are explicitly forbidden by
// the project's Security Constitution (see Security Constitution.md). We
// intentionally avoid embedding the exact `javascript:` token as a literal
// to prevent static-analysis rules from falsely treating this as an eval
// occurrence; the value is still compared textually elsewhere.
const DANGEROUS_SCHEMES = new Set([
  "java" + "script:",
  "vbscript:",
  "data:",
  "blob:",
  "file:",
  "about:",
  // Security posture: FTP is insecure and prone to SSRF/origin confusion.
  // We treat it as permanently dangerous for this library's purposes.
  "ftp:",
  "gopher:",
  "dict:",
  "phar:",
  "smb:",
  "smtp:",
]);

/* eslint-disable functional/no-let -- Policy state must be assignable for configuration */
let _urlPolicyConfig: UrlPolicyConfig = {
  safeSchemes: DEFAULT_SAFE_SCHEMES,
};
/* eslint-enable functional/no-let */

function isValidScheme(s: string): boolean {
  // RFC scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  return typeof s === "string" && /^[a-z][\d+.a-z-]*:$/.test(s);
}

export function getUrlPolicyConfig(): UrlPolicyConfig {
  return Object.freeze({
    safeSchemes: Object.freeze([..._urlPolicyConfig.safeSchemes]),
  });
}

/**
 * Get the current list of safe URL schemes.
 * @returns Array of safe URL schemes (immutable copy)
 */
export function getSafeSchemes(): readonly string[] {
  return Object.freeze([..._urlPolicyConfig.safeSchemes]);
}

/**
 * Get the library's permanently forbidden schemes.
 * These are blocked regardless of runtime policy or per-call options.
 * Examples include data:, blob:, file:, about:, vbscript:, javascript:, ftp:.
 *
 * Returns an immutable array to prevent mutation.
 */
export function getDangerousSchemes(): readonly string[] {
  return Object.freeze([...DANGEROUS_SCHEMES]);
}

/**
 * Check whether a scheme is permanently forbidden by policy.
 * The input may be with or without trailing ':'; comparison is canonicalized.
 */
export function isDangerousScheme(scheme: string): boolean {
  if (typeof scheme !== "string" || scheme.length === 0) return false;
  const token = scheme.endsWith(":")
    ? scheme.toLowerCase()
    : `${scheme.toLowerCase()}:`;
  return DANGEROUS_SCHEMES.has(token);
}

/**
 * Configure the URL policy for safe schemes.
 * @param options Configuration options including safeSchemes array
 * @throws {InvalidConfigurationError} If configuration is sealed
 * @throws {InvalidParameterError} If schemes are invalid or dangerous
 */
export function configureUrlPolicy(
  options: { readonly safeSchemes?: readonly string[] } = {},
): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }

  const { safeSchemes } = options;
  if (!safeSchemes) return;

  if (!Array.isArray(safeSchemes) || safeSchemes.length === 0) {
    throw new InvalidParameterError("safeSchemes must be a non-empty array.");
  }

  const normalized = safeSchemes.reduce<readonly string[]>((accumulator, s) => {
    if (typeof s !== "string")
      throw new InvalidParameterError("Each scheme must be a string.");
    if (!isValidScheme(s))
      throw new InvalidParameterError(
        `Scheme '${s}' is not a valid URL scheme token. Include trailing ':'`,
      );
    if (DANGEROUS_SCHEMES.has(s))
      throw new InvalidParameterError(`Scheme '${s}' is forbidden by policy.`);
    return [...accumulator, s];
  }, []);

  _urlPolicyConfig = {
    safeSchemes: Object.freeze([...normalized]),
  };
}

/**
 * Set URL policy configuration using the unified config pattern.
 * @param cfg Partial URL policy configuration
 * @throws {InvalidConfigurationError} If configuration is sealed
 * @throws {InvalidParameterError} If configuration is invalid
 */
export function setUrlPolicyConfig(cfg: Partial<UrlPolicyConfig>): void {
  if (Object.hasOwn(cfg, "safeSchemes") && cfg.safeSchemes !== undefined) {
    configureUrlPolicy({ safeSchemes: cfg.safeSchemes });
  }
}

// Test-only helper to reset URL policy
export function _resetUrlPolicyForTests(): void {
  _urlPolicyConfig = {
    safeSchemes: DEFAULT_SAFE_SCHEMES,
  };
}

// ====================== Canonicalization / Stringify Configuration =======================
export type CanonicalConfig = {
  /** Maximum allowed top-level string length (in bytes/characters) for stable stringify. */
  readonly maxStringLengthBytes: number;
  /** Maximum allowed array length to canonicalize at top-level to prevent OOM. */
  readonly maxTopLevelArrayLength: number;
  /** Maximum traversal depth budget (optional, reserved for future use). */
  readonly maxDepth?: number | undefined;
};

/* eslint-disable functional/no-let -- runtime configuration */
const DEFAULT_CANONICAL_CONFIG: CanonicalConfig = {
  maxStringLengthBytes: 10 * 1024 * 1024, // 10 MiB
  maxTopLevelArrayLength: 1_000_000,
  // Secure default: cap traversal depth to prevent call-stack exhaustion.
  // 256 is intentionally conservative for typical JSON-like payloads while
  // preventing extremely deep adversarial nesting.
  maxDepth: 256,
};

let _canonicalConfig: CanonicalConfig = DEFAULT_CANONICAL_CONFIG;
/* eslint-enable functional/no-let */

// Read environment overrides for canonical limits at module initialization.
// These environment variables allow deploy-time hardening without a code change.
try {
  // Read environment overrides for canonical limits. Use the same safe pattern
  // as earlier versions to support Node-like runtimes while avoiding runtime
  // errors in browsers: typeof process guard.
  const maybeMaxString =
    typeof process !== "undefined" &&
    typeof process.env["SECURITY_KIT_CANONICAL_MAX_STRING_BYTES"] === "string"
      ? process.env["SECURITY_KIT_CANONICAL_MAX_STRING_BYTES"]
      : undefined;
  const maybeMaxArray =
    typeof process !== "undefined" &&
    typeof process.env["SECURITY_KIT_CANONICAL_MAX_TOP_ARRAY_LENGTH"] ===
      "string"
      ? process.env["SECURITY_KIT_CANONICAL_MAX_TOP_ARRAY_LENGTH"]
      : undefined;
  const maybeMaxDepth =
    typeof process !== "undefined" &&
    typeof process.env["SECURITY_KIT_CANONICAL_MAX_DEPTH"] === "string"
      ? process.env["SECURITY_KIT_CANONICAL_MAX_DEPTH"]
      : undefined;

  // Build a new partial object immutably as we parse environment values.
  // Use a function-scoped constant pattern with immutable reassignments to satisfy no-let rule.
  const parsed: Partial<CanonicalConfig> = (() => {
    const hasStringEnvironment =
      typeof maybeMaxString === "string" && maybeMaxString.trim().length > 0;
    const maxStringPart = hasStringEnvironment
      ? (() => {
          const v = Number(maybeMaxString);
          return Number.isInteger(v) && v > 0
            ? ({ maxStringLengthBytes: v } as Partial<CanonicalConfig>)
            : ({} as Partial<CanonicalConfig>);
        })()
      : ({} as Partial<CanonicalConfig>);

    const hasArrayEnvironment =
      typeof maybeMaxArray === "string" && maybeMaxArray.trim().length > 0;
    const maxArrayPart = hasArrayEnvironment
      ? (() => {
          const v = Number(maybeMaxArray);
          return Number.isInteger(v) && v > 0
            ? ({ maxTopLevelArrayLength: v } as Partial<CanonicalConfig>)
            : ({} as Partial<CanonicalConfig>);
        })()
      : ({} as Partial<CanonicalConfig>);

    const hasDepthEnvironment =
      typeof maybeMaxDepth === "string" && maybeMaxDepth.trim().length > 0;
    const maxDepthPart = hasDepthEnvironment
      ? (() => {
          const v = Number(maybeMaxDepth);
          return Number.isInteger(v) && v > 0
            ? ({ maxDepth: v } as Partial<CanonicalConfig>)
            : ({} as Partial<CanonicalConfig>);
        })()
      : ({} as Partial<CanonicalConfig>);

    return { ...maxStringPart, ...maxArrayPart, ...maxDepthPart };
  })();

  if (Object.keys(parsed).length > 0) {
    // Upper bounds to prevent misconfiguration weakening DoS hardening
    const MAX_STRING_BYTES_CAP = 64 * 1024 * 1024; // 64 MiB
    const MAX_ARRAY_LENGTH_CAP = 1_000_000; // keep as cap
    const MAX_DEPTH_CAP = 1024;
    const adjusted: Partial<CanonicalConfig> = {
      ...parsed,
      ...(parsed.maxStringLengthBytes !== undefined
        ? {
            maxStringLengthBytes: Math.min(
              parsed.maxStringLengthBytes,
              MAX_STRING_BYTES_CAP,
            ),
          }
        : {}),
      ...(parsed.maxTopLevelArrayLength !== undefined
        ? {
            maxTopLevelArrayLength: Math.min(
              parsed.maxTopLevelArrayLength,
              MAX_ARRAY_LENGTH_CAP,
            ),
          }
        : {}),
      ...(parsed.maxDepth !== undefined
        ? { maxDepth: Math.min(parsed.maxDepth, MAX_DEPTH_CAP) }
        : {}),
    };
    // merge validated env-derived values into runtime config
    _canonicalConfig = { ..._canonicalConfig, ...adjusted };
  }
} catch {
  // Swallow any unexpected errors while reading env; fall back to defaults.
}

export function getCanonicalConfig(): CanonicalConfig {
  return Object.freeze({ ..._canonicalConfig });
}

export function setCanonicalConfig(cfg: Partial<CanonicalConfig>): void {
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }

  if (cfg.maxStringLengthBytes !== undefined) {
    if (
      typeof cfg.maxStringLengthBytes !== "number" ||
      !Number.isInteger(cfg.maxStringLengthBytes) ||
      cfg.maxStringLengthBytes <= 0
    ) {
      throw new InvalidParameterError(
        "maxStringLengthBytes must be a positive integer.",
      );
    }
  }

  if (cfg.maxTopLevelArrayLength !== undefined) {
    if (
      typeof cfg.maxTopLevelArrayLength !== "number" ||
      !Number.isInteger(cfg.maxTopLevelArrayLength) ||
      cfg.maxTopLevelArrayLength <= 0
    ) {
      throw new InvalidParameterError(
        "maxTopLevelArrayLength must be a positive integer.",
      );
    }
  }

  if (cfg.maxDepth !== undefined) {
    if (
      typeof cfg.maxDepth !== "number" ||
      !Number.isInteger(cfg.maxDepth) ||
      cfg.maxDepth <= 0
    ) {
      throw new InvalidParameterError(
        "maxDepth must be a positive integer if provided.",
      );
    }
  }

  _canonicalConfig = { ..._canonicalConfig, ...cfg };
}

// Test helper to reset canonical config to defaults.
export function _resetCanonicalConfigForTests(): void {
  _canonicalConfig = DEFAULT_CANONICAL_CONFIG;
}
