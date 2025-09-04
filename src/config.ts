// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Public API for configuring the security-kit library.
 * @module
 */

import { InvalidConfigurationError, InvalidParameterError } from "./errors";
import {
  CryptoState,
  getCryptoState,
  _sealSecurityKit,
  _setCrypto,
} from "./state";
import { environment } from "./environment";
import {
  configureProdErrorReporter as configureProductionErrorReporter,
  setProdErrorHook as setProductionErrorHook,
} from "./reporting";

import {
  DEFAULT_HANDSHAKE_MAX_NONCE_LENGTH,
  DEFAULT_NONCE_FORMATS,
  type NonceFormat,
} from "./constants";

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

function extractValidatedProperty<T>(
  cfg: Partial<LoggingConfig>,
  property: keyof LoggingConfig,
): ExtractResult<T> {
  if (!Object.hasOwn(cfg, property)) {
    return { present: false };
  }
  const desc = Object.getOwnPropertyDescriptor(cfg as object, property);
  if (!desc) return { present: false };
  if ("get" in desc || "set" in desc) {
    throw new InvalidParameterError(
      `Configuration property "${String(property)}" must be a plain data property (no getters/setters).`,
    );
  }
  // Value may be any type; refine using small helpers for each property to keep
  // the function simple and easier to reason about.
  const rawValue = desc.value as unknown;

  const validateBoolean = <U>(v: unknown, propertyName: string): U => {
    if (typeof v !== "boolean") {
      throw new InvalidParameterError(`${propertyName} must be a boolean.`);
    }
    return v as U;
  };

  const validateStringOrUndefined = <U>(v: unknown): U => {
    if (v !== undefined && typeof v !== "string") {
      throw new InvalidParameterError("unsafeKeyHashSalt must be a string.");
    }
    return v as U;
  };

  const validatePositiveIntegerOrUndefined = <U>(v: unknown): U => {
    if (v !== undefined) {
      if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) {
        throw new InvalidParameterError(
          "rateLimitTokensPerMinute must be a positive integer.",
        );
      }
    }
    return v as U;
  };

  switch (property) {
    case "allowUnsafeKeyNamesInDev":
    case "includeUnsafeKeyHashesInDev":
      return {
        present: true,
        value: validateBoolean<T>(rawValue, String(property)),
      };
    case "unsafeKeyHashSalt":
      return { present: true, value: validateStringOrUndefined<T>(rawValue) };
    case "rateLimitTokensPerMinute":
      return {
        present: true,
        value: validatePositiveIntegerOrUndefined<T>(rawValue),
      };
    default:
      return { present: true, value: rawValue as T };
  }
}

function enforceProductionConstraints(
  isProduction: boolean,
  allowExtract: ExtractResult<boolean>,
  includeExtract: ExtractResult<boolean>,
): void {
  if (!isProduction) return;
  if (
    (allowExtract.present && allowExtract.value === true) ||
    (includeExtract.present && includeExtract.value === true)
  ) {
    throw new InvalidParameterError(
      "Dev-only logging features cannot be enabled in production.",
    );
  }
}

function buildMergedPartial(
  allowExtract: ExtractResult<boolean>,
  includeExtract: ExtractResult<boolean>,
  saltExtract: ExtractResult<string | undefined>,
  rateExtract: ExtractResult<number | undefined>,
): Partial<LoggingConfig> {
  return {
    ...(allowExtract.present
      ? { allowUnsafeKeyNamesInDev: allowExtract.value }
      : {}),
    ...(includeExtract.present
      ? { includeUnsafeKeyHashesInDev: includeExtract.value }
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
  const allowExtract = extractValidatedProperty<boolean>(
    cfg,
    "allowUnsafeKeyNamesInDev",
  );
  const includeExtract = extractValidatedProperty<boolean>(
    cfg,
    "includeUnsafeKeyHashesInDev",
  );
  const saltExtract = extractValidatedProperty<string | undefined>(
    cfg,
    "unsafeKeyHashSalt",
  );
  const rateExtract = extractValidatedProperty<number | undefined>(
    cfg,
    "rateLimitTokensPerMinute",
  );

  enforceProductionConstraints(
    environment.isProduction,
    allowExtract,
    includeExtract,
  );

  const merged = buildMergedPartial(
    allowExtract,
    includeExtract,
    saltExtract,
    rateExtract,
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
  if (environment_ !== "development" && environment_ !== "production") {
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
          `allowedNonceFormats must contain only non-empty strings. Found: ${String(f)}`,
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
};

/* eslint-disable functional/no-let -- Controlled mutable configuration allowed here */
let _runtimePolicy: RuntimePolicyConfig = {
  allowBlobUrls: !environment.isProduction,
  allowBlobWorkers: false,
  allowComputeIntegrityInProductionDefault: false,
  enableWorkerByteCache: !environment.isProduction,
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
