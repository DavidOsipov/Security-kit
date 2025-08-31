// SPDX-License-Identifier: MIT
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
