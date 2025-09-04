// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Manages the internal state and lifecycle of the crypto provider.
 * @module
 */

import {
  CryptoUnavailableError,
  InvalidConfigurationError,
  InvalidParameterError,
} from "./errors";
import { environment, isDevelopment } from "./environment";
import { reportProdError as reportProductionError } from "./reporting";
import {
  developmentLog_ as secureDevelopmentLog,
  setDevelopmentLogger_,
} from "./dev-logger";

// --- State Machine ---
export const CryptoState = Object.freeze({
  Unconfigured: "unconfigured",
  Configuring: "configuring",
  Configured: "configured",
  Sealed: "sealed",
} as const);
export type CryptoState = (typeof CryptoState)[keyof typeof CryptoState];

function isCryptoLike(v: unknown): v is Crypto {
  return (
    !!v &&
    typeof v === "object" &&
    typeof (v as { readonly getRandomValues?: unknown }).getRandomValues ===
      "function"
  );
}

/**
 * Securely detects Node.js crypto implementation with strict validation.
 * Protected against cache poisoning via generation-based invalidation.
 * ASVS L3 compliant: validates all crypto interfaces before trusting.
 */
async function detectNodeCrypto(
  generation: number,
): Promise<Crypto | undefined> {
  try {
    // Dynamic import prevents bundler issues and allows lazy loading
    const nodeModule = await import("node:crypto");

    // Validate generation hasn't changed during async operation (cache poisoning protection)
    if (generation !== _cryptoInitGeneration) {
      return undefined; // Generation changed, abort
    }

    // ASVS L3: Strict validation of Node webcrypto interface
    if (nodeModule?.webcrypto && isCryptoLike(nodeModule.webcrypto)) {
      const webcrypto = nodeModule.webcrypto as Crypto;
      // Additional validation for SubtleCrypto if present
      const subtle = (webcrypto as { readonly subtle?: unknown }).subtle;
      if (subtle && typeof subtle === "object") {
        // Verify critical SubtleCrypto methods exist
        const subtleObject = subtle as Record<string, unknown>;
        if (typeof subtleObject["digest"] === "function") {
          return webcrypto;
        }
      }
      // Return webcrypto even if subtle is incomplete - some use cases only need getRandomValues
      return webcrypto;
    }

    // Fallback: Check if Node crypto.randomBytes can be adapted
    if (typeof nodeModule?.randomBytes === "function") {
      const randomBytesFunction = nodeModule.randomBytes as (
        size: number,
      ) => Buffer;

      // Create a Crypto-compatible interface using Node's randomBytes
      const adaptedCrypto: Crypto = {
        getRandomValues: <T extends ArrayBufferView | null>(array: T): T => {
          if (!array || typeof array !== "object" || !("byteLength" in array)) {
            throw new TypeError("getRandomValues requires an ArrayBufferView");
          }
          const buffer = randomBytesFunction(array.byteLength);
          new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(
            buffer,
          );
          return array;
        },
        // Note: subtle may not be available in this fallback
        subtle: undefined as unknown as SubtleCrypto,
        randomUUID:
          nodeModule.randomUUID?.bind(nodeModule) ??
          (() => {
            throw new Error("randomUUID not available");
          }),
      };

      return adaptedCrypto;
    }

    return undefined;
  } catch (error) {
    // Secure logging: don't expose internal error details
    if (isDevelopment()) {
      // Initialize logger on first use to avoid side effects on import
      import("./utils")
        .then(({ secureDevLog }) => {
          setDevelopmentLogger_(secureDevLog);
        })
        .catch(() => {
          // Ignore logger initialization failures
        });

      secureDevelopmentLog(
        "debug",
        "security-kit",
        "Node crypto detection failed",
        { error: error instanceof Error ? error.message : String(error) },
      );
    }
    return undefined;
  }
}

/* Deliberate mutable module-level state for lifecycle management. These
  variables must be mutable so the module can manage crypto provider
  initialization, caching and sealing. Narrowly disable the rule here. */
/* eslint-disable functional/no-let -- deliberate mutable lifecycle state */
let _cachedCrypto: Crypto | undefined = undefined;
let _cryptoPromise: Promise<Crypto> | undefined = undefined;
let _cryptoState: CryptoState = CryptoState.Unconfigured;
let _cryptoInitGeneration = 0;
/* eslint-enable functional/no-let */

// --- Internal State Accessors ---
export function getCryptoState(): CryptoState {
  return _cryptoState;
}

// --- Internal Configuration API ---
/** @internal - Do not export from package entry; used by config.ts only */
export function _setCrypto(
  cryptoLike: Crypto | undefined,
  { allowInProduction = false }: { readonly allowInProduction?: boolean } = {},
): void {
  if (_cryptoState === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  if (typeof allowInProduction !== "boolean") {
    throw new InvalidParameterError("allowInProduction must be a boolean.");
  }
  if (environment.isProduction && cryptoLike && !allowInProduction) {
    throw new InvalidConfigurationError(
      "setCrypto() was called in production without allowInProduction=true",
    );
  }
  // If caller explicitly allows using a custom crypto in production, require an
  // explicit opt-in via an environment variable or a global override to avoid
  // accidental weakening of entropy in production deployments.
  if (environment.isProduction && cryptoLike && allowInProduction) {
    const environmentAllow =
      typeof process !== "undefined" &&
      process?.env?.["SECURITY_KIT_ALLOW_SET_CRYPTO_IN_PROD"] === "true";
    const globalAllow = !!(globalThis as unknown as Record<string, unknown>)[
      "__SECURITY_KIT_ALLOW_SET_CRYPTO_IN_PROD"
    ];
    if (!environmentAllow && !globalAllow) {
      throw new InvalidConfigurationError(
        "setCrypto(..., { allowInProduction: true }) in production requires explicit opt-in.\n" +
          "Set environment variable SECURITY_KIT_ALLOW_SET_CRYPTO_IN_PROD=true or set globalThis.__SECURITY_KIT_ALLOW_SET_CRYPTO_IN_PROD = true to acknowledge the risk.",
      );
    }

    // Report a high-severity warning so operators are aware that crypto was
    // overridden in production. This helps with post-deployment audits.
    try {
      reportProductionError(
        new Error("Custom crypto provider set in production (operator opt-in)"),
        {
          component: "security-kit",
          action: "setCrypto",
          note: "Operator explicitly allowed replacing crypto in production",
        },
      );
    } catch {
      /* best-effort reporting */
    }
  }

  _cryptoInitGeneration++;
  _cryptoPromise = undefined;

  if (cryptoLike == undefined) {
    _cachedCrypto = undefined;
    _cryptoState = CryptoState.Unconfigured;
    return;
  }
  if (!isCryptoLike(cryptoLike)) {
    throw new InvalidParameterError(
      "setCrypto: provided object must implement crypto.getRandomValues(Uint8Array).",
    );
  }

  _cachedCrypto = cryptoLike;
  _cryptoState = CryptoState.Configured;
}

/** @internal - Do not export from package entry; used by config.ts only */
export function _sealSecurityKit(): void {
  if (_cryptoState === CryptoState.Sealed) return;
  if (_cryptoState === CryptoState.Configuring) {
    throw new InvalidConfigurationError(
      "Cannot seal the security kit while initialization is in progress.",
    );
  }
  if (!_cachedCrypto && !_cryptoPromise) {
    throw new CryptoUnavailableError(
      "sealSecurityKit() cannot be called before a crypto implementation is available. Call an async crypto function first.",
    );
  }
  _cryptoState = CryptoState.Sealed;
}

// --- Crypto Provider Access ---
export async function ensureCrypto(): Promise<Crypto> {
  if (_cryptoState === CryptoState.Sealed) {
    if (!_cachedCrypto)
      throw new CryptoUnavailableError(
        "Security kit is sealed, but no crypto provider was configured.",
      );
    return _cachedCrypto!;
  }
  if (_cryptoState === CryptoState.Configured && _cachedCrypto) {
    return _cachedCrypto!;
  }
  if (_cryptoPromise) {
    return _cryptoPromise;
  }

  _cryptoState = CryptoState.Configuring;
  const myGeneration = _cryptoInitGeneration;

  _cryptoPromise = (async (): Promise<Crypto> => {
    try {
      if (myGeneration !== _cryptoInitGeneration) {
        if (_cachedCrypto) {
          _cryptoState = CryptoState.Configured;
          return _cachedCrypto!;
        }
        _cryptoState = CryptoState.Unconfigured;
        throw new CryptoUnavailableError(
          "Crypto initialization was reset during async operation.",
        );
      }
      if (_cachedCrypto) {
        _cryptoState = CryptoState.Configured;
        return _cachedCrypto!;
      }
      // First, try globalThis.crypto (browser or Node 20+)
      const globalCrypto = (globalThis as { readonly crypto?: Crypto }).crypto;
      if (isCryptoLike(globalCrypto)) {
        if (myGeneration === _cryptoInitGeneration) {
          _cachedCrypto = globalCrypto;
          _cryptoState = CryptoState.Configured;
        }
        return _cachedCrypto!;
      }

      // ASVS L3 Enhancement: Auto-detect Node.js crypto with security validation
      const nodeCrypto = await detectNodeCrypto(myGeneration);
      if (nodeCrypto && myGeneration === _cryptoInitGeneration) {
        _cachedCrypto = nodeCrypto;
        _cryptoState = CryptoState.Configured;

        // Log successful Node crypto detection in development
        if (isDevelopment()) {
          // Initialize logger on first use to avoid side effects on import
          import("./utils")
            .then(({ secureDevLog }) => {
              setDevelopmentLogger_(secureDevLog);
            })
            .catch(() => {
              // Ignore logger initialization failures
            });

          secureDevelopmentLog(
            "info",
            "security-kit",
            "Node.js crypto provider detected and configured",
            {
              hasSubtle: !!(nodeCrypto as { readonly subtle?: unknown }).subtle,
            },
          );
        }

        return _cachedCrypto!;
      }

      // Validation: Ensure generation hasn't changed during Node detection
      if (myGeneration !== _cryptoInitGeneration) {
        throw new CryptoUnavailableError(
          "Crypto initialization was invalidated during Node detection.",
        );
      }

      throw new CryptoUnavailableError(
        "Crypto API is unavailable. In Node.js < 20, install a webcrypto polyfill or call setCrypto().",
      );
    } catch (error) {
      if (myGeneration === _cryptoInitGeneration) {
        _cryptoPromise = undefined;
        _cryptoState = CryptoState.Unconfigured;
      }
      throw error;
    }
  })();

  _cryptoPromise.catch((error: unknown) => {
    const safeContext = {
      component: "security-kit",
      phase: "ensureCrypto",
      message: "initialization failed",
    };
    try {
      const safeError =
        error instanceof Error ? error : new Error(String(error));
      if (environment.isProduction) {
        reportProductionError(safeError, safeContext);
      } else if (isDevelopment()) {
        // Initialize logger on first use to avoid side effects on import
        import("./utils")
          .then(({ secureDevLog }) => {
            setDevelopmentLogger_(secureDevLog);
          })
          .catch(() => {
            // Ignore logger initialization failures
          });

        secureDevelopmentLog(
          "error",
          "security-kit",
          "ensureCrypto initialization failed",
          {
            error:
              safeError instanceof Error
                ? { name: safeError.name, message: safeError.message }
                : String(safeError),
          },
        );
      }
    } catch {
      /* best-effort reporting; ignore errors from reporting */
    }
  });

  return await _cryptoPromise;
}

export function ensureCryptoSync(): Crypto {
  if (_cachedCrypto) return _cachedCrypto;
  if (_cryptoState === CryptoState.Sealed) {
    throw new CryptoUnavailableError(
      "Security kit is sealed, but no crypto provider was configured.",
    );
  }
  if (_cryptoState === CryptoState.Configuring) {
    throw new CryptoUnavailableError(
      "Crypto initialization is in progress. Use the async ensureCrypto() instead.",
    );
  }
  const globalCrypto = (globalThis as { readonly crypto?: Crypto }).crypto;
  if (isCryptoLike(globalCrypto)) {
    _cachedCrypto = globalCrypto;
    _cryptoState = CryptoState.Configured;
    return _cachedCrypto;
  }
  throw new CryptoUnavailableError(
    "Crypto API is unavailable synchronously. Use async ensureCrypto() for Node.js support.",
  );
}

/**
 * Securely generates cryptographically random bytes using the enhanced crypto provider.
 * ASVS L3 compliant: Uses validated crypto sources, protected against cache poisoning.
 *
 * @param length Number of random bytes to generate
 * @returns Promise resolving to Uint8Array with cryptographically secure random bytes
 * @throws CryptoUnavailableError if no secure crypto source is available
 */
export async function secureRandomBytes(length: number): Promise<Uint8Array> {
  if (typeof length !== "number" || length < 0 || !Number.isInteger(length)) {
    throw new InvalidParameterError("length must be a non-negative integer");
  }
  if (length > 65536) {
    // 64KB limit for safety
    throw new InvalidParameterError("length must not exceed 65536 bytes");
  }

  const crypto = await ensureCrypto();
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

/**
 * Checks if crypto is available without initializing it.
 * Useful for feature detection before making crypto calls.
 *
 * @returns Promise resolving to true if crypto will be available
 */
export async function isCryptoAvailable(): Promise<boolean> {
  try {
    await ensureCrypto();
    return true;
  } catch {
    // Expected when crypto is unavailable
    return false;
  }
}

// --- Test-only Helpers ---
export const __test_resetCryptoStateForUnitTests: undefined | (() => void) =
  typeof __TEST__ !== "undefined" && __TEST__
    ? (() => {
        // Synchronous test-only reset helper. Avoids async imports to ensure
        // tests can reliably reset module state within beforeEach/afterEach
        // without race conditions. Intentionally limited to test builds.
        return () => {
          _cachedCrypto = undefined;
          _cryptoPromise = undefined;
          _cryptoState = CryptoState.Unconfigured;
          _cryptoInitGeneration = 0;
          // NOTE: Do not clear the environment's explicit override here.
          // Some tests set environment.setExplicitEnv("production") before
          // resetting crypto state to verify production-only behavior. Clearing
          // the environment cache here would silently drop that explicit
          // override (since clearCache resets it), causing tests to run under a
          // different environment than intended. Callers who need to clear the
          // environment cache should do so explicitly in their tests.
        };
      })()
    : undefined;

// Additional test helper: make reset available when running under NODE_ENV=test.
// This is intentionally guarded so it only works in test runs. It helps test
// harnesses that don't set __TEST__ at compile-time to reset global state.
export function __resetCryptoStateForTests(): void {
  if (process.env["NODE_ENV"] !== "test") {
    throw new Error(
      "__resetCryptoStateForTests is test-only and cannot be used outside tests.",
    );
  }
  _cachedCrypto = undefined;
  _cryptoPromise = undefined;
  _cryptoState = CryptoState.Unconfigured;
  _cryptoInitGeneration = 0;
  // Preserve any explicit environment overrides set by tests.
}

/* eslint-disable-next-line unicorn/prevent-abbreviations -- stable public test helper name; descriptive alias exported below */
export function getInternalTestUtils():
  | {
      readonly _getCryptoGenerationForTest: () => number;
      readonly _getCryptoStateForTest: () => string;
    }
  | undefined {
  // This entire block will be removed in production if __TEST__ is false.
  if (typeof __TEST__ !== "undefined" && __TEST__) {
    return {
      _getCryptoGenerationForTest: () => _cryptoInitGeneration,
      _getCryptoStateForTest: () => _cryptoState,
    };
  }
  return undefined;
}

// Provide a descriptive compatibility alias to satisfy callers and reduce
// noisy naming warnings from lint rules (non-breaking).
export const getInternalTestUtilities = getInternalTestUtils;

// Small test helper to inspect cached crypto in unit tests when allowed.
export function __test_getCachedCrypto(): Crypto | null | undefined {
  // For test environment, always return cached crypto
  if (process.env["NODE_ENV"] === "test") {
    return _cachedCrypto;
  }
  // Check compile-time flag
  if (typeof __TEST__ !== "undefined" && __TEST__) {
    return _cachedCrypto;
  }
  // Also check runtime flag for test environments
  const globalTestFlag = (globalThis as { readonly __TEST__?: boolean })
    .__TEST__;
  if (globalTestFlag === true) {
    return _cachedCrypto;
  }
  return undefined;
}

// Test helper to set cached crypto for testing
export function __test_setCachedCrypto(crypto: Crypto | undefined): void {
  if (process.env["NODE_ENV"] === "test") {
    _cachedCrypto = crypto;
    if (crypto) {
      _cryptoState = CryptoState.Configured;
    } else {
      _cryptoState = CryptoState.Unconfigured;
    }
  }
}
