// SPDX-License-Identifier: MIT
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
import { secureDevLog as secureDevelopmentLog } from "./utils";

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

let _cachedCrypto: Crypto | undefined = undefined;
let _cryptoPromise: Promise<Crypto> | undefined = undefined;
let _cryptoState: CryptoState = CryptoState.Unconfigured;
let _cryptoInitGeneration = 0;

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
      const globalCrypto = (globalThis as { readonly crypto?: Crypto }).crypto;
      if (isCryptoLike(globalCrypto)) {
        if (myGeneration === _cryptoInitGeneration) {
          _cachedCrypto = globalCrypto;
          _cryptoState = CryptoState.Configured;
        }
        return _cachedCrypto!;
      }
      throw new CryptoUnavailableError(
        "Web Crypto API is unavailable. In Node.js, inject an implementation via setCrypto().",
      );
    } catch (error) {
      if (myGeneration === _cryptoInitGeneration) {
        _cryptoPromise = undefined;
        _cryptoState = CryptoState.Unconfigured;
      }
      throw error;
    }
  })();

  _cryptoPromise.catch((error) => {
    const safeContext = {
      component: "security-kit",
      phase: "ensureCrypto",
      message: "initialization failed",
    };
    try {
      if (environment.isProduction) {
        reportProductionError(
          error instanceof Error ? error : new Error(String(error)),
          safeContext,
        );
      } else if (isDevelopment()) {
        secureDevelopmentLog(
          "error",
          "security-kit",
          "ensureCrypto initialization failed",
          {
            error:
              error instanceof Error
                ? { name: error.name, message: error.message }
                : String(error),
          },
        );
      }
    } catch {
      /* ignore */
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
    "Web Crypto API is unavailable synchronously.",
  );
}

// --- Test-only Helpers ---
export const __test_resetCryptoStateForUnitTests: undefined | (() => void) =
  typeof __TEST__ !== "undefined" && __TEST__
    ? (() => {
        // runtime guard to prevent accidental execution in production
        // import lazily to avoid cycles at module load time
        const { assertTestApiAllowed } = require("./development-guards");
        assertTestApiAllowed();
        return () => {
          _cachedCrypto = undefined;
          _cryptoPromise = undefined;
          _cryptoState = CryptoState.Unconfigured;
          _cryptoInitGeneration = 0;
          try {
            environment.clearCache();
          } catch {}
        };
      })()
    : undefined;

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

// Small test helper to inspect cached crypto in unit tests when allowed.
export function __test_getCachedCrypto(): Crypto | null | undefined {
  if (typeof __TEST__ !== "undefined" && __TEST__) {
    return _cachedCrypto;
  }
  return undefined;
}
