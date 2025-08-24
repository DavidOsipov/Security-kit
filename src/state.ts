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
import { reportProdError } from "./reporting";
import { secureDevLog } from "./utils";

// --- State Machine ---
export const CryptoState = Object.freeze({
  Unconfigured: "unconfigured",
  Configuring: "configuring",
  Configured: "configured",
  Sealed: "sealed",
} as const);
export type CryptoState = (typeof CryptoState)[keyof typeof CryptoState];

let _cachedCrypto: Crypto | null = null;
let _cryptoPromise: Promise<Crypto> | null = null;
let _cryptoState: CryptoState = CryptoState.Unconfigured;
let _cryptoInitGeneration = 0;

// --- Internal State Accessors ---
export function getCryptoState(): CryptoState {
  return _cryptoState;
}

// --- Internal Configuration API ---
export function _setCrypto(
  cryptoLike: Crypto | null | undefined,
  { allowInProduction = false }: { allowInProduction?: boolean } = {},
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

  _cryptoInitGeneration++;
  _cryptoPromise = null;

  if (cryptoLike == null) {
    _cachedCrypto = null;
    _cryptoState = CryptoState.Unconfigured;
    return;
  }
  if (
    typeof cryptoLike !== "object" ||
    typeof (cryptoLike as { getRandomValues?: unknown }).getRandomValues !==
      "function"
  ) {
    throw new InvalidParameterError(
      "setCrypto: provided object must implement crypto.getRandomValues(Uint8Array).",
    );
  }

  _cachedCrypto = cryptoLike;
  _cryptoState = CryptoState.Configured;
}

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
    return _cachedCrypto;
  }
  if (_cryptoState === CryptoState.Configured && _cachedCrypto) {
    return _cachedCrypto;
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
          return _cachedCrypto;
        }
        _cryptoState = CryptoState.Unconfigured;
        throw new CryptoUnavailableError(
          "Crypto initialization was reset during async operation.",
        );
      }
      if (_cachedCrypto) {
        _cryptoState = CryptoState.Configured;
        return _cachedCrypto;
      }
      const globalCrypto = (globalThis as { crypto?: Crypto }).crypto;
      if (globalCrypto && typeof globalCrypto.getRandomValues === "function") {
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
        _cryptoPromise = null;
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
        reportProdError(
          error instanceof Error ? error : new Error(String(error)),
          safeContext,
        );
      } else if (isDevelopment()) {
        secureDevLog(
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
  const globalCrypto = (globalThis as { crypto?: Crypto }).crypto;
  if (globalCrypto && typeof globalCrypto.getRandomValues === "function") {
    _cachedCrypto = globalCrypto;
    _cryptoState = CryptoState.Configured;
    return _cachedCrypto;
  }
  throw new CryptoUnavailableError(
    "Web Crypto API is unavailable synchronously.",
  );
}

// --- Test-only Helpers ---
export let __test_resetCryptoStateForUnitTests: undefined | (() => void);
if (typeof __TEST__ !== "undefined" && __TEST__) {
  __test_resetCryptoStateForUnitTests = () => {
    _cachedCrypto = null;
    _cryptoPromise = null;
    _cryptoState = CryptoState.Unconfigured;
    _cryptoInitGeneration = 0;
    try {
      environment.clearCache();
    } catch {}
  };
}

export function getInternalTestUtils():
  | {
      _getCryptoGenerationForTest: () => number;
      _getCryptoStateForTest: () => string;
    }
  | undefined {
  const isNodeTestEnv =
    typeof process !== "undefined" && process.env?.["NODE_ENV"] === "test";
  const isSecurityKitTestFlag =
    typeof process !== "undefined" &&
    process.env?.["SECURITY_KIT_TEST"] === "1";

  if (!isDevelopment() && !isNodeTestEnv && !isSecurityKitTestFlag) {
    return undefined;
  }
  return {
    _getCryptoGenerationForTest: () => _cryptoInitGeneration,
    _getCryptoStateForTest: () => _cryptoState,
  };
}
