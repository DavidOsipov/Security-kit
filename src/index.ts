// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Secure, performant, and modern cryptographic utilities.
 * @module @david-osipov/security-kit
 * @version 7.3.1
 */

// --- Re-export all public APIs ---

// Errors
export * from "./errors";

// Configuration
export {
  setCrypto,
  sealSecurityKit,
  setAppEnvironment,
  setProductionErrorHandler,
  configureErrorReporter,
} from "./config";

// State (Test-only)
export {
  getInternalTestUtils,
  __test_resetCryptoStateForUnitTests,
} from "./state";
export type { CryptoState } from "./state";

// Environment
export { environment, isDevelopment } from "./environment";

// Core Crypto Primitives
export * from "./crypto";

// URL Utilities
export * from "./url";

// PostMessage Utilities
export * from "./postMessage";

// General Utilities
export {
  secureWipe,
  secureCompare,
  secureCompareAsync,
  secureDevLog,
  secureDevNotify,
  __test_arrayBufferToBase64,
} from "./utils";
