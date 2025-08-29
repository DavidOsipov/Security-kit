// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Secure, performant, and modern cryptographic utilities.
 * @module @david-osipov/security-kit
 * @version 0.7.1
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
// URL policy configuration (controlled opt-in)
export { configureUrlPolicy, getSafeSchemes } from "./url-policy";

// PostMessage Utilities
export * from "./postMessage";

// General Utilities
export {
  secureWipe,
  secureCompare,
  secureCompareAsync,
  secureDevLog,
} from "./utils";

// Sanitizer Utilities (requires peer dependency 'dompurify')
export * from "./sanitizer";
// DOM querying and validation utilities
export * from "./dom";

// Scripts / dev helpers
// Note: test-only harness moved into the test tree. Do not export test harness from public API.

// Optional: production error reporter for manual emission (rate-limited)
export { reportProdError } from "./reporting";

// Canonicalization utilities for secure API signing (shared client/server)
export { safeStableStringify, toCanonicalValue } from "./canonical";
