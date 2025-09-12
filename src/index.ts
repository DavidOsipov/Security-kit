// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Secure, performant, and modern cryptographic utilities.
 * @module @david-osipov/security-kit
 * @version 0.7.1
 */

// --- Re-export all public APIs ---

// Errors
export * from "./errors.ts";

// Configuration
export {
  setCrypto,
  sealSecurityKit,
  freezeConfig,
  setAppEnvironment,
  setProductionErrorHandler,
  configureErrorReporter,
  // Cache profile helpers
  getSecureLRUProfiles,
  setSecureLRUProfiles,
  resolveSecureLRUOptions,
} from "./config.ts";

// State (Test-only)
export {
  getInternalTestUtils,
  __test_resetCryptoStateForUnitTests,
} from "./state.ts";
export type { CryptoState } from "./state.ts";

// Environment
export { environment, isDevelopment } from "./environment.ts";

// Core Crypto Primitives
export * from "./crypto.ts";

// URL Utilities
export * from "./url.ts";
// URL hardening runtime config helpers
export {
  getUrlHardeningConfig,
  setUrlHardeningConfig,
  runWithStrictUrlHardening,
} from "./config.ts";
// URL policy configuration (controlled opt-in)
export { configureUrlPolicy, getSafeSchemes } from "./config.ts";

// PostMessage Utilities
export * from "./postMessage.ts";

// General Utilities
export {
  secureWipe,
  secureWipeOrThrow,
  secureWipeAsync,
  secureWipeAsyncOrThrow,
  secureCompare,
  secureCompareAsync,
  secureDevLog,
  withSecureBuffer,
  secureCompareBytes,
} from "./utils.ts";

// Logger (optional ergonomic wrapper)
export { createLogger } from "./logger.ts";

// Sanitizer Utilities (requires peer dependency 'dompurify')
export * from "./sanitizer.ts";
// DOM querying and validation utilities
export * from "./dom.ts";

// Scripts / dev helpers
// Note: test-only harness moved into the test tree. Do not export test harness from public API.

// Optional: production error reporter for manual emission (rate-limited)
export { reportProdError } from "./reporting.ts";

// Canonicalization utilities for secure API signing (shared client/server)
export { safeStableStringify, toCanonicalValue } from "./canonical.ts";

// Secure LRU Cache - Standalone security-hardened cache utility
export {
  SecureLRUCache,
  VerifiedByteCache,
  asReadOnlyCache,
  type ReadOnlyCache,
  type CacheOptions,
  type SetOptions,
  type CacheStats,
  type EvictionReason,
  type EvictedEntry,
  type Logger,
} from "./secure-cache.ts";
