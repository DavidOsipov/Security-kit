// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Centralized production error reporting with rate-limiting.
 * @module
 */

import { environment } from "./environment";
import {
  _redact,
  validateNumericParam as validateNumericParameter,
} from "./utils";
import { InvalidParameterError, sanitizeErrorForLogs } from "./errors";

// Use integer arithmetic for token refill to avoid floating-point drift.
const TOKEN_PRECISION = 1000; // millitokens
// Use `undefined` instead of `null` to align with project lint rules.
// The hook is intentionally mutable at runtime so callers can install/uninstall
// a production reporting hook. This is safe because callers must opt-in.
// eslint-disable-next-line functional/no-let -- deliberate runtime mutability for hook install/uninstall
let _productionErrorHook:
  | ((error: Error, context: Record<string, unknown>) => void)
  | undefined = undefined;
const _productionErrorReportState = {
  // Stored in millitokens
  tokens: 5 * TOKEN_PRECISION,
  maxTokens: 5 * TOKEN_PRECISION,
  // refillRatePerSec is tokens-per-second (logical tokens); keep it as number
  refillRatePerSec: 1,
  lastRefillTs: 0,
};

// Keep short internal name for backward compatibility; config.ts re-exports
// with a descriptive alias. Suppress the prevent-abbreviations rule here.
// eslint-disable-next-line unicorn/prevent-abbreviations
export function getProdErrorHook() {
  return _productionErrorHook;
}

// eslint-disable-next-line unicorn/prevent-abbreviations
export function setProdErrorHook(
  hook:
    | ((error: Error, context: Record<string, unknown>) => void)
    | undefined
    | null,
) {
  // Treat `null` as explicit uninstall (backwards-compatible with older tests).
  if (hook === null) {
    _productionErrorHook = undefined;
    return;
  }
  if (hook !== undefined && typeof hook !== "function") {
    throw new InvalidParameterError(
      "Production error handler must be a function or undefined.",
    );
  }
  // intentional runtime mutation: install/uninstall hook
  _productionErrorHook = hook;
}

// eslint-disable-next-line unicorn/prevent-abbreviations
export function configureProdErrorReporter(config: {
  readonly burst: number;
  readonly refillRatePerSec: number;
}) {
  validateNumericParameter(config.burst, "burst", 1, 100);
  validateNumericParameter(config.refillRatePerSec, "refillRatePerSec", 0, 100);
  // Intentional in-place mutation for performance: this rate-limiter is a
  // low-level runtime primitive and allocating a new object on every
  // configuration change is unnecessary. Documented and limited scope.
  // eslint-disable-next-line functional/immutable-data
  _productionErrorReportState.maxTokens = config.burst * TOKEN_PRECISION;
  // eslint-disable-next-line functional/immutable-data
  _productionErrorReportState.tokens = config.burst * TOKEN_PRECISION;
  // eslint-disable-next-line functional/immutable-data
  _productionErrorReportState.refillRatePerSec = config.refillRatePerSec;
  // eslint-disable-next-line functional/immutable-data
  _productionErrorReportState.lastRefillTs = 0;
}

// eslint-disable-next-line unicorn/prevent-abbreviations
export function reportProdError(error: Error, context: unknown = {}) {
  try {
    if (!environment.isProduction || _productionErrorHook === undefined) return;
    const now = Date.now();
    if (_productionErrorReportState.lastRefillTs === 0) {
      // intentionally mutate timestamp to initialize the refill clock; narrow exception
      // eslint-disable-next-line functional/immutable-data -- deliberate, limited mutation
      _productionErrorReportState.lastRefillTs = now;
    }
    const elapsedMs = Math.max(
      0,
      now - _productionErrorReportState.lastRefillTs,
    );
    // Update timestamp before spending tokens to reduce race conditions
    // Calculate millitokens to add using integer math to avoid float drift.
    // eslint-disable-next-line functional/immutable-data -- deliberate, limited mutation
    _productionErrorReportState.lastRefillTs = now;
    const tokensToAdd = Math.floor(
      (elapsedMs *
        _productionErrorReportState.refillRatePerSec *
        TOKEN_PRECISION) /
        1000,
    );
    if (tokensToAdd > 0) {
      // update tokens in-place for performance; limited and documented
      // eslint-disable-next-line functional/immutable-data -- deliberate, limited mutation
      _productionErrorReportState.tokens = Math.min(
        _productionErrorReportState.maxTokens,
        _productionErrorReportState.tokens + tokensToAdd,
      );
    }
    // Require at least one whole token (TOKEN_PRECISION millitokens) to send
    if (_productionErrorReportState.tokens < TOKEN_PRECISION) return;
    // deduct one whole token (millitokens used internally)
    // eslint-disable-next-line functional/immutable-data -- deliberate, limited mutation
    _productionErrorReportState.tokens -= TOKEN_PRECISION;

    const sanitized = sanitizeErrorForLogs(error) || {
      name: "Error",
      message: "Unknown",
    };
    // Call the installed hook in a try/catch to ensure reporter never throws.
    try {
      const hook = _productionErrorHook as (
        error_: Error,
        context_: Record<string, unknown>,
      ) => void;
      // Redact the user-provided context first to avoid spreading raw objects
      // (which may have side-effectful getters) and to guarantee a sanitized
      // payload is passed to the production hook. Freeze the final object so
      // downstream reporters cannot mutate it.
      const redactedContext =
        (_redact(context) || {}) as Record<string, unknown>;
      const finalContext = Object.freeze({
        ...redactedContext,
        stackHash: (sanitized as { readonly stackHash?: string }).stackHash,
      });
      try {
        hook(
          new Error(`${sanitized.name}: ${sanitized.message}`),
          finalContext,
        );
      } catch {
        // Swallow errors from the hook - reporting must never throw.
      }
    } catch {
      // Swallow errors from the hook - reporting must never throw.
    }
  } catch {
    // Never throw from the reporter
  }
}

// Test helpers (for unit tests). These are intentionally named with
// a double-underscore prefix to indicate internal/test-only usage.
// Test helpers (kept with abbreviated name intentionally; tests import them
// directly). Suppress prevent-abbreviations for test helper.
// eslint-disable-next-line unicorn/prevent-abbreviations
export function __test_resetProdErrorReporter() {
  // eslint-disable-next-line functional/immutable-data
  _productionErrorReportState.maxTokens = 5 * TOKEN_PRECISION;
  // eslint-disable-next-line functional/immutable-data
  _productionErrorReportState.tokens = 5 * TOKEN_PRECISION;
  // eslint-disable-next-line functional/immutable-data
  _productionErrorReportState.refillRatePerSec = 1;
  // eslint-disable-next-line functional/immutable-data
  _productionErrorReportState.lastRefillTs = 0;
  _productionErrorHook = undefined;
}

export function __test_setLastRefillForTesting(msAgo: number) {
  // eslint-disable-next-line functional/immutable-data
  _productionErrorReportState.lastRefillTs = Date.now() - Math.max(0, msAgo);
}
