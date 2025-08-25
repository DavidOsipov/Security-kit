// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Centralized production error reporting with rate-limiting.
 * @module
 */

import { environment } from "./environment";
import { _redact, validateNumericParam } from "./utils";
import { InvalidParameterError, sanitizeErrorForLogs } from "./errors";

// Use integer arithmetic for token refill to avoid floating-point drift.
const TOKEN_PRECISION = 1000; // millitokens

let _prodErrorHook:
  | ((error: Error, context: Record<string, unknown>) => void)
  | null = null;
const _prodErrorReportState = {
  // Stored in millitokens
  tokens: 5 * TOKEN_PRECISION,
  maxTokens: 5 * TOKEN_PRECISION,
  // refillRatePerSec is tokens-per-second (logical tokens); keep it as number
  refillRatePerSec: 1,
  lastRefillTs: 0,
};

export function getProdErrorHook() {
  return _prodErrorHook;
}

export function setProdErrorHook(
  hook: ((error: Error, context: Record<string, unknown>) => void) | null,
) {
  if (hook !== null && typeof hook !== "function") {
    throw new InvalidParameterError(
      "Production error handler must be a function or null.",
    );
  }
  _prodErrorHook = hook;
}

export function configureProdErrorReporter(config: {
  burst: number;
  refillRatePerSec: number;
}) {
  validateNumericParam(config.burst, "burst", 1, 100);
  validateNumericParam(config.refillRatePerSec, "refillRatePerSec", 0, 100);
  _prodErrorReportState.maxTokens = config.burst * TOKEN_PRECISION;
  _prodErrorReportState.tokens = config.burst * TOKEN_PRECISION;
  _prodErrorReportState.refillRatePerSec = config.refillRatePerSec;
  _prodErrorReportState.lastRefillTs = 0;
}

export function reportProdError(err: Error, context: unknown = {}) {
  try {
    if (!environment.isProduction || !_prodErrorHook) return;
    const now = Date.now();
    if (_prodErrorReportState.lastRefillTs === 0) {
      _prodErrorReportState.lastRefillTs = now;
    }
    const elapsedMs = Math.max(0, now - _prodErrorReportState.lastRefillTs);
    // Update timestamp before spending tokens to reduce race conditions
    // Calculate millitokens to add using integer math to avoid float drift.
    _prodErrorReportState.lastRefillTs = now;
    const tokensToAdd = Math.floor(
      (elapsedMs * _prodErrorReportState.refillRatePerSec * TOKEN_PRECISION) /
        1000,
    );
    if (tokensToAdd > 0) {
      _prodErrorReportState.tokens = Math.min(
        _prodErrorReportState.maxTokens,
        _prodErrorReportState.tokens + tokensToAdd,
      );
    }
    // Require at least one whole token (TOKEN_PRECISION millitokens) to send
    if (_prodErrorReportState.tokens < TOKEN_PRECISION) return;
    _prodErrorReportState.tokens -= TOKEN_PRECISION;

    const sanitized = sanitizeErrorForLogs(err) || {
      name: "Error",
      message: "Unknown",
    };
    _prodErrorHook(
      new Error(`${sanitized.name}: ${sanitized.message}`),
      // Include the stackHash in the redacted context for correlation.
      _redact({
        ...(context as object),
        stackHash: (sanitized as { stackHash?: string }).stackHash,
      }) as Record<string, unknown>,
    );
  } catch {
    // Never throw from the reporter
  }
}

// Test helpers (for unit tests). These are intentionally named with
// a double-underscore prefix to indicate internal/test-only usage.
export function __test_resetProdErrorReporter() {
  _prodErrorReportState.maxTokens = 5 * TOKEN_PRECISION;
  _prodErrorReportState.tokens = 5 * TOKEN_PRECISION;
  _prodErrorReportState.refillRatePerSec = 1;
  _prodErrorReportState.lastRefillTs = 0;
  _prodErrorHook = null;
}

export function __test_setLastRefillForTesting(msAgo: number) {
  _prodErrorReportState.lastRefillTs = Date.now() - Math.max(0, msAgo);
}
