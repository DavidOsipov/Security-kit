// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Centralized production error reporting with rate-limiting.
 * @module
 */

import { environment } from "./environment";
import { _redact, validateNumericParam } from "./utils";
import { InvalidParameterError, sanitizeErrorForLogs } from "./errors";

let _prodErrorHook:
  | ((error: Error, context: Record<string, unknown>) => void)
  | null = null;
const _prodErrorReportState = {
  tokens: 5,
  maxTokens: 5,
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
  _prodErrorReportState.maxTokens = config.burst;
  _prodErrorReportState.tokens = config.burst;
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
    _prodErrorReportState.lastRefillTs = now;
    const tokensToAdd =
      (elapsedMs / 1000) * _prodErrorReportState.refillRatePerSec;
    if (tokensToAdd > 0) {
      _prodErrorReportState.tokens = Math.min(
        _prodErrorReportState.maxTokens,
        _prodErrorReportState.tokens + tokensToAdd,
      );
    }
    if (_prodErrorReportState.tokens < 1) return;
    _prodErrorReportState.tokens -= 1;

    const sanitized = sanitizeErrorForLogs(err) || {
      name: "Error",
      message: "Unknown",
    };
    _prodErrorHook(
      new Error(`${sanitized.name}: ${sanitized.message}`),
      _redact(context) as Record<string, unknown>,
    );
  } catch {
    // Never throw from the reporter
  }
}
