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
  _setCrypto(cryptoLike, options);
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
