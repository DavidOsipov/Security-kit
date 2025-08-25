// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Runtime guards for test-only APIs. These are defensive checks that will
 * prevent accidental usage of test helpers in production when the
 * __TEST__ flag is true during build-time but runtime still ends up in
 * a production environment (e.g., misconfiguration).
 */
import { environment } from "./environment";
import { InvalidConfigurationError } from "./errors";

export function assertTestApiAllowed(): void {
  // If we're not in production, it's always allowed.
  if (!environment.isProduction) return;

  // Allow explicit opt-in via env var or a global token.
  const envAllow =
    typeof process !== "undefined" &&
    process?.env?.["SECURITY_KIT_ALLOW_TEST_APIS"] === "true";
  const globalAllow = !!(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  if (envAllow || globalAllow) return;

  throw new InvalidConfigurationError(
    "Test-only APIs are disabled in production. Set SECURITY_KIT_ALLOW_TEST_APIS=true or set globalThis.__SECURITY_KIT_ALLOW_TEST_APIS = true to explicitly allow.",
  );
}
