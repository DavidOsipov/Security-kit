// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Provides utilities for detecting the application environment.
 * @module
 */

export const environment = (() => {
  const cache = new Map<string, boolean>();
  /*
   * explicitEnvironment must be mutable at runtime because callers may
   * explicitly override environment detection during initialization or tests.
   * This mutation is intentional and guarded by configuration seals elsewhere.
   */
  // eslint-disable-next-line functional/no-let -- runtime mutability required for setExplicitEnv
  let explicitEnvironment: "development" | "production" | undefined;

  function isPrivate172(hostname: string): boolean {
    if (typeof hostname !== "string") return false;
    // Do NOT trim here: treat leading/trailing whitespace as malformed input.
    const parts = hostname.split(".");
    if (parts.length !== 4) return false;
    // Ensure all octets are integers within 0..255
    const octets = parts.map((p) => {
      if (p.length === 0) return NaN;
      if (!/^\d+$/.test(p)) return NaN;
      const n = Number(p);
      return Number.isInteger(n) && n >= 0 && n <= 255 ? n : NaN;
    });
    if (octets.some((n) => !Number.isFinite(n))) return false;
    const first = octets[0] as number;
    const second = octets[1] as number;
    return first === 172 && second >= 16 && second <= 31;
  }

  return {
    setExplicitEnv(environment_: "development" | "production") {
      explicitEnvironment = environment_;
      // Intentional runtime cache mutation to reflect explicit environment override.
      // eslint-disable-next-line functional/immutable-data -- deliberate, limited cache mutation
      cache.clear();
    },
    get isDevelopment() {
      if (explicitEnvironment !== undefined)
        return explicitEnvironment === "development";
      const cached = cache.get("isDevelopment");
      if (cached !== undefined) return cached;

      // Authoritative: NODE_ENV if present (case-insensitive)
      if (
        typeof process !== "undefined" &&
        typeof process.env["NODE_ENV"] === "string"
      ) {
        const environmentValue = process.env["NODE_ENV"].trim().toLowerCase();
        const isNodeDevelopment =
          environmentValue === "development" || environmentValue === "test";
        // Cache node-derived environment for subsequent calls.
        // eslint-disable-next-line functional/immutable-data -- deliberate, limited cache mutation
        cache.set("isDevelopment", isNodeDevelopment);
        return isNodeDevelopment;
      }

      // Default to false (production)
      // eslint-disable-next-line functional/no-let -- try-catch requires mutable variable
      let location: Location | undefined;
      try {
        location = (globalThis as { readonly location?: Location }).location;
      } catch {
        // If accessing location throws (e.g., due to CSP or other restrictions), treat as production
        return false;
      }
      if (!location) {
        return false;
      }
      if (!Object.hasOwn(location as object, "hostname")) {
        return false;
      }
      // eslint-disable-next-line functional/no-let -- try-catch requires mutable variable
      let rawHost: unknown;
      try {
        rawHost = (location as unknown as Record<string, unknown>)["hostname"];
      } catch {
        // If accessing hostname throws (e.g., due to CSP or other restrictions), treat as production
        return false;
      }
      if (typeof rawHost !== "string") {
        return false;
      }

      // Do NOT trim whitespace: treat leading/trailing spaces as malformed input
      // to avoid accidentally accepting ambiguous hostnames.
      const hostname = rawHost.toLowerCase();
      const developmentHostnames = ["localhost", "127.0.0.1", "[::1]", ""];
      const developmentSuffixes = [".local", ".test"];
      const developmentPrefixes = ["192.168.", "10."];
      const result =
        developmentHostnames.includes(hostname) ||
        developmentSuffixes.some((suffix) => hostname.endsWith(suffix)) ||
        developmentPrefixes.some((prefix) => hostname.startsWith(prefix)) ||
        isPrivate172(hostname);

      // Cache the computed value for subsequent calls. This is a deliberate
      // optimization; mutating the Map is intentional and limited in scope.
      // eslint-disable-next-line functional/immutable-data -- intentional, limited cache mutation
      cache.set("isDevelopment", result);
      return result;
    },
    get isProduction() {
      if (explicitEnvironment !== undefined)
        return explicitEnvironment === "production";
      // Avoid relying on `this` binding in getters; reference the exported
      // `environment` object explicitly to ensure correctness if the getter
      // is extracted or called with a different `this`.
      return !environment.isDevelopment;
    },
    clearCache() {
      // Reset explicit environment so subsequent calls re-evaluate conditions
      explicitEnvironment = undefined;
      // eslint-disable-next-line functional/immutable-data -- intentional, limited cache mutation
      cache.clear();
    },
  };
})();

/**
 * Returns `true` if the current environment is determined to be 'development'.
 */
export function isDevelopment(): boolean {
  return environment.isDevelopment;
}
