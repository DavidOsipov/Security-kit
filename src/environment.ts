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

  function isPrivate172(hostname: string) {
    if (typeof hostname !== "string") return false;
    const parts = hostname.trim().split(".");
    if (parts.length !== 4) return false;
    const first = Number(parts[0]);
    const second = Number(parts[1]);
    if (!Number.isFinite(first) || !Number.isFinite(second)) return false;
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
      if (cache.has("isDevelopment"))
        return cache.get("isDevelopment") ?? false;

      if (typeof process !== "undefined" && process.env?.["NODE_ENV"]) {
        const isNodeDevelopment =
          process.env["NODE_ENV"] === "development" ||
          process.env["NODE_ENV"] === "test";
        // Cache node-derived environment for subsequent calls.
        // eslint-disable-next-line functional/immutable-data -- deliberate, limited cache mutation
        cache.set("isDevelopment", isNodeDevelopment);
        return isNodeDevelopment;
      }

      const result = (() => {
        try {
          const location = (globalThis as { readonly location?: Location })
            .location;
          if (!location) return false;
          const hostname = (location.hostname || "").trim().toLowerCase();
          const developmentHostnames = ["localhost", "127.0.0.1", "[::1]", ""];
          const developmentSuffixes = [".local", ".test"];
          const developmentPrefixes = ["192.168.", "10."];
          return (
            developmentHostnames.includes(hostname) ||
            developmentSuffixes.some((suffix) => hostname.endsWith(suffix)) ||
            developmentPrefixes.some((prefix) => hostname.startsWith(prefix)) ||
            isPrivate172(hostname)
          );
        } catch {
          return false;
        }
      })();
      // Cache the computed value for subsequent calls. This is a deliberate
      // optimization; mutating the Map is intentional and limited in scope.
      // eslint-disable-next-line functional/immutable-data -- intentional, limited cache mutation
      cache.set("isDevelopment", result);
      return result;
    },
    get isProduction() {
      if (explicitEnvironment) return explicitEnvironment === "production";
      // Avoid relying on `this` binding in getters; reference the exported
      // `environment` object explicitly to ensure correctness if the getter
      // is extracted or called with a different `this`.
      return !environment.isDevelopment;
    },
    clearCache() {
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
