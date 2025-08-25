// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Provides utilities for detecting the application environment.
 * @module
 */

export const environment = (() => {
  const cache = new Map<string, boolean>();
  let explicitEnv: "development" | "production" | null = null;

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
    setExplicitEnv(env: "development" | "production") {
      explicitEnv = env;
      cache.clear();
    },
    get isDevelopment() {
      if (explicitEnv) return explicitEnv === "development";
      if (cache.has("isDevelopment"))
        return cache.get("isDevelopment") ?? false;

      if (typeof process !== "undefined" && process.env?.["NODE_ENV"]) {
        const isNodeDev =
          process.env["NODE_ENV"] === "development" ||
          process.env["NODE_ENV"] === "test";
        cache.set("isDevelopment", isNodeDev);
        return isNodeDev;
      }

      let result = false;
      try {
        const location = (globalThis as { location?: Location }).location;
        if (location) {
          const hostname = (location.hostname || "").trim().toLowerCase();
          const devHostnames = ["localhost", "127.0.0.1", "[::1]", ""];
          const devSuffixes = [".local", ".test"];
          const devPrefixes = ["192.168.", "10."];
          result =
            devHostnames.includes(hostname) ||
            devSuffixes.some((suffix) => hostname.endsWith(suffix)) ||
            devPrefixes.some((prefix) => hostname.startsWith(prefix)) ||
            isPrivate172(hostname);
        }
      } catch {
        /* Default to false */
      }
      cache.set("isDevelopment", result);
      return result;
    },
    get isProduction() {
      if (explicitEnv) return explicitEnv === "production";
      // Avoid relying on `this` binding in getters; reference the exported
      // `environment` object explicitly to ensure correctness if the getter
      // is extracted or called with a different `this`.
      return !environment.isDevelopment;
    },
    clearCache() {
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
