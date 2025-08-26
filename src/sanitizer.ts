// --- File: src/sanitizer.ts ---

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Provides a hardened wrapper around DOMPurify to create and manage
 * Trusted Types policies for HTML sanitization, in direct alignment with the
 * Security Constitution (Rule 2.2, Rule 4.4, Appendix C).
 * @module
 */

import type { Config as DOMPurifyConfig } from "dompurify";
import { InvalidConfigurationError, InvalidParameterError } from "./errors";

// --- Pre-defined, Hardened Policies (as per Security Constitution Appendix C) ---

/**
 * A strict, baseline policy allowing only basic HTML formatting tags.
 * It explicitly disables SVG and MathML.
 * @see Security Constitution: Appendix C.2
 */
export const STRICT_HTML_POLICY_CONFIG: DOMPurifyConfig = Object.freeze({
  USE_PROFILES: { html: true, svg: false, mathml: false },
  RETURN_TRUSTED_TYPE: true,
});

/**
 * A hardened policy for allowing SVGs, with dangerous tags and attributes forbidden.
 * @see Security Constitution: Appendix C.4
 */
export const HARDENED_SVG_POLICY_CONFIG: DOMPurifyConfig = Object.freeze({
  USE_PROFILES: { html: true, svg: true, mathml: false },
  FORBID_TAGS: ["script", "style", "iframe", "foreignObject", "form", "a"],
  FORBID_ATTR: ["onclick", "onerror", "onload", "onmouseover", "href"],
  RETURN_TRUSTED_TYPE: true,
});

// --- Sanitizer Class ---

export type SanitizerPolicies = Record<string, DOMPurifyConfig>;

/**
 * A class that manages Trusted Types policies using a provided DOMPurify instance.
 * It enforces the Security Constitution's rule that all sanitizer configurations
 * must be centralized and named, preventing ad-hoc, insecure configurations.
 */
export class Sanitizer {
  // Use a minimal, compatible type for the DOMPurify instance to avoid complex ReturnType constraints
  readonly #dompurify: {
    readonly sanitize: (
      s: string,
      cfg?: DOMPurifyConfig,
    ) => string | TrustedHTML;
  };
  readonly #policies: SanitizerPolicies;
  // TrustedTypePolicy shapes vary by environment; store typed policies.
  // The cache is intentionally mutable but strictly private. TrustedTypePolicy
  // objects are immutable by contract (the TT API returns opaque objects) and
  // caching avoids repeated, expensive policy creation. We keep the mutation
  // minimal and contained to this single line to balance security, clarity,
  // and performance.
  readonly #trustedTypePolicies = new Map<string, TrustedTypePolicy>();

  /**
   * @param dompurifyInstance An instance of the DOMPurify library.
   * @param policies A map of named, pre-defined DOMPurify configurations.
   */
  constructor(
    dompurifyInstance: {
      readonly sanitize: (
        s: string,
        cfg?: DOMPurifyConfig,
      ) => string | TrustedHTML;
    },
    policies: SanitizerPolicies,
  ) {
    if (
      !dompurifyInstance ||
      typeof dompurifyInstance.sanitize !== "function"
    ) {
      throw new InvalidParameterError(
        "A valid DOMPurify instance must be provided.",
      );
    }
    this.#dompurify = dompurifyInstance;
    this.#policies = policies;
  }

  /**
   * Creates and registers a Trusted Types policy for a named sanitizer configuration.
   * This is the primary method for securely creating TrustedHTML.
   * @param policyName The name of the policy to create (must exist in the constructor's policies map).
   * @returns The created TrustedTypePolicy instance.
   * @throws {InvalidConfigurationError} If the policy name is not found.
   */
  public createPolicy(policyName: string): TrustedTypePolicy {
    // Return cached policy if already created
    const existing = this.#trustedTypePolicies.get(policyName);
    if (existing) return existing;

    const config = this.#policies[policyName];
    if (!config) {
      throw new InvalidConfigurationError(
        `Sanitizer policy "${policyName}" is not defined.`,
      );
    }

    // Use optional chaining to detect availability of the Trusted Types API.
    if (typeof window.trustedTypes?.createPolicy !== "function") {
      throw new Error(
        "Trusted Types API is not available in this environment.",
      );
    }

    // Narrowly typed alias for the Trusted Types createPolicy function
    type TTCreatePolicy = (
      name: string,
      rules: {
        readonly createHTML: (input: string) => TrustedHTML;
        readonly createScript?: () => never;
        readonly createScriptURL?: () => never;
      },
    ) => TrustedTypePolicy;

    const createPolicyFunction = window.trustedTypes
      .createPolicy as unknown as TTCreatePolicy;

    const raw = createPolicyFunction(policyName, {
      createHTML: (input: string) => {
        // Ensure RETURN_TRUSTED_TYPE is true for the policy to work correctly.
        return this.#dompurify.sanitize(input, {
          ...config,
          RETURN_TRUSTED_TYPE: true,
        }) as TrustedHTML;
      },
      createScript: () => {
        throw new TypeError("Dynamic scripts are not allowed");
      },
      createScriptURL: () => {
        throw new TypeError("Dynamic script URLs are not allowed");
      },
    });

    // Controlled cache population: intentionally mutate the private Map to
    // cache the created policy. This is a narrowly-scoped, auditable exception
    // because TrustedTypePolicy instances are opaque and safe to reuse once
    // created. Keep the eslint-disable scoped to this single call only.
    /* eslint-disable-next-line functional/immutable-data --
       private, controlled cache mutation for TrustedTypePolicy instances */
    this.#trustedTypePolicies.set(policyName, raw);
    return raw;
  }

  /**
   * A secure fallback for sanitizing HTML in browsers that do not support Trusted Types.
   * @param dirtyHtml The untrusted HTML string to sanitize.
   * @param policyName The name of the policy configuration to use.
   * @returns A sanitized HTML string.
   */
  public sanitizeForNonTTBrowsers(
    dirtyHtml: string,
    policyName: string,
  ): string {
    const config = this.#policies[policyName];
    if (!config) {
      throw new InvalidConfigurationError(
        `Sanitizer policy "${policyName}" is not defined.`,
      );
    }
    // Ensure we return a string for non-TT environments.
    return this.#dompurify.sanitize(dirtyHtml, {
      ...config,
      RETURN_TRUSTED_TYPE: false,
    }) as string;
  }

  /**
   * Attempts to create a Named TrustedTypePolicy if the API is available.
   * Returns the policy or `undefined` if the environment doesn't support Trusted Types.
   * This does not throw when Trusted Types are unavailable.
   */
  public createPolicyIfAvailable(
    policyName: string,
  ): TrustedTypePolicy | undefined {
    if (!this.#policies[policyName]) {
      throw new InvalidConfigurationError(
        `Sanitizer policy "${policyName}" is not defined.`,
      );
    }
    if (typeof window === "undefined") return undefined;
    // Optional chaining to detect availability
    const win = window as unknown as Record<string, unknown>;
    const tt = win["trustedTypes"] as
      | undefined
      | { readonly createPolicy?: unknown };
        if (typeof tt?.createPolicy !== "function") return undefined;
    try {
      return this.createPolicy(policyName);
    } catch {
          // If policy creation fails for any reason, fall back to undefined
          return undefined;
    }
  }

  /**
   * Returns sanitized HTML either as TrustedHTML (when Trusted Types available)
   * or as a sanitized string for non-TT environments.
   */
  /**
   * Returns a sanitized HTML string using the named policy. This function
   * always returns a string and never assigns DOM properties (avoids unsafe
   * side effects and satisfies linting rules). Consumers running in Trusted
   * Types-enabled environments can still call `createPolicyIfAvailable` and
   * use the policy directly if they wish to produce TrustedHTML values.
   */
  public getSanitizedString(dirtyHtml: string, policyName: string): string {
    return this.sanitizeForNonTTBrowsers(dirtyHtml, policyName);
  }
}

// NOTE: The sanitizer needs to manage a small cache of Trusted Type policies
// which is a controlled mutation (Map.set) for performance and to avoid
// repeatedly creating policies. This file intentionally performs a tiny
// amount of mutation for that purpose; keep the scope of mutations small and
// justified.

/**
 * ESLint/Policy recommendations for consumers of this library.
 * These are suggestions you can paste into your project's ESLint config
 * or documentation to help enforce safe usage of innerHTML and DOM APIs.
 */
export const SANITIZER_ESLINT_RECOMMENDATIONS = Object.freeze([
  "security/no-unsafe-innerhtml",
  "no-restricted-syntax (disallow direct innerHTML assignment)",
  "prefer using Sanitizer.safeSetInnerHTML for DOM updates",
]);
