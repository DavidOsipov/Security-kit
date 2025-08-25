// --- File: src/sanitizer.ts ---

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Provides a hardened wrapper around DOMPurify to create and manage
 * Trusted Types policies for HTML sanitization, in direct alignment with the
 * Security Constitution (Rule 2.2, Rule 4.4, Appendix C).
 * @module
 */

import DOMPurify, { Config as DOMPurifyConfig } from "dompurify";
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
  readonly #dompurify:
    | ReturnType<typeof DOMPurify>
    | { sanitize: (s: string, cfg?: DOMPurifyConfig) => string | TrustedHTML };
  readonly #policies: SanitizerPolicies;
  // TrustedTypePolicy shapes vary by environment; keep stored value as `any` to avoid tight coupling with lib types
  #trustedTypePolicies = new Map<string, any>();

  /**
   * @param dompurifyInstance An instance of the DOMPurify library.
   * @param policies A map of named, pre-defined DOMPurify configurations.
   */
  constructor(
    dompurifyInstance:
      | ReturnType<typeof DOMPurify>
      | {
          sanitize: (s: string, cfg?: DOMPurifyConfig) => string | TrustedHTML;
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
    if (this.#trustedTypePolicies.has(policyName)) {
      return this.#trustedTypePolicies.get(policyName)!;
    }

    const config = this.#policies[policyName];
    if (!config) {
      throw new InvalidConfigurationError(
        `Sanitizer policy "${policyName}" is not defined.`,
      );
    }

    if (
      typeof window.trustedTypes === "undefined" ||
      !window.trustedTypes.createPolicy
    ) {
      throw new Error(
        "Trusted Types API is not available in this environment.",
      );
    }

    const ttPolicy: any = window.trustedTypes.createPolicy(policyName, {
      createHTML: (input: string) => {
        // Ensure RETURN_TRUSTED_TYPE is true for the policy to work correctly.
        return this.#dompurify.sanitize(input, {
          ...config,
          RETURN_TRUSTED_TYPE: true,
        }) as unknown as string;
      },
      createScript: () => {
        throw new TypeError("Dynamic scripts are not allowed");
      },
      createScriptURL: () => {
        throw new TypeError("Dynamic script URLs are not allowed");
      },
    });

    this.#trustedTypePolicies.set(policyName, ttPolicy);
    return ttPolicy;
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
}
