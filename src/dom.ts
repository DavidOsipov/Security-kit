// --- File: src/dom.ts ---

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Provides hardened, allowlist-based DOM querying and validation utilities.
 * This module is a critical security component that prevents selector injection
 * and ensures that application logic can only interact with a predefined,
 * safe subset of the DOM, enforcing the Principle of Least Privilege.
 * @module
 */

/* eslint-disable functional/immutable-data, unicorn/no-null */

import {
  InvalidParameterError,
  InvalidConfigurationError,
  sanitizeErrorForLogs,
} from "./errors";
import { secureDevLog as secureDevelopmentLog } from "./utils";

/**
 * Configuration for the DOMValidator.
 */
export interface DOMValidatorConfig {
  /** A Set of CSS selectors defining the root elements within which all queries must be contained. */
  readonly allowedRootSelectors: ReadonlySet<string>;
  /** A Set of selectors that are explicitly forbidden from being in the allowlist (e.g., 'body', 'html'). */
  readonly forbiddenRoots: ReadonlySet<string>;
}

const DEFAULT_CONFIG: DOMValidatorConfig = {
  // Example configuration. A real app would configure this at startup.
  allowedRootSelectors: new Set([
    "#main-content",
    "#main-header",
    "#modal-container",
  ]),
  forbiddenRoots: new Set(["body", "html", "#app", "#root"]),
};

// Note: We intentionally do not rely on the immutability of the inner Set
// contents here. The DOMValidator constructor will clone and normalize any
// provided configuration to ensure internal copies cannot be mutated by
// external consumers.

/**
 * A security-focused class for validating and querying DOM elements.
 */
export class DOMValidator {
  readonly #config: DOMValidatorConfig;
  readonly #validatedElements = new WeakSet<Element>();
  // Use `undefined` instead of `null` for uninitialized caches to satisfy
  // linting rules; semantics remain identical.
  #resolvedRootsCache:
    | ReadonlyMap<string, Element | undefined>
    | undefined = undefined;

  constructor(config: DOMValidatorConfig = DEFAULT_CONFIG) {
    // Clone and normalize the configuration to avoid retaining references to
    // mutable Sets supplied by callers. This defends against accidental or
    // malicious mutation of the allowlist at runtime.
    function cloneConfig(cfg: DOMValidatorConfig): DOMValidatorConfig {
      const allowed = new Set<string>();
      for (const s of cfg.allowedRootSelectors) allowed.add(String(s));
      const forbidden = new Set<string>();
      for (const s of cfg.forbiddenRoots)
        forbidden.add(String(s).toLowerCase());
      return {
        allowedRootSelectors: allowed,
        forbiddenRoots: forbidden,
      };
    }

    this.#config = Object.freeze(cloneConfig(config));
    // Self-defense mechanism: Validate the provided configuration on instantiation.
    for (const root of this.#config.allowedRootSelectors) {
      if (this.#config.forbiddenRoots.has(root.toLowerCase())) {
        throw new InvalidConfigurationError(
          `Disallowed broad selector in validator allowlist: "${root}"`,
        );
      }
    }
  }

  /**
   * Resolves and caches the DOM Elements corresponding to the allowed root selectors.
   */
  #resolveAndCacheAllowedRoots(): ReadonlyMap<string, Element | undefined> {
    if (this.#resolvedRootsCache) {
      return this.#resolvedRootsCache;
    }
    const cache = new Map<string, Element | undefined>();
    for (const selector of this.#config.allowedRootSelectors) {
      // Assuming 'document' is available in the context where this runs.
      cache.set(selector, document.querySelector(selector) ?? undefined);
    }
    this.#resolvedRootsCache = cache;
    return cache;
  }

  /**
   * Performs a basic validation of a CSS selector's syntax.
   * @param selector The CSS selector string to validate.
   * @returns The validated selector.
   * @throws {InvalidParameterError} If the selector is invalid.
   */
  public validateSelectorSyntax(selector: string): string {
    if (typeof selector !== "string" || !selector.trim()) {
      throw new InvalidParameterError(
        "Invalid selector: must be a non-empty string.",
      );
    }
    // Reject selectors that are excessively long which may be expensive to
    // parse or may be used in DoS attempts.
    const MAX_SELECTOR_LEN = 1024;
    if (selector.length > MAX_SELECTOR_LEN) {
      throw new InvalidParameterError("Selector is too long.");
    }

    // Disallow known expensive or new pseudo-classes that can cause complex
    // selector evaluation (e.g., :has()). This helps avoid high CPU selectors.
    const expensiveTokens = /:has\(|:is\(|:where\(|:nth-last|:nth-child/;
    if (expensiveTokens.test(selector)) {
      throw new InvalidParameterError(
        "Selector contains disallowed or expensive pseudo-classes.",
      );
    }
    // Check syntax without actually querying the live DOM if possible.
    if (typeof document !== "undefined") {
      try {
        document.createDocumentFragment().querySelector(selector);
      } catch (error) {
        throw new InvalidParameterError(
          `Invalid selector syntax: ${selector}. Reason: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    return selector;
  }

  /**
   * Validates that a given value is a DOM Element and not a forbidden tag.
   * @param el The unknown value to validate.
   * @returns The validated DOM Element.
   * @throws {InvalidParameterError} If validation fails.
   */
  public validateElement(element_: unknown): Element {
    if (!element_ || (element_ as Node).nodeType !== Node.ELEMENT_NODE) {
      throw new InvalidParameterError(
        "Invalid element: must be a DOM Element.",
      );
    }
    const element = element_ as Element;
    if (!this.#validatedElements.has(element)) {
      const tag = element.tagName.toLowerCase();
      if (["script", "iframe", "object", "embed", "style"].includes(tag)) {
        throw new InvalidParameterError(`Forbidden element tag: <${tag}>`);
      }
      this.#validatedElements.add(element);
    }
    return element;
  }

  /**
   * Safely queries for an element, ensuring it resides within an allowed root container.
   * This is the primary method for secure DOM access.
   * @param selector The CSS selector to query.
   * @param context The DOM context (Element or Document) in which to perform the query.
   * @returns The validated Element, or null if not found or if validation fails.
   */
  public queryElementSafely(
    selector: string,
    context: Document | Element = document,
  ): Element | null {
    try {
      this.validateSelectorSyntax(selector);
      const element = context.querySelector(selector);
      if (!element) return null;

      const rootEls = Array.from(
        this.#resolveAndCacheAllowedRoots().values(),
      ).filter(Boolean) as readonly Element[];

      const isContained = rootEls.some(
        (rootElement) =>
          rootElement === element || rootElement.contains(element),
      );

      if (!isContained) {
        throw new InvalidParameterError(
          `Element targeted by selector is outside allowlisted roots: ${selector}`,
        );
      }

      return this.validateElement(element);
    } catch (error) {
      secureDevelopmentLog(
        "warn",
        "DOMValidator",
        "Element query failed validation",
        {
          selector,
          err: sanitizeErrorForLogs(error),
        },
      );
      return null;
    }
  }
}

/**
 * A default, pre-configured instance of the DOMValidator for convenience.
 * Your application should ideally create and configure its own instance.
 */
export const defaultDOMValidator = new DOMValidator();

/**
 * Factory helper to create a new, independent `DOMValidator` instance with the
 * library's default configuration. Prefer creating your own instance in
 * application code instead of mutating the default singleton.
 */
export function createDefaultDOMValidator(): DOMValidator {
  return new DOMValidator(DEFAULT_CONFIG);
}
