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

import {
  InvalidParameterError,
  InvalidConfigurationError,
  sanitizeErrorForLogs,
} from "./errors";
import { secureDevLog } from "./utils";

/**
 * Configuration for the DOMValidator.
 */
export interface DOMValidatorConfig {
  /** A Set of CSS selectors defining the root elements within which all queries must be contained. */
  allowedRootSelectors: Set<string>;
  /** A Set of selectors that are explicitly forbidden from being in the allowlist (e.g., 'body', 'html'). */
  forbiddenRoots: Set<string>;
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

// Freeze the container object to prevent accidental reassignment of config sets.
// Note: Set contents remain mutable; applications should provide their own
// immutable configs at startup for stricter guarantees.
Object.freeze(DEFAULT_CONFIG);

/**
 * A security-focused class for validating and querying DOM elements.
 */
export class DOMValidator {
  readonly #config: DOMValidatorConfig;
  #validatedElements = new WeakSet<Element>();
  #resolvedRootsCache: Map<string, Element | null> | null = null;

  constructor(config: DOMValidatorConfig = DEFAULT_CONFIG) {
    this.#config = config;
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
  #resolveAndCacheAllowedRoots(): Map<string, Element | null> {
    if (this.#resolvedRootsCache) {
      return this.#resolvedRootsCache;
    }
    const cache = new Map<string, Element | null>();
    for (const selector of this.#config.allowedRootSelectors) {
      // Assuming 'document' is available in the context where this runs.
      cache.set(selector, document.querySelector(selector));
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
    // Check syntax without actually querying the live DOM if possible.
    if (typeof document !== "undefined") {
      try {
        document.createDocumentFragment().querySelector(selector);
      } catch (err) {
        throw new InvalidParameterError(
          `Invalid selector syntax: ${selector}. Reason: ${err instanceof Error ? err.message : String(err)}`,
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
  public validateElement(el: unknown): Element {
    if (!el || (el as Node).nodeType !== Node.ELEMENT_NODE) {
      throw new InvalidParameterError(
        "Invalid element: must be a DOM Element.",
      );
    }
    const element = el as Element;
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
      const el = context.querySelector(selector);
      if (!el) return null;

      const rootEls = Array.from(
        this.#resolveAndCacheAllowedRoots().values(),
      ).filter(Boolean) as Element[];

      const isContained = rootEls.some(
        (rootEl) => rootEl === el || rootEl.contains(el),
      );

      if (!isContained) {
        throw new InvalidParameterError(
          `Element targeted by selector is outside allowlisted roots: ${selector}`,
        );
      }

      return this.validateElement(el);
    } catch (err) {
      secureDevLog("warn", "DOMValidator", "Element query failed validation", {
        selector,
        err: sanitizeErrorForLogs(err),
      });
      return null;
    }
  }
}

/**
 * A default, pre-configured instance of the DOMValidator for convenience.
 * Your application should ideally create and configure its own instance.
 */
export const defaultDOMValidator = new DOMValidator();
