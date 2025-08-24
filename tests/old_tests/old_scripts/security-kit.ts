// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
// Author Website: https://david-osipov.vision
// Author ISNI: 0000 0005 1802 960X
// Author ISNI URL: https://isni.org/isni/000000051802960X
// Author ORCID: 0009-0005-2713-9242
// Author VIAF: 1391726847611590332
// Author Wikidata: Q130604188
// Version: 9.2.0 (Definitive Hardened Version - Post-Expert-Audit)

/**
 * @file This module provides a high-performance, security-hardened animation controller for the main site header.
 * This definitive version is production-ready, incorporating comprehensive expert feedback on semantic validation,
 * cross-realm compatibility, and ultimate error handling robustness. This version has been audited and hardened
 * against common lifecycle, configuration, and context-related vulnerabilities.
 *
 * @summary A security-first animation controller for the main header.
 */

import {
  secureDevLog,
  environment,
  InvalidParameterError,
  InvalidConfigurationError,
  sanitizeErrorForLogs,
} from "../utils/security_kit";

//==============================================================================
// UTILITIES
//==============================================================================

/**
 * A standard, SSR-safe debounce utility function.
 * @summary Creates a debounced function that delays invoking func until after wait milliseconds have elapsed
 * since the last time the debounced function was invoked. The returned function also includes a .cancel() method
 * to clear any pending timeout, which is critical for lifecycle management and preventing memory leaks.
 * @template T The type of the function to debounce.
 * @param func The function to debounce.
 * @param wait The debounce delay in milliseconds.
 * @returns A debounced version of the function with a cancel method.
 */
function debounce<T extends (...args: unknown[]) => void>(
  func: T,
  wait: number,
): ((...args: Parameters<T>) => void) & { cancel: () => void } {
  let timeout: ReturnType<typeof setTimeout> | undefined;

  const executedFunction = function (...args: Parameters<T>) {
    const later = () => {
      timeout = undefined;
      func(...args);
    };
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
    timeout = globalThis.setTimeout(later, wait);
  };

  /**
   * Cancels the pending debounced function call.
   */
  executedFunction.cancel = () => {
    if (timeout !== undefined) {
      clearTimeout(timeout);
      timeout = undefined;
    }
  };

  return executedFunction;
}

//==============================================================================
// TYPE DEFINITIONS & INTERFACES
//==============================================================================

export interface AnimationCapabilities {
  readonly webAnimations: boolean;
  readonly viewTransitions: boolean;
  readonly intersectionObserver: boolean;
  readonly reducedMotion: boolean;
  readonly composite: boolean;
  readonly supportsNegativePlaybackRate: boolean;
  readonly level: "premium" | "enhanced" | "standard" | "fallback";
}

type ExtendedAnimationOptions = KeyframeAnimationOptions & {
  composite?: CompositeOperation;
};

export interface PerformanceMetrics {
  initStart: number;
  initComplete: number;
  animationCount: number;
  errorCount: number;
  initDuration: number;
  animationsActive: number;
  elementsTracked: number;
  capabilities: AnimationCapabilities["level"] | "unknown";
}

//==============================================================================
// CONFIGURATION
//==============================================================================

/**
 * @summary Centralized, immutable configuration for the animator.
 * Freezing the configuration objects prevents runtime tampering, adhering to the
 * Security Constitution's "Secure by Default" principle.
 */
const CONFIG = {
  DEBUG: environment.isDevelopment,
  HEADER_ID: "main-header",
  VIEW_TRANSITION_NAME: "main-header",
  ELEMENT_SELECTORS: {
    navbarContainer: "#navbar-container",
    headerLogo: "#header-logo",
    navbarMenu: "#navbar-menu",
    languageSwitcher: "#language-switcher",
  },
  ANIMATION: {
    DURATION: 300,
    EASING: "cubic-bezier(0.4, 0.0, 0.2, 1)",
    TIMING: "both",
  },
  HOVER: {
    DEBOUNCE_MS: 50,
  },
  SENTINEL: {
    TOP_OFFSET: 50,
    CLASS_NAME: "header-animator-sentinel",
  },
  PERFORMANCE: {
    MAX_ANIMATION_RETRIES: 3,
  },
  SECURITY: {
    MAX_ELEMENTS: 10,
  },
} as const;

Object.freeze(CONFIG);
Object.freeze(CONFIG.ELEMENT_SELECTORS);
Object.freeze(CONFIG.ANIMATION);
Object.freeze(CONFIG.HOVER);
Object.freeze(CONFIG.SENTINEL);
Object.freeze(CONFIG.PERFORMANCE);
Object.freeze(CONFIG.SECURITY);

/**
 * @summary Static animation keyframe definitions.
 * Defined at the module level to prevent re-creation on each class instantiation,
 * improving performance and reducing memory allocations.
 */
const ANIMATION_DEFINITIONS = {
  header: [
    {
      backgroundColor: "rgba(255, 255, 255, 0.1)",
      backdropFilter: "blur(4px)",
      boxShadow: "none",
    },
    {
      backgroundColor: "rgba(238, 229, 233, 0.4)",
      backdropFilter: "blur(12px)",
      boxShadow:
        "0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)",
    },
  ],
  navbarContainer: [
    { paddingTop: "1rem", paddingBottom: "1rem" },
    { paddingTop: "0.25rem", paddingBottom: "0.25rem" },
  ],
  headerLogo: [
    { transform: "scale3d(1, 1, 1)" },
    { transform: "scale3d(0.85, 0.85, 1)" },
  ],
  navbarMenu: [
    { transform: "scale3d(1, 1, 1)" },
    { transform: "scale3d(0.9, 0.9, 1)" },
  ],
  languageSwitcher: [
    { transform: "scale3d(1, 1, 1)" },
    { transform: "scale3d(0.9, 0.9, 1)" },
  ],
} as const;
Object.freeze(ANIMATION_DEFINITIONS);

//==============================================================================
// CAPABILITY DETECTOR
//==============================================================================

/**
 * @summary Detects and caches browser animation capabilities to determine the optimal animation level.
 * This class uses static methods and a private cache for high performance, ensuring detection logic
 * runs only once per page load.
 */
export class CapabilityDetector {
  private static cache: AnimationCapabilities | null = null;

  public static detect(): AnimationCapabilities {
    if (this.cache) {
      return this.cache;
    }

    const capabilities: Omit<AnimationCapabilities, "level"> & {
      level: AnimationCapabilities["level"];
    } = {
      webAnimations: this.testWebAnimations(),
      viewTransitions: this.testViewTransitions(),
      intersectionObserver: this.testIntersectionObserver(),
      reducedMotion: this.testReducedMotion(),
      composite: false,
      supportsNegativePlaybackRate: false,
      level: "fallback",
    };

    // Isolate feature detection that requires DOM manipulation in a try/catch
    // to prevent a single failing test from breaking the entire detection process.
    try {
      capabilities.composite = this._testComposite();
      capabilities.supportsNegativePlaybackRate =
        this._testNegativePlaybackRate();
    } catch (error: unknown) {
      secureDevLog(
        "warn",
        "CapabilityDetector",
        "Advanced capability detection failed",
        { error: sanitizeErrorForLogs(error) },
      );
    }

    if (
      CONFIG.DEBUG &&
      capabilities.webAnimations &&
      !capabilities.supportsNegativePlaybackRate
    ) {
      secureDevLog(
        "info",
        "CapabilityDetector",
        "Negative playbackRate not supported — seek fallback will be used",
        {},
      );
    }

    if (capabilities.viewTransitions && capabilities.webAnimations) {
      capabilities.level = "premium";
    } else if (capabilities.webAnimations && capabilities.composite) {
      capabilities.level = "enhanced";
    } else if (capabilities.webAnimations) {
      capabilities.level = "standard";
    }

    this.cache = Object.freeze(capabilities);

    if (CONFIG.DEBUG) {
      secureDevLog(
        "info",
        "CapabilityDetector",
        "Capabilities detected",
        this.cache,
      );
    }

    return this.cache;
  }

  /**
   * @summary A private helper to safely create, use, and clean up a temporary DOM element for feature detection.
   * This avoids code duplication and ensures robust cleanup, even if the detection callback throws an error.
   * @param callback The function to execute with the temporary element.
   * @returns The result of the callback, or false if the operation fails or is in an SSR environment.
   */
  private static _withTestElement<T>(
    callback: (el: HTMLDivElement) => T,
  ): T | false {
    if (typeof document === "undefined") return false;

    const testEl = document.createElement("div");
    // Move the element off-screen to prevent any visual flicker or layout shifts.
    testEl.style.setProperty("position", "absolute");
    testEl.style.setProperty("left", "-9999px");

    const parent = document.body ?? document.documentElement;
    parent.appendChild(testEl);

    try {
      return callback(testEl);
    } catch {
      return false;
    } finally {
      // Robust cleanup: ensure the element is removed from the DOM.
      if (testEl.parentNode) {
        testEl.parentNode.removeChild(testEl);
      }
    }
  }

  private static testWebAnimations = (): boolean =>
    typeof Element !== "undefined" &&
    typeof Element.prototype.animate === "function";

  private static testViewTransitions = (): boolean => {
    interface DocumentWithViewTransition extends Document {
      startViewTransition(callback: () => unknown): unknown;
    }
    return (
      typeof document !== "undefined" &&
      typeof (document as DocumentWithViewTransition).startViewTransition ===
        "function"
    );
  };

  private static testIntersectionObserver = (): boolean =>
    typeof IntersectionObserver !== "undefined";

  private static testReducedMotion = (): boolean => {
    // Hardened: Wrap in try/catch for environments where matchMedia might be mocked or throw.
    try {
      return (
        typeof window !== "undefined" &&
        !!window.matchMedia &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches
      );
    } catch {
      return false;
    }
  };

  private static _testComposite = (): boolean => {
    if (!this.testWebAnimations()) return false;
    return (
      this._withTestElement((testEl) => {
        const animation = testEl.animate([{ opacity: 0 }, { opacity: 1 }], {
          duration: 1,
          composite: "replace",
        });
        const hasComposite =
          !!animation.effect &&
          typeof (animation.effect as KeyframeEffect).composite !== "undefined";
        animation.cancel();
        return hasComposite;
      }) || false
    );
  };

  private static _testNegativePlaybackRate = (): boolean => {
    if (!this.testWebAnimations()) return false;
    return (
      this._withTestElement((testEl) => {
        const animation = testEl.animate([{ opacity: 0 }, { opacity: 1 }], {
          duration: 1,
        });
        animation.playbackRate = -1;
        animation.cancel();
        return true;
      }) || false
    );
  };
}

//==============================================================================
// ELEMENT VALIDATOR
//==============================================================================

/**
 * @summary Provides safe, allowlist-based DOM querying and validation.
 * This class is a critical security component that prevents selector injection and ensures
 * that the animator can only interact with a predefined, safe subset of the DOM.
 * @note Per audit: This implementation assumes a light DOM context. `document.querySelector`
 * will not find elements within a Shadow DOM root. For such cases, the architecture would
 * need to be adapted to accept direct Element references for roots.
 */
class ElementValidator {
  private static validatedElements = new WeakSet<Element>();
  private static allowedRootSelectors = new Set([
    ...Object.values(CONFIG.ELEMENT_SELECTORS),
    `#${CONFIG.HEADER_ID}`,
  ]);
  private static forbiddenRoots = new Set(["body", "html", "#app", "#root"]);
  private static allowedRootElementsCache: Map<string, Element | null> | null =
    null;

  /**
   * @summary Self-defense mechanism to validate the validator's own configuration.
   * This static block runs once when the class is defined and ensures that the allowedRoots
   * configuration does not contain overly broad selectors, enforcing the Principle of Least Privilege.
   */
  static {
    for (const root of this.allowedRootSelectors) {
      if (this.forbiddenRoots.has(root.toLowerCase())) {
        throw new InvalidConfigurationError(
          `Disallowed broad selector in validator allowlist: "${root}"`,
        );
      }
    }
  }

  /**
   * @private
   * @summary Resolves and caches the DOM Elements corresponding to the allowed root selectors.
   * This is a performance optimization to avoid repeated DOM queries on every validation check.
   * @returns A map of root selectors to their resolved Element (or null if not found).
   */
  private static _resolveAndCacheAllowedRoots(): Map<string, Element | null> {
    if (this.allowedRootElementsCache) {
      return this.allowedRootElementsCache;
    }
    const cache = new Map<string, Element | null>();
    for (const selector of this.allowedRootSelectors) {
      cache.set(selector, document.querySelector(selector));
    }
    this.allowedRootElementsCache = cache;
    return cache;
  }

  /**
   * Performs a basic validation of a CSS selector's syntax and non-emptiness.
   * It does NOT perform semantic validation of where the selector points.
   * @param selector The CSS selector string to validate.
   * @returns The validated selector.
   * @throws {InvalidParameterError} If the selector is invalid.
   * @note Per audit: This is a reasonable syntax-only check but may not catch
   * some context-specific invalid selectors (e.g., certain pseudo-classes).
   */
  public static validateSelectorSyntax(selector: string): string {
    if (typeof selector !== "string" || !selector.trim()) {
      throw new InvalidParameterError(
        "Invalid selector: must be a non-empty string",
      );
    }
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
   * Validates that a given value is a DOM Element using a cross-realm-safe nodeType check.
   * It also rejects forbidden tag names like <script> or <iframe>.
   * @param el The unknown value to validate.
   * @param expectedId An optional ID to match against.
   * @returns The validated DOM Element.
   * @throws {InvalidParameterError} If validation fails.
   */
  public static validateElement(
    el: unknown,
    expectedId?: string | null,
  ): Element {
    if (!el || (el as Node).nodeType !== Node.ELEMENT_NODE) {
      throw new InvalidParameterError("Invalid element: must be a DOM Element");
    }
    const element = el as Element;
    if (expectedId && element.id !== expectedId) {
      throw new InvalidParameterError(
        `Element ID mismatch: expected ${expectedId}, got ${element.id}`,
      );
    }
    if (!this.validatedElements.has(element)) {
      const tag = element.tagName.toLowerCase();
      if (["script", "iframe", "object", "embed"].includes(tag)) {
        throw new InvalidParameterError(`Forbidden element tag: <${tag}>`);
      }
      this.validatedElements.add(element);
    }
    return element;
  }

  /**
   * @summary Safely queries for an element and performs a full semantic validation.
   * This is the primary method for secure DOM access. It ensures that the returned element
   * not only matches the selector within the given context but also resides within one of the
   * globally defined allowedRoots. This prevents security bypasses where a valid selector
   * could target an unintended element in a different part of the DOM.
   * @param selector The CSS selector to query.
   * @param context The DOM context (Element or Document) in which to perform the query.
   * @returns The validated Element, or null if not found or if validation fails.
   */
  public static queryElementSafely(
    selector: string,
    context: Document | Element = document,
  ): Element | null {
    try {
      this.validateSelectorSyntax(selector);
      const el = context.querySelector(selector);
      if (!el) return null;

      // **AUDIT-DRIVEN IMPROVEMENT**: Context-aware containment check.
      // This logic is hardened to correctly handle queries scoped to a specific `context`
      // element, preventing both false positives and negatives.
      const rootEls = Array.from(
        this._resolveAndCacheAllowedRoots().values(),
      ).filter(Boolean) as Element[];

      let isContained = false;
      for (const rootEl of rootEls) {
        // 1. Direct containment: The found element is inside an allowed root.
        if (rootEl === el || rootEl.contains(el)) {
          isContained = true;
          break;
        }
      }

      if (!isContained && context instanceof Element) {
        for (const rootEl of rootEls) {
          // 2. Context containment: The query context itself is inside an allowed root.
          if (rootEl === context || rootEl.contains(context)) {
            isContained = true;
            break;
          }
        }
      }

      if (!isContained) {
        throw new InvalidParameterError(
          `Element targeted by selector is outside allowlisted roots: ${selector}`,
        );
      }

      // If containment is confirmed, perform final element validation.
      return this.validateElement(el);
    } catch (err) {
      secureDevLog(
        "warn",
        "ElementValidator",
        "Element query failed validation",
        { selector, err: sanitizeErrorForLogs(err) },
      );
      return null;
    }
  }
}

//==============================================================================
// ENHANCED HEADER ANIMATOR
//==============================================================================

/**
 * @summary Manages the state and animations for the main site header.
 * This class encapsulates all logic for observing scroll position, handling user interaction,
 * and applying animations in a performant and secure manner.
 */
export class EnhancedHeaderAnimator {
  private readonly header: Element;
  private readonly elements = new Map<string, Element>();
  private readonly animations = new Map<string, Animation>();
  private readonly abortController: AbortController;
  private readonly capabilities: AnimationCapabilities;
  private readonly performanceMetrics: Omit<
    PerformanceMetrics,
    "initDuration" | "animationsActive" | "elementsTracked" | "capabilities"
  > & {
    initStart: number;
    initComplete: number;
  };
  private readonly debouncedMouseLeave: { (): void; cancel(): void };
  private fallbackHandlers: Array<{
    target: EventTarget;
    type: string;
    listener: EventListenerOrEventListenerObject;
    options: AddEventListenerOptions;
  }> = [];
  private sentinelElement: HTMLDivElement | null = null;
  private observer: IntersectionObserver | null = null;
  private isHovering = false;
  private isCompact = false;
  private isDestroyed = false;

  constructor(headerElement: unknown) {
    const now =
      typeof performance !== "undefined" ? performance.now() : Date.now();
    this.performanceMetrics = {
      initStart: now,
      initComplete: 0,
      animationCount: 0,
      errorCount: 0,
    };

    try {
      this.header = ElementValidator.validateElement(
        headerElement,
        CONFIG.HEADER_ID,
      );
      this.abortController = new AbortController();
      this.capabilities = CapabilityDetector.detect();
      this.debouncedMouseLeave = debounce(
        this.performMouseLeaveActions.bind(this),
        CONFIG.HOVER.DEBOUNCE_MS,
      );

      if (CONFIG.DEBUG) {
        secureDevLog("info", "EnhancedHeaderAnimator", "Initializing", {
          capabilities: this.capabilities,
        });
      }

      if (this.capabilities.reducedMotion) {
        this.handleReducedMotion();
      } else if (this.checkPrerequisites()) {
        this.initialize();
      } else {
        this.handleFallback();
      }

      const end =
        typeof performance !== "undefined" ? performance.now() : Date.now();
      this.performanceMetrics.initComplete = end;

      if (CONFIG.DEBUG) {
        const initTime =
          this.performanceMetrics.initComplete -
          this.performanceMetrics.initStart;
        secureDevLog(
          "info",
          "EnhancedHeaderAnimator",
          "Initialization complete",
          {
            initTime: `${initTime.toFixed(2)}ms`,
            level: this.capabilities.level,
          },
        );
      }
    } catch (error: unknown) {
      this.handleError("Initialization failed catastrophically", error);
      try {
        this.handleFallback();
      } catch (fallbackError) {
        secureDevLog(
          "error",
          "EnhancedHeaderAnimator",
          "handleFallback failed during catastrophic error recovery",
          { error: sanitizeErrorForLogs(fallbackError) },
        );
      }
    }
  }

  /**
   * @summary Plays or seeks an animation to its target state, handling browser inconsistencies.
   * This method includes a proactive check for animation.ready to prevent race conditions
   * and uses the most performant method available (negative playback rate) for reversing animations.
   * @param animation The Web Animation object to control.
   * @param toCompact true to animate to the compact state, false to the expanded state.
   */
  private playOrSeekAnimation(animation: Animation, toCompact: boolean): void {
    const maybeReady = (animation as Animation & { ready?: Promise<Animation> })
      .ready;
    if (maybeReady && typeof maybeReady.then === "function") {
      maybeReady.catch(() => {});
    }

    const duration = Number(animation.effect?.getTiming().duration ?? 0);

    const seekToEndState = () => {
      try {
        animation.currentTime = toCompact ? duration : 0;
        animation.pause();
      } catch (seekErr) {
        this.handleError("Catastrophic animation seek failure", seekErr);
      }
    };

    if (this.capabilities.supportsNegativePlaybackRate && duration > 0) {
      try {
        animation.playbackRate = toCompact ? 1 : -1;
        animation.currentTime = toCompact ? 0 : duration;
        animation.play();
      } catch (err: unknown) {
        this.handleError(
          "playOrSeekAnimation playback failed, falling back to seek",
          err,
        );
        seekToEndState();
      }
    } else {
      seekToEndState();
    }
  }

  private handleReducedMotion(): void {
    this.header.classList.add("reduced-motion");
    this.header.setAttribute("data-animation-disabled", "reduced-motion");
  }

  private handleFallback(): void {
    this.header.classList.add("js-animation-fallback");
    this.header.setAttribute("data-animation-disabled", "api-unavailable");
  }

  private checkPrerequisites = (): boolean =>
    this.capabilities.webAnimations && this.capabilities.intersectionObserver;

  private initialize(): void {
    try {
      this.setupElements();
      this.setupViewTransitions();
      this.createAnimations();
      this.setupIntersectionObserver();
      this.attachEventListeners();
      this.header.setAttribute("data-animation-ready", "true");
    } catch (error) {
      this.handleError("Core initialization sequence failed", error);
      this.handleFallback();
    }
  }

  private setupElements(): void {
    const elementCount = Object.keys(CONFIG.ELEMENT_SELECTORS).length;
    if (elementCount > CONFIG.SECURITY.MAX_ELEMENTS) {
      throw new InvalidParameterError(
        `Too many elements configured: ${elementCount} > ${CONFIG.SECURITY.MAX_ELEMENTS}`,
      );
    }
    for (const [key, selector] of Object.entries(CONFIG.ELEMENT_SELECTORS)) {
      const element = ElementValidator.queryElementSafely(
        selector,
        this.header,
      );
      if (element) this.elements.set(key, element);
    }
  }

  private setupViewTransitions(): void {
    if (
      this.capabilities.viewTransitions &&
      this.header instanceof HTMLElement
    ) {
      this.header.style.setProperty(
        "view-transition-name",
        CONFIG.VIEW_TRANSITION_NAME,
      );
    }
  }

  private createAnimations(): void {
    const baseOptions: ExtendedAnimationOptions = {
      duration: CONFIG.ANIMATION.DURATION,
      fill: CONFIG.ANIMATION.TIMING,
      easing: CONFIG.ANIMATION.EASING,
      composite: this.capabilities.composite ? "replace" : undefined,
    };

    try {
      const headerAnimation = this.header.animate(
        ANIMATION_DEFINITIONS.header,
        baseOptions,
      );
      headerAnimation.pause();
      this.animations.set("header", headerAnimation);

      for (const [key, keyframes] of Object.entries(ANIMATION_DEFINITIONS)) {
        if (key === "header") continue;
        const element = this.elements.get(key);
        if (element) {
          const animation = element.animate(keyframes, baseOptions);
          animation.pause();
          this.animations.set(key, animation);
        }
      }
    } catch (error: unknown) {
      this.handleError("Animation creation failed", error);
      this.handleFallback();
    }
  }

  private setupIntersectionObserver(): void {
    this.sentinelElement = document.createElement("div");
    this.sentinelElement.className = CONFIG.SENTINEL.CLASS_NAME;
    this.sentinelElement.setAttribute("aria-hidden", "true");
    const style = this.sentinelElement.style;
    style.setProperty("position", "absolute");
    style.setProperty("top", `${CONFIG.SENTINEL.TOP_OFFSET}px`);
    style.setProperty("height", "1px");
    style.setProperty("width", "1px");

    const body = document.body ?? document.documentElement;
    body.insertBefore(this.sentinelElement, body.firstChild);

    const observerCallback: IntersectionObserverCallback = (entries) => {
      if (this.isDestroyed) return;
      window.requestAnimationFrame(() => {
        if (this.isDestroyed) return;
        try {
          for (const entry of entries) {
            const wasCompact = this.isCompact;
            this.isCompact = !entry.isIntersecting;
            if (wasCompact !== this.isCompact) this.updateAnimationState();
          }
        } catch (error: unknown) {
          this.handleError("Observer callback failed", error);
        }
      });
    };

    this.observer = new IntersectionObserver(observerCallback, {
      threshold: 0,
      rootMargin: "0px",
    });
    this.observer.observe(this.sentinelElement);
    this.setInitialState();
  }

  private setInitialState(): void {
    if (!this.sentinelElement || this.isDestroyed) return;
    window.requestAnimationFrame(() => {
      if (this.isDestroyed || !this.sentinelElement) return;
      try {
        const rect = this.sentinelElement.getBoundingClientRect();
        this.isCompact = rect.top < 0;
        for (const animation of this.animations.values()) {
          const duration = animation.effect?.getTiming().duration ?? 0;
          animation.currentTime = this.isCompact ? Number(duration) : 0;
          animation.pause();
        }
      } catch (error: unknown) {
        this.handleError("Setting initial state failed", error);
      }
    });
  }

  private safeAddEventListener(
    target: EventTarget,
    type: string,
    listener: EventListenerOrEventListenerObject,
  ): void {
    const options: AddEventListenerOptions = { passive: true };
    try {
      options.signal = this.abortController.signal;
      target.addEventListener(type, listener, options);
    } catch (e) {
      delete options.signal;
      target.addEventListener(type, listener, options);
      this.fallbackHandlers.push({
        target,
        type,
        listener,
        options: { ...options },
      });
    }
  }

  private attachEventListeners(): void {
    this.safeAddEventListener(this.header, "mouseenter", this.handleMouseEnter);
    this.safeAddEventListener(this.header, "mouseleave", this.handleMouseLeave);
    this.safeAddEventListener(
      document,
      "visibilitychange",
      this.handleVisibilityChange,
    );
  }

  private updateAnimationState(): void {
    if (this.isDestroyed || (this.isHovering && this.isCompact)) return;
    try {
      for (const animation of this.animations.values()) {
        this.playOrSeekAnimation(animation, this.isCompact);
      }
      this.performanceMetrics.animationCount++;
    } catch (error: unknown) {
      this.handleError("Animation state update failed", error);
    }
  }

  private handleMouseEnter = (): void => {
    if (this.isDestroyed || !this.isCompact) return;
    this.isHovering = true;
    try {
      for (const animation of this.animations.values())
        this.playOrSeekAnimation(animation, false);
    } catch (error: unknown) {
      this.handleError("Mouse enter handler failed", error);
    }
  };

  private handleMouseLeave = (): void => {
    if (this.isDestroyed || !this.isCompact) return;
    this.isHovering = false;
    this.debouncedMouseLeave();
  };

  private performMouseLeaveActions(): void {
    if (!this.isHovering && !this.isDestroyed && this.isCompact) {
      try {
        for (const animation of this.animations.values())
          this.playOrSeekAnimation(animation, true);
      } catch (error: unknown) {
        this.handleError("Debounced mouse leave handler failed", error);
      }
    }
  }

  private handleVisibilityChange = (): void => {
    if (document.hidden && !this.isDestroyed) {
      for (const animation of this.animations.values()) {
        if (animation.playState === "running") animation.pause();
      }
    }
  };

  /**
   * @summary Centralized error handler with a circuit breaker.
   * Implements the "Fail Loudly, Fail Safely" principle. If too many errors occur,
   * it will automatically destroy the animator instance to prevent further issues.
   */
  private handleError(message: string, error: unknown): void {
    this.performanceMetrics.errorCount++;
    secureDevLog("error", "EnhancedHeaderAnimator", message, {
      error: sanitizeErrorForLogs(error),
      state: { isCompact: this.isCompact, isHovering: this.isHovering },
    });

    if (
      this.performanceMetrics.errorCount >
      CONFIG.PERFORMANCE.MAX_ANIMATION_RETRIES
    ) {
      secureDevLog(
        "error",
        "EnhancedHeaderAnimator",
        "Exceeded max retries, destroying instance.",
        {},
      );
      try {
        this.destroy();
      } catch (destroyError) {
        secureDevLog(
          "error",
          "EnhancedHeaderAnimator",
          "destroy() failed during error-driven self-destruction",
          { error: sanitizeErrorForLogs(destroyError) },
        );
      }
    }
  }

  public getMetrics(): PerformanceMetrics {
    return {
      ...this.performanceMetrics,
      initDuration:
        this.performanceMetrics.initComplete -
        this.performanceMetrics.initStart,
      animationsActive: this.animations.size,
      elementsTracked: this.elements.size,
      capabilities: this.capabilities?.level ?? "unknown",
    };
  }

  /**
   * @summary Safely tears down all resources, listeners, and observers.
   * This method is critical for preventing memory leaks in Single-Page Applications.
   */
  public destroy(): void {
    if (this.isDestroyed) return;
    this.isDestroyed = true;

    try {
      this.debouncedMouseLeave.cancel();
      this.abortController.abort();

      for (const h of this.fallbackHandlers) {
        h.target.removeEventListener(h.type, h.listener, h.options);
      }
      this.fallbackHandlers.length = 0;

      this.observer?.disconnect();
      this.animations.forEach((animation) => animation.cancel());
      this.sentinelElement?.remove();

      this.animations.clear();
      this.elements.clear();

      if (CONFIG.DEBUG) {
        secureDevLog(
          "info",
          "EnhancedHeaderAnimator",
          "Destroyed successfully",
          this.getMetrics(),
        );
      }
    } catch (error: unknown) {
      secureDevLog("error", "EnhancedHeaderAnimator", "Destruction failed", {
        error: sanitizeErrorForLogs(error),
      });
    }
  }
}

//==============================================================================
// INITIALIZATION MANAGER
//==============================================================================

/**
 * @summary A singleton manager to handle the lifecycle of the EnhancedHeaderAnimator.
 */
export class HeaderAnimationManager {
  private static instance: EnhancedHeaderAnimator | null = null;

  public static initialize(): void {
    try {
      if (this.instance) {
        this.instance.destroy();
        this.instance = null;
      }

      const header = ElementValidator.queryElementSafely(
        `#${CONFIG.HEADER_ID}`,
      );
      if (!header) {
        if (CONFIG.DEBUG)
          secureDevLog(
            "warn",
            "HeaderAnimationManager",
            `Header not found: #${CONFIG.HEADER_ID}`,
            {},
          );
        return;
      }

      this.instance = new EnhancedHeaderAnimator(header);
    } catch (error: unknown) {
      secureDevLog("error", "HeaderAnimationManager", "Initialization failed", {
        error: sanitizeErrorForLogs(error),
      });
      this.instance = null;
      const header = document.getElementById(CONFIG.HEADER_ID);
      if (header) {
        header.classList.add("js-animation-failed");
        header.setAttribute("data-animation-disabled", "error");
      }
    }
  }

  public static destroy(): void {
    if (this.instance) {
      this.instance.destroy();
      this.instance = null;
    }
  }

  public static getInstance(): EnhancedHeaderAnimator | null {
    return this.instance;
  }
}

//==============================================================================
// SECURE INITIALIZATION
//==============================================================================

/**
 * A unique, non-colliding symbol to act as a global guard, ensuring that the
 * initialization listeners are attached only once.
 * @see Security Constitution: "RULE: Idempotent Initialization (MUST)"
 * @note Per audit: This guard is per-window/realm. It does not provide
 * cross-frame single-instance semantics, which is the intended behavior here.
 */
const INITIALIZATION_KEY = Symbol.for(
  "dev.david-osipov.HeaderAnimatorInitialized",
);

/**
 * This function safely initializes the HeaderAnimationManager.
 */
function safeInitialize(): void {
  HeaderAnimationManager.destroy();
  HeaderAnimationManager.initialize();
}

if (typeof document !== "undefined" && typeof window !== "undefined") {
  // Idempotency Guard: Prevents memory leaks and duplicate handlers in HMR/SPA environments.
  if (!(window as any)[INITIALIZATION_KEY]) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", safeInitialize, {
        once: true,
      });
    } else {
      safeInitialize();
    }

    document.addEventListener("astro:page-load", safeInitialize);
    window.addEventListener(
      "beforeunload",
      () => HeaderAnimationManager.destroy(),
      { once: true },
    );

    Object.defineProperty(window, INITIALIZATION_KEY, {
      value: true,
      writable: false,
      configurable: true,
    });
  }
}

export default HeaderAnimationManager;
