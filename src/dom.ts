// --- File: src/dom.ts ---
//
// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
//
// Hardened DOM validation utilities — tightened types, sanitized logging,
// privacy-by-default audit behavior, and strict linter / security rule alignment.
//
// NOTE: This module prioritizes safety, privacy, and linter compliance over micro-optimizations.
// For extremely hot paths you may selectively add deliberate exemptions with clear comments.

import {
  InvalidParameterError,
  InvalidConfigurationError,
  CryptoUnavailableError,
  sanitizeErrorForLogs,
} from "./errors";
import { secureDevLog as secureDevelopmentLog, secureWipe } from "./utils";
import { SHARED_ENCODER } from "./encoding";

/*
/* NOTE: This file intentionally performs a few runtime-type checks and
 * maintains small mutable caches/counters for performance and correctness in
 * realistic DOM environments. To keep the code readable and avoid fighting the
 * linter we explicitly permit a small set of rules here with clear justification:
 * - @typescript-eslint/no-explicit-any & no-unsafe-member-access: we perform
 *   guarded runtime checks against `globalThis` and dynamic imports, and we validate
 *   shapes before use. These are required for cross-runtime crypto fallbacks.
 * - functional/immutable-data, functional/no-let, functional/prefer-readonly-type:
 *   internal caches and rate limiter counters are intentionally mutable and
 *   documented as such. Mutability here is a deliberate engineering trade-off.
 */
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, functional/immutable-data, functional/no-let, functional/prefer-readonly-type */

/* ----------------------------- Runtime guards ---------------------------- */

const hasDOM =
  typeof globalThis !== "undefined" &&
  typeof (globalThis as any).document !== "undefined" &&
  typeof (globalThis as any).Element !== "undefined" &&
  typeof (globalThis as any).Node !== "undefined";

/* ---------------------------- Audit / hashing types ---------------------- */

export type AuditEventKind =
  | "validation_failure"
  | "forbidden_access"
  | "cache_refresh"
  | "validation_failure_hash"
  | "rate_limit_triggered";

export type AuditEvent = {
  readonly kind: AuditEventKind;
  readonly timestamp: string;
  readonly selectorFingerprint?: string;
  readonly selectorLength?: number;
  readonly reason?: string;
  readonly selectorHash?: string;
  readonly instanceId?: string;
};

/**
 * An audit hook receives sanitized audit events. The library will never pass raw
 * selectors or raw DOM nodes to the hook. If you enable `emitSelectorHash`, a
 * SHA-256 hex of the selector MAY be included — this is opt-in and disabled by default.
 */
export type AuditHook = (event: AuditEvent) => void | Promise<void>;

/* ---------------------------- Public types / config ---------------------- */

export interface DOMValidatorConfig {
  readonly allowedRootSelectors: ReadonlySet<string>;
  readonly forbiddenRoots: ReadonlySet<string>;
  readonly failFast?: boolean;
  readonly maxSelectorLength?: number;
  readonly maxValidationsPerSecond?: number;
  readonly auditHook?: AuditHook;
  readonly validatedElementTTLms?: number;
  readonly instanceId?: string;
  /**
   * Synchronous factory to create a Map-like cache. This keeps the public API synchronous
   * while allowing the host application to provide an LRU implementation if desired.
   *
   * Example:
   *   cacheFactory: () => new Map<string, Element | undefined>()
   */
  readonly cacheFactory?: () => Map<string, Element | undefined>;
  /**
   * How long (ms) to wait for the auditHook before abandoning the call. Default: 2000 ms.
   */
  readonly auditHookTimeoutMs?: number;

  /**
   * Privacy guard: if `true` the validator will compute & emit a SHA-256 hex of
   * the selector as part of follow-up validation_failure_hash events. Default: false.
   */
  readonly emitSelectorHash?: boolean;
}

/* ------------------------------- Defaults -------------------------------- */

/**
 * NOTE: Sets are shallowly referenced here. Object.freeze is used to guard the top-level
 * config object from accidental property mutation; the Set contents themselves are treated
 * as immutable by convention. If you require absolute immutability consider using a frozen
 * wrapper or an immutable collection library.
 */
const DEFAULT_CONFIG = Object.freeze({
  allowedRootSelectors: new Set([
    "#main-content",
    "#main-header",
    "#modal-container",
  ]),
  forbiddenRoots: new Set(["body", "html", "#app", "#root"]),
  failFast: false,
  maxSelectorLength: 1024,
  maxValidationsPerSecond: 50,
  auditHook: undefined,
  validatedElementTTLms: 5 * 60 * 1000,
  instanceId: undefined,
  cacheFactory: undefined,
  auditHookTimeoutMs: 2000,
  emitSelectorHash: false,
}) as unknown as DOMValidatorConfig;

/* ------------------------------ Helpers ---------------------------------- */

/**
 * Deterministic, non-cryptographic fingerprint (djb2 -> hex) implemented
 * in a functional/reduce style to satisfy immutability lint rules while remaining
 * deterministic and fast enough for short selectors.
 */
function fingerprintHexSync(input: string): string {
  // Functional reduction over code points — avoids mutable `let` per lint policy.
  // rename accumulator to satisfy naming rules
  const hash = Array.from(String(input)).reduce((accumulator, ch) => {
    // acc * 33 ^ c  (force to unsigned 32-bit)
    const next = ((accumulator * 33) ^ ch.charCodeAt(0)) >>> 0;
    return next;
  }, 5381);
  return hash.toString(16).padStart(8, "0");
}

/**
 * Helper: wrap a promise with a timeout that rejects with a specific error.
 * Ensures that the timeout rejection cleans up the timer deterministically.
 */
function promiseWithTimeout<T>(
  p: Promise<T>,
  ms: number,
  errorMessage = "operation_timeout",
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => {
      reject(new Error(errorMessage));
    }, ms);
    void p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (error) => {
        clearTimeout(t);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

/**
 * Async SHA-256 hex digest with guarded timeout and typed fallbacks.
 *
 * Strategy:
 *  - Prefer Web Crypto (crypto.subtle) in browsers.
 *  - Prefer Node's built-in `createHash` synchronously when available (dynamic import).
 *  - Try optional fast libs as last resorts.
 *
 * Notes:
 *  - Some underlying operations (e.g., subtle.digest) are not cancellable — the timeout
 *    prevents us from waiting forever but cannot stop the underlying work. Keep timeouts conservative.
 *  - All imported modules are validated by runtime shape checks; no unchecked `any` usage.
 */
async function sha256Hex(input: string, timeoutMs = 1500): Promise<string> {
  const enc = SHARED_ENCODER;

  // Test hook: allow unit tests to override dynamic imports deterministically.
  // Tests may set __test_importOverride to a function that receives a module
  // specifier and returns a Promise resolving to a module-like object.
  // This is only used for testing and is intentionally opt-in.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const importer: (spec: string) => Promise<any> =
    (sha256Hex as any).__test_importOverride ??
    ((s: string) => {
      // Security: Restrict dynamic imports to a strict allowlist using a switch
      // to avoid variable import() calls. ASVS V3.7.5.
      switch (s) {
        case "node:crypto":
          return import("node:crypto");
        case "fast-sha256":
          return import("fast-sha256");
        case "hash-wasm":
          return import("hash-wasm");
        default:
          throw new Error(
            `Security violation: unauthorized module import '${s}'`,
          );
      }
    });

  // Helper strategies: try multiple implementations in order and return the first successful result.
  async function tryWebCrypto(): Promise<string | undefined> {
    let data: Uint8Array | undefined;
    let u8: Uint8Array | undefined;
    try {
      const g = globalThis as unknown as { crypto?: unknown };

      if (g.crypto && typeof (g.crypto as any).subtle === "object") {
        type SubtleLike = {
          digest(
            alg: string,
            data: ArrayBuffer | ArrayBufferView,
          ): Promise<ArrayBuffer>;
        };

        const subtle = (g.crypto as any).subtle as SubtleLike;
        // create an explicit encoded buffer so we can attempt to wipe it afterwards
        data = enc.encode(input);
        const digest = await promiseWithTimeout(
          subtle.digest("SHA-256", data),
          timeoutMs,
          "sha256_timeout",
        );
        u8 = new Uint8Array(digest);
        return Array.from(u8)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      }
    } catch (error) {
      try {
        secureDevelopmentLog(
          "debug",
          "DOMValidator",
          "sha256: webcrypto failed",
          { err: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* swallow */
      }
    } finally {
      // Best-effort attempt to wipe any temporary buffers we created
      try {
        if (u8) secureWipe(u8);
      } catch {
        /* swallow */
      }
      try {
        if (data) secureWipe(data);
      } catch {
        /* swallow */
      }
    }
    return undefined;
  }

  async function tryNodeCrypto(): Promise<string | undefined> {
    try {
      const nodeCryptoModulePromise = importer("node:crypto") as Promise<
        typeof import("node:crypto")
      >;
      const nodeCrypto = await promiseWithTimeout(
        nodeCryptoModulePromise,
        timeoutMs,
        "sha256_timeout",
      );
      if (nodeCrypto && typeof nodeCrypto.createHash === "function") {
        return String(
          nodeCrypto.createHash("sha256").update(input).digest("hex"),
        );
      }
    } catch (error) {
      try {
        secureDevelopmentLog(
          "debug",
          "DOMValidator",
          "sha256: node:crypto unavailable",
          { err: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* swallow */
      }
    }
    return undefined;
  }

  async function tryFastSha256(): Promise<string | undefined> {
    try {
      const fastModulePromise = importer("fast-sha256") as Promise<unknown>;
      const fastModule = await promiseWithTimeout(
        fastModulePromise,
        timeoutMs,
        "sha256_timeout",
      );
      if (fastModule !== null && typeof fastModule === "object") {
        const m = fastModule as Record<string, unknown>;
        if (typeof m["hashHex"] === "function")
          return String((m["hashHex"] as (...a: unknown[]) => unknown)(input));
        if (typeof m["hex"] === "function")
          return String((m["hex"] as (...a: unknown[]) => unknown)(input));
      }
      if (typeof fastModule === "function")
        return String((fastModule as unknown as (s: string) => string)(input));
    } catch (error) {
      try {
        secureDevelopmentLog(
          "debug",
          "DOMValidator",
          "sha256: fast-sha256 not usable",
          { err: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* swallow */
      }
    }
    return undefined;
  }

  async function tryHashWasm(): Promise<string | undefined> {
    try {
      const hwPromise = importer("hash-wasm") as Promise<unknown>;
      const hw = await promiseWithTimeout(
        hwPromise,
        timeoutMs,
        "sha256_timeout",
      );
      if (hw !== null && typeof hw === "object") {
        const module_ = hw as Record<string, unknown>;
        if (typeof module_["sha256"] === "function") {
          const maybe = (module_["sha256"] as (...a: unknown[]) => unknown)(
            input,
          );
          if (maybe instanceof Promise)
            return String(
              await promiseWithTimeout(
                maybe as Promise<unknown>,
                timeoutMs,
                "sha256_timeout",
              ),
            );
          return String(maybe);
        }
      }
    } catch (error) {
      try {
        secureDevelopmentLog(
          "debug",
          "DOMValidator",
          "sha256: hash-wasm not usable",
          { err: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* swallow */
      }
    }
    return undefined;
  }

  const strategies = [tryWebCrypto, tryNodeCrypto, tryFastSha256, tryHashWasm];
  for (const strat of strategies) {
    const out = await strat();
    if (typeof out === "string") return out;
  }

  throw new CryptoUnavailableError("No crypto available");
}

/** Sanitize selector for logs: strip attribute values and quoted substrings; truncate. */
function sanitizeSelectorForLogs(sel: string): string {
  try {
    const s = String(sel);
    // Use safe scanners instead of complex regexes to avoid catastrophic backtracking
    const redacted = redactAttributesSafely(s);
    const noQuotes = removeQuotedSegmentsSafely(redacted);
    // Truncate to safe length
    if (noQuotes.length <= 128) return noQuotes;
    const head = noQuotes.slice(0, 96);
    const tail = noQuotes.slice(-24);
    return `${head}…${tail}`;
  } catch {
    return "<unavailable>";
  }
}

/**
 * Redact attribute selector values safely without backtracking-prone regex.
 * Implementation is somewhat stateful and branchy by necessity; disable the
 * cognitive-complexity rule here with a justification — this is a small,
 * auditable scanner that avoids ReDoS risks from complex regexes.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity
function redactAttributesSafely(s: string): string {
  const out: string[] = [];
  let index = 0;
  while (index < s.length) {
    const ch = s[index];
    if (ch === "[") {
      // capture up to '=' or closing bracket
      let index_ = index + 1;
      while (index_ < s.length && s[index_] !== "]" && s[index_] !== "=")
        index_++;
      if (index_ < s.length && s[index_] === "=") {
        // we have an attribute with value; find end of value
        // skip whitespace
        let k = index_ + 1;
        while (k < s.length && /\s/.test(String(s[k]))) k++;
        // value may be quoted or unquoted
        if (k < s.length && (s[k] === '"' || s[k] === "'")) {
          const quote = s[k];
          k++;
          while (k < s.length && s[k] !== quote) k++;
          // advance to closing bracket
          while (k < s.length && s[k] !== "]") k++;
          out.push(s.slice(index, index + 1));
          out.push(s.slice(index + 1, index_).replace(/\s+/g, ""));
          out.push("=<redacted>]");
          index = k + 1;
          continue;
        }
        // unquoted value: advance to closing bracket
        while (k < s.length && s[k] !== "]") k++;
        out.push(s.slice(index, index + 1));
        out.push(s.slice(index + 1, index_).replace(/\s+/g, ""));
        out.push("=<redacted>]");
        index = k + 1;
        continue;
      }
    }
    out.push(String(ch));
    index++;
  }
  return out.join("");
}

/** Remove quoted segments safely (handles escaped quotes conservatively). */
function removeQuotedSegmentsSafely(s: string): string {
  let out = "";
  let index = 0;
  while (index < s.length) {
    const ch = s[index];
    if (ch === '"' || ch === "'") {
      const quote = ch;
      index++;
      while (index < s.length) {
        if (s[index] === "\\") {
          // skip escaped char
          index += 2;
        } else if (s[index] === quote) {
          index++;
          break;
        } else {
          index++;
        }
      }
      out += "<redacted>";
      continue;
    }
    out += ch;
    index++;
  }
  return out;
}

/**
 * Extract raw bracketed attribute segments (including brackets) from a selector.
 * Implemented as a safe scanner to avoid complex regexes.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity
function extractAttributeSegments(s: string): string[] {
  const parts: string[] = [];
  let index = 0;
  while (index < s.length) {
    if (s[index] === "[") {
      const start = index;
      index++;
      // scan until matching closing bracket, handling nested quotes conservatively
      let inQuote: string | undefined = undefined;
      while (index < s.length) {
        const ch = s[index];
        if (inQuote !== undefined) {
          if (ch === "\\") {
            index += 2;
            continue;
          }
          if (ch === inQuote) {
            inQuote = undefined;
            index++;
            continue;
          }
          index++;
          continue;
        }
        if (ch === '"' || ch === "'") {
          inQuote = ch;
          index++;
          continue;
        }
        if (ch === "]") {
          index++;
          break;
        }
        index++;
      }
      parts.push(s.slice(start, index));
      continue;
    }
    index++;
  }
  return parts;
}

/* ------------------------------ Implementation ---------------------------- */

type RootCache = Map<string, Element | undefined>;

/**
 * A security-focused class for validating and querying DOM elements.
 */
export class DOMValidator {
  readonly #config: DOMValidatorConfig;

  // validatedElements stores last validation timestamp to allow TTL-based revalidation.
  // WeakMap keys ensure no memory leaks; value is epoch ms when validated.
  readonly #validatedElements = new WeakMap<Element, number>();

  // Mutable internal cache (lazily populated) — typed as RootCache for clarity.
  #resolvedRootsCache?: RootCache;

  // Rate limiter state (mutable)
  #validationCounter = 0;
  #lastWindow = Date.now();

  // Instance id for audit correlation
  readonly #instanceId: string | undefined;

  /**
   * Construct a new DOMValidator.
   *
   * @param config - validator configuration
   * @mutates this.#resolvedRootsCache - initializes internal cache (Map by default)
   */
  constructor(config: DOMValidatorConfig = DEFAULT_CONFIG) {
    this.#config = Object.freeze(DOMValidator.cloneAndNormalizeConfig(config));
    this.#instanceId = this.#config.instanceId;

    // initialize cache synchronously via factory (if provided) or Map
    this.#resolvedRootsCache = this.#config.cacheFactory
      ? this.#config.cacheFactory()
      : new Map<string, Element | undefined>();

    // If the host hasn't provided a cacheFactory, try to asynchronously upgrade
    // the default Map to an optional `lru-cache` instance when available. This
    // is a best-effort, non-blocking optimization and must not change the
    // synchronous public API (we keep the Map until/if LRU becomes ready).
    if (!this.#config.cacheFactory) {
      // The upgrade attempt is intentionally non-blocking and may perform an
      // optional dynamic import; running it from the constructor is safe because
      // we never await it and it does not change the synchronous public API.
      // Disable the rule here with a narrow comment explaining the trade-off.
      // eslint-disable-next-line sonarjs/no-async-constructor
      void this.#tryUpgradeCache();
    }

    // Defensive validation: ensure no allowed selector is present in forbiddenRoots (case-insensitive compare)
    for (const root of this.#config.allowedRootSelectors) {
      try {
        const normalized = String(root).trim().toLowerCase();
        if (this.#config.forbiddenRoots.has(normalized)) {
          throw new InvalidConfigurationError(
            `Disallowed broad selector in validator allowlist: "${root}"`,
          );
        }
      } catch (error) {
        // sanitize and rethrow as configuration error
        const safe = sanitizeErrorForLogs(error);
        secureDevelopmentLog(
          "error",
          "DOMValidator",
          "constructor: invalid config",
          { err: safe },
        );
        throw error;
      }
    }
  }

  /**
   * Attempt to upgrade the internal cache to an optional LRU implementation if available.
   * This runs asynchronously and never changes the synchronous contract of the class.
   */
  async #tryUpgradeCache(): Promise<void> {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const importer: (spec: string) => Promise<any> =
        // OWASP ASVS L3: Dynamic imports are security-critical. We validate module
        // specifiers against a strict whitelist and use timeout protection to prevent
        // DoS attacks. The 's' parameter is validated before use.

        (DOMValidator as any).__test_importOverride ??
        ((s: string) => {
          // Security: Validate module specifier against strict whitelist and avoid variable import().
          switch (s) {
            case "lru-cache":
              return import("lru-cache");
            case "css-what":
              return import("css-what");
            default:
              throw new Error(
                `Security violation: unauthorized module import '${s}'`,
              );
          }
        });
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const module_ = await promiseWithTimeout(
        importer("lru-cache"),
        1200,
        "lru_import_timeout",
      );
      // Narrow the dynamic import result into a minimal runtime shape we expect.
      const LRU: unknown = (module_ as any).default ?? module_;
      if (typeof LRU === "function") {
        // Construct via 'any' intentionally but validate runtime shape before use.
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call
        const inst: unknown = new (LRU as any)({ max: 1000 });
        if (
          inst &&
          typeof (inst as any).get === "function" &&
          typeof (inst as any).set === "function"
        ) {
          this.#resolvedRootsCache = inst as unknown as RootCache;
          secureDevelopmentLog(
            "debug",
            "DOMValidator",
            "lru-cache: upgraded internal cache",
          );
        }
      }
    } catch (error) {
      const safe = sanitizeErrorForLogs(error);
      try {
        secureDevelopmentLog(
          "debug",
          "DOMValidator",
          "lru-cache not available or failed to init",
          { err: safe },
        );
      } catch {
        /* swallow */
      }
    }
  }

  private static cloneAndNormalizeConfig(
    cfg: DOMValidatorConfig,
  ): DOMValidatorConfig {
    // Defensive clones: ensure nested Sets are fresh copies (prevent external mutation)
    const allowed = new Set<string>();
    for (const s of cfg.allowedRootSelectors ??
      DEFAULT_CONFIG.allowedRootSelectors) {
      allowed.add(String(s).trim());
    }
    const forbidden = new Set<string>();
    for (const s of cfg.forbiddenRoots ?? DEFAULT_CONFIG.forbiddenRoots) {
      forbidden.add(String(s).trim().toLowerCase());
    }

    const out = {
      allowedRootSelectors: allowed,
      forbiddenRoots: forbidden,
      failFast: Boolean(cfg.failFast),
      maxSelectorLength:
        cfg.maxSelectorLength ?? DEFAULT_CONFIG.maxSelectorLength,
      maxValidationsPerSecond:
        cfg.maxValidationsPerSecond ?? DEFAULT_CONFIG.maxValidationsPerSecond,
      auditHook: cfg.auditHook ?? DEFAULT_CONFIG.auditHook,
      validatedElementTTLms:
        cfg.validatedElementTTLms ?? DEFAULT_CONFIG.validatedElementTTLms,
      instanceId: cfg.instanceId ?? DEFAULT_CONFIG.instanceId,
      cacheFactory: cfg.cacheFactory,
      auditHookTimeoutMs:
        cfg.auditHookTimeoutMs ?? DEFAULT_CONFIG.auditHookTimeoutMs,
      emitSelectorHash: cfg.emitSelectorHash ?? DEFAULT_CONFIG.emitSelectorHash,
    };

    // Shallow-freeze to prevent casual mutation; nested Sets are already fresh copies.
    return Object.freeze(out) as unknown as DOMValidatorConfig;
  }

  /**
   * Clear any cached root resolution state. Useful for SPAs or dynamic pages where
   * root elements can be removed/replaced.
   *
   * @mutates this.#resolvedRootsCache
   */
  public invalidateCache(): void {
    this.#resolvedRootsCache = this.#config.cacheFactory
      ? this.#config.cacheFactory()
      : new Map<string, Element | undefined>();

    // emit audit event if configured (fire-and-forget)
    if (this.#config.auditHook) {
      const eventBase = {
        kind: "cache_refresh" as const,
        timestamp: new Date().toISOString(),
      };
      const event = this.#instanceId
        ? ({ ...eventBase, instanceId: this.#instanceId } as AuditEvent)
        : (eventBase as AuditEvent);
      // intentionally fire-and-forget; safeCallAuditHook has internal timeout
      void this.#safeCallAuditHook(event).catch(() => {
        /* swallowing; audit non-critical */
      });
    }
  }

  /**
   * Resolve and cache allowed root Elements. Returns an empty Map in no-DOM environments.
   *
   * Note: synchronous by design to keep public API sync.
   *
   * @mutates this.#resolvedRootsCache
   */
  #resolveAndCacheAllowedRoots(): ReadonlyMap<string, Element | undefined> {
    if (!hasDOM) return new Map();

    if (this.#resolvedRootsCache && this.#resolvedRootsCache.size > 0) {
      return this.#resolvedRootsCache;
    }

    const mutable =
      this.#resolvedRootsCache ?? new Map<string, Element | undefined>();
    for (const selector of this.#config.allowedRootSelectors) {
      try {
        const element = document.querySelector(selector) ?? undefined;
        mutable.set(selector, element);
      } catch (error) {
        secureDevelopmentLog("debug", "DOMValidator", "resolve root failed", {
          selector: sanitizeSelectorForLogs(String(selector)),
          err: sanitizeErrorForLogs(error),
        });
        mutable.set(selector, undefined);
      }
    }
    this.#resolvedRootsCache = mutable;
    return this.#resolvedRootsCache;
  }

  // Helper: assert parenthesis nesting depth is within allowed limit
  #assertParenDepthWithinLimit(selector: string, maxDepth: number): void {
    let depth = 0;
    for (let index = 0; index < selector.length; index++) {
      const ch = selector[index];
      if (ch === "(") {
        depth++;
        if (depth > maxDepth) {
          this.#emitValidationFailureEvent(selector, "paren_depth_exceeded");
          throw new InvalidParameterError(
            "Selector nesting depth is too large.",
          );
        }
      } else if (ch === ")") {
        depth = Math.max(0, depth - 1);
      }
    }
  }

  /**
   * Non-blocking background parse using optional `css-what` to detect subtle
   * selector syntax issues. This never changes the synchronous result; it only
   * emits audit events or dev logs if the optional parser reports problems.
   */
  #backgroundCssWhatParse(selector: string): void {
    if (!selector) return;
    void (async () => {
      try {
        // Allow tests to override dynamic imports deterministically.
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const importer: (spec: string) => Promise<any> =
          // OWASP ASVS L3: Dynamic imports are security-critical. We validate module
          // specifiers against a strict whitelist and use timeout protection to prevent
          // DoS attacks. The 's' parameter is validated before use.

          (DOMValidator as any).__test_importOverride ??
          /* eslint-disable no-unsanitized/method */
          ((s: string) => {
            // Security: Validate module specifier against strict whitelist
            const allowedModules = new Set(["lru-cache", "css-what"]);
            if (!allowedModules.has(s)) {
              throw new Error(
                `Security violation: unauthorized module import '${s}'`,
              );
            }
            // OWASP ASVS L3: Dynamic imports are validated against strict whitelist before execution
            return import(s);
          });
        /* eslint-enable no-unsanitized/method */
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const module_ = await promiseWithTimeout(
          importer("css-what"),
          800,
          "css-what_timeout",
        );
        // Narrow runtime shape: we expect an exported parser function named
        // `parse` or the default export. Treat as unknown and validate before use.

        const maybeParser: unknown =
          (module_ as any).parse ?? (module_ as any).default ?? module_;
        if (typeof maybeParser === "function") {
          const parserFunction = maybeParser as (s: string) => unknown;
          // call parser; css-what throws on invalid input
          parserFunction(String(selector));
        }
      } catch (error) {
        try {
          // Non-fatal: emit a validation failure audit and a dev log for debugging
          this.#emitValidationFailureEvent(selector, "css_what_parse_failed");
          secureDevelopmentLog(
            "debug",
            "DOMValidator",
            "css-what parse failed",
            {
              err: sanitizeErrorForLogs(error),
            },
          );
        } catch {
          /* swallow */
        }
      }
    })();
  }

  /**
   * Rate-limit guard for selector syntax validation.
   * Throws InvalidParameterError when rate limit exceeded.
   *
   * @mutates this.#validationCounter
   * @mutates this.#lastWindow
   */
  #checkRateLimit(): void {
    const now = Date.now();
    if (now - this.#lastWindow >= 1000) {
      this.#lastWindow = now;
      this.#validationCounter = 0;
    }
    this.#validationCounter++;
    const max = this.#config.maxValidationsPerSecond ?? 50;
    if (this.#validationCounter > max) {
      if (this.#config.auditHook) {
        const eventBase = {
          kind: "rate_limit_triggered" as const,
          timestamp: new Date().toISOString(),
        };
        const event = this.#instanceId
          ? ({ ...eventBase, instanceId: this.#instanceId } as AuditEvent)
          : (eventBase as AuditEvent);
        void this.#safeCallAuditHook(event).catch(() => {});
      }
      throw new InvalidParameterError("Selector validation rate exceeded");
    }
  }

  /**
   * Basic validation of a CSS selector's syntax. Conservative approach:
   * - quick allowlist for simple selectors (ID, class, tag, basic combinators);
   * - explicit rejection of expensive pseudo-classes and known expensive constructs;
   * - disallow complex selectors in non-DOM environments.
   *
   * @throws {InvalidParameterError} If the selector is invalid or disallowed.
   */
  public validateSelectorSyntax(selector: string): string {
    this.#checkRateLimit();

    if (typeof selector !== "string") {
      this.#emitValidationFailureEvent(String(selector), "non_string_selector");
      throw new InvalidParameterError("Selector must be a string.");
    }

    const s = selector.trim();

    if (!s) {
      this.#emitValidationFailureEvent(s, "empty_selector");
      throw new InvalidParameterError(
        "Invalid selector: must be a non-empty string.",
      );
    }

    const maxLength = this.#config.maxSelectorLength ?? 1024;
    if (s.length > maxLength) {
      this.#emitValidationFailureEvent(s, "selector_too_long");
      throw new InvalidParameterError("Selector is too long.");
    }

    // Fast allowlist for very simple selectors: ID, class, tag, and simple combinators.
    // Implemented via safe scanner to avoid complex regexes and ReDoS.
    const maxCombinators = 8;
    const isSimple = (() => {
      let tokens = 0;
      let index = 0;
      const validToken = (tok: string) => /^[#.]?[-\w]+$/.test(tok);
      while (index < s.length) {
        // split on combinators
        let index_ = index;
        while (index_ < s.length && !/[ >+~]/.test(s.charAt(index_))) index_++;
        const tok = s.slice(index, index_).trim();
        if (!tok) return false;
        if (!validToken(tok)) return false;
        tokens++;
        // skip combinator(s)
        while (index_ < s.length && /[ >+~]/.test(s.charAt(index_))) index_++;
        index = index_;
        if (tokens > maxCombinators + 1) return false;
      }
      return tokens > 0 && tokens <= maxCombinators + 1;
    })();
    if (isSimple) return s;

    // Reject known expensive or complex pseudo-classes immediately. Use simple
    // substring checks instead of a complex regex to avoid ReDoS concerns.
    const expensiveList = [
      ":has(",
      ":is(",
      ":where(",
      ":nth-last",
      ":nth-child",
      ":not(",
      ":matches(",
      ":contains(",
    ];
    for (const token of expensiveList) {
      if (s.toLowerCase().includes(token)) {
        this.#emitValidationFailureEvent(s, "expensive_pseudo");
        throw new InvalidParameterError(
          "Selector contains disallowed or expensive pseudo-classes.",
        );
      }
    }

    // Additional syntactic constraints: parentheses depth, attribute selector length
    // parentheses depth
    this.#assertParenDepthWithinLimit(s, 3);

    // attributes length and complexity — use a safe scanner to extract bracketed segments
    const attributeSegments = extractAttributeSegments(s);
    for (const seg of attributeSegments) {
      if (seg.length > 128) {
        this.#emitValidationFailureEvent(s, "attribute_selector_too_long");
        throw new InvalidParameterError("Attribute selector is too large.");
      }
    }

    if (!hasDOM) {
      this.#emitValidationFailureEvent(s, "complex_selector_no_dom");
      throw new InvalidParameterError(
        "Complex selectors are disallowed in non-DOM environments.",
      );
    }

    // Final safety-net: attempt to parse using a DocumentFragment (may throw)
    try {
      document.createDocumentFragment().querySelector(s);
    } catch (error) {
      const safe = sanitizeErrorForLogs(error);
      this.#emitValidationFailureEvent(s, "parser_reject");
      secureDevelopmentLog(
        "debug",
        "DOMValidator",
        "selector parsing rejected by native parser",
        { err: safe },
      );
      throw new InvalidParameterError(
        `Invalid selector syntax (rejected by parser).`,
      );
    }

    // Kick off an optional background parse using `css-what` for additional
    // parsing coverage without blocking the sync return.
    this.#backgroundCssWhatParse(s);

    return s;
  }

  /**
   * Narrowing helper: asserts the provided value is a DOM Element.
   * Uses TTL-based revalidation to avoid trusting elements indefinitely.
   * @throws {InvalidParameterError} if the value is not an Element or if no DOM exists.
   *
   * @mutates this.#validatedElements
   */
  public validateElement(element_: unknown): Element {
    if (!hasDOM) {
      this.#emitValidationFailureEvent(String(element_), "no_dom_for_element");
      throw new InvalidParameterError("No DOM available to validate elements.");
    }
    if (!(element_ instanceof Element)) {
      this.#emitValidationFailureEvent(String(element_), "not_element");
      throw new InvalidParameterError(
        "Invalid element: must be a DOM Element.",
      );
    }
    const element = element_ as Element;

    const now = Date.now();
    const ttl = this.#config.validatedElementTTLms ?? 5 * 60 * 1000;
    const last = this.#validatedElements.get(element) ?? 0;
    if (last && now - last <= ttl) {
      // considered still validated
      return element;
    }

    const tag = (element.tagName || "").toLowerCase();
    if (["script", "iframe", "object", "embed", "style"].includes(tag)) {
      this.#emitValidationFailureEvent(String(tag), "forbidden_tag");
      throw new InvalidParameterError(`Forbidden element tag: <${tag}>`);
    }

    this.#validatedElements.set(element, now);
    return element;
  }

  /**
   * Safely query for an element ensuring it resides within an allowlisted root.
   *
   * Returns `undefined` in non-DOM environments or when nothing matches.
   */
  public queryElementSafely(
    selector: string,
    context?: Document | Element,
  ): Element | undefined {
    const results = this.queryAllSafely(selector, context);
    return results.length > 0 ? results[0] : undefined;
  }

  /**
   * Query for all matching elements that are inside allowlisted roots.
   * Returns empty array in no-DOM contexts.
   *
   * Public return type is readonly, internal array is mutable.
   *
   * @mutates this.#resolvedRootsCache
   */
  public queryAllSafely(
    selector: string,
    context?: Document | Element,
  ): readonly Element[] {
    if (!hasDOM) {
      secureDevelopmentLog(
        "warn",
        "DOMValidator",
        "Blocked queryAllSafely: no DOM available",
        {
          selector: sanitizeSelectorForLogs(selector),
        },
      );
      return [];
    }

    try {
      this.validateSelectorSyntax(selector);

      const context_ = (context ?? document) as Document | Element;
      const nodeList = context_.querySelectorAll(selector);
      if (!nodeList || nodeList.length === 0) return [];

      // Refresh cached roots and ensure connectedness
      const resolved = new Map<string, Element | undefined>(
        this.#resolveAndCacheAllowedRoots() as ReadonlyMap<
          string,
          Element | undefined
        >,
      );
      for (const [sel, rootElement] of Array.from(resolved.entries())) {
        if (rootElement && !rootElement.isConnected) {
          try {
            resolved.set(sel, document.querySelector(sel) ?? undefined);
          } catch (error) {
            secureDevelopmentLog(
              "debug",
              "DOMValidator",
              "refresh root failed",
              {
                selector: sanitizeSelectorForLogs(sel),
                err: sanitizeErrorForLogs(error),
              },
            );
            resolved.set(sel, undefined);
          }
        }
      }
      // commit refreshed map to internal cache
      this.#resolvedRootsCache = new Map(resolved);

      const rootEls = Array.from(resolved.values()).filter(
        Boolean,
      ) as readonly Element[];

      // Internal mutable result
      const result: Element[] = [];
      for (const element of Array.from(nodeList)) {
        const isContained = rootEls.some(
          (rootElement) =>
            rootElement === element || rootElement.contains(element),
        );
        if (!isContained) continue;
        try {
          result.push(this.validateElement(element));
        } catch (error) {
          // skip elements that fail validation (and continue)
          secureDevelopmentLog(
            "debug",
            "DOMValidator",
            "element validation failed, skipping",
            {
              selector: sanitizeSelectorForLogs(selector),
              err: sanitizeErrorForLogs(error),
            },
          );
        }
      }
      return result as readonly Element[];
    } catch (error) {
      const safe = sanitizeErrorForLogs(error);
      secureDevelopmentLog("warn", "DOMValidator", "queryAllSafely failed", {
        selector: sanitizeSelectorForLogs(selector),
        err: safe,
      });
      if (this.#config.failFast) throw error;
      return [];
    }
  }

  /**
   * Checks whether a given element is contained inside allowed roots.
   * Returns false in non-DOM contexts.
   */
  public containsWithinAllowedRoots(element: Element): boolean {
    if (!hasDOM) return false;
    try {
      this.validateElement(element);
    } catch {
      return false;
    }
    const resolved = this.#resolveAndCacheAllowedRoots();
    for (const root of Array.from(resolved.values()).filter(
      Boolean,
    ) as readonly Element[]) {
      if (root === element || root.contains(element)) return true;
    }
    return false;
  }

  /* ---------------------------- Auditing helpers ------------------------- */

  /**
   * Internal: emit lightweight audit event for validation failure; immediately
   * includes fingerprint; asynchronously compute SHA-256 of the selector (with timeout)
   * and emit follow-up event when available — only if emitSelectorHash is enabled.
   */
  #emitValidationFailureEvent(selector: string, reason?: string): void {
    const hook = this.#config.auditHook;
    if (!hook) return;
    const fingerprint = fingerprintHexSync(selector);
    const baseEvent: AuditEvent = Object.freeze({
      kind: "validation_failure",
      timestamp: new Date().toISOString(),
      selectorFingerprint: fingerprint,
      selectorLength: selector ? selector.length : 0,
      ...(reason ? { reason } : {}),
      ...(this.#instanceId ? { instanceId: this.#instanceId } : {}),
    } as AuditEvent);
    // fire-and-forget (do not await) — ensure rejections are observed by attaching catch
    void this.#safeCallAuditHook(baseEvent).catch(() => {
      /* non-fatal */
    });

    // Compute SHA-256 asynchronously with timeout and emit follow-up event when ready,
    // only when explicitly enabled to avoid privacy leakage and extra CPU.
    if (!this.#config.emitSelectorHash) return;

    void (async () => {
      try {
        const hash = await sha256Hex(
          selector,
          this.#config.auditHookTimeoutMs ?? 1500,
        );
        const follow: AuditEvent = Object.freeze({
          kind: "validation_failure_hash",
          timestamp: new Date().toISOString(),
          selectorFingerprint: fingerprint,
          selectorHash: hash,
          selectorLength: selector.length,
          ...(reason ? { reason } : {}),
          ...(this.#instanceId ? { instanceId: this.#instanceId } : {}),
        } as AuditEvent);
        await this.#safeCallAuditHook(follow);
      } catch (error) {
        // log sanitized debug info; never throw from auditing path
        try {
          secureDevelopmentLog(
            "debug",
            "DOMValidator",
            "emitValidationFailureEvent: hash or hook failed",
            {
              err: sanitizeErrorForLogs(error),
            },
          );
        } catch {
          /* swallow */
        }
      }
    })();
  }

  /** Generic safe call to audit hook with error handling and timeout. */
  async #safeCallAuditHook(event: AuditEvent): Promise<void> {
    try {
      const hook = this.#config.auditHook;
      if (!hook) return;
      const timeoutMs = this.#config.auditHookTimeoutMs ?? 2000;
      // Wrap the hook call in Promise.race with a timeout.
      // Create a plain, whitelisted, frozen event object to avoid accidental
      // prototype pollution or unexpected keys being received by the hook.
      const base = { kind: event.kind, timestamp: event.timestamp } as const;
      const safeEvent = Object.freeze({
        ...base,
        ...(event.selectorFingerprint
          ? { selectorFingerprint: event.selectorFingerprint }
          : {}),
        ...(event.selectorLength !== undefined
          ? { selectorLength: event.selectorLength }
          : {}),
        ...(event.reason ? { reason: event.reason } : {}),
        ...(event.selectorHash ? { selectorHash: event.selectorHash } : {}),
        ...(event.instanceId ? { instanceId: event.instanceId } : {}),
      } as AuditEvent);

      await promiseWithTimeout(
        (async () => {
          // Ensure any thrown value is propagated to our outer try/catch and sanitized.
          await hook(safeEvent);
        })(),
        timeoutMs,
        "audit_hook_timeout",
      );
    } catch (error) {
      // Avoid throwing from auditing; log minimally for dev
      try {
        secureDevelopmentLog("warn", "DOMValidator", "Audit hook failed", {
          err: sanitizeErrorForLogs(error),
          eventKind: event.kind,
        });
      } catch {
        // swallow
      }
    }
  }

  /* ---------------------------- Misc helpers ----------------------------- */
  /* Misc helpers intentionally minimal; mask/truncate helpers live as top-level functions. */
  // Test-only methods: allow unit tests to trigger internal background tasks
  // in a controlled manner. These are part of the test surface only and
  // do not change production behavior.
  public async __test_tryUpgradeCache(): Promise<void> {
    return await this.#tryUpgradeCache();
  }

  public __test_backgroundCssWhatParse(selector: string): void {
    return this.#backgroundCssWhatParse(selector);
  }
}

/* ---------------------------- Default helpers ---------------------------- */

/**
 * Factory helper to create a new, independent `DOMValidator` instance with the
 * library's default configuration. Prefer creating your own instance in
 * application code instead of mutating the default singleton.
 *
 * Accepts partial config shapes (arrays or sets) and normalizes them.
 */
export function createDefaultDOMValidator(
  config?: Partial<DOMValidatorConfig>,
): DOMValidator {
  const merged: DOMValidatorConfig = {
    ...DEFAULT_CONFIG,
    ...(config ?? {}),
  } as DOMValidatorConfig;

  // Rehydrate sets if caller provided arrays or iterables
  const allowedInput = (config?.allowedRootSelectors ??
    DEFAULT_CONFIG.allowedRootSelectors) as
    | ReadonlySet<string>
    | string[]
    | Iterable<string>;
  const forbiddenInput = (config?.forbiddenRoots ??
    DEFAULT_CONFIG.forbiddenRoots) as
    | ReadonlySet<string>
    | string[]
    | Iterable<string>;

  const allowedSet = new Set<string>();
  for (const s of allowedInput as Iterable<string>)
    allowedSet.add(String(s).trim());
  const forbiddenSet = new Set<string>();
  for (const s of forbiddenInput as Iterable<string>)
    forbiddenSet.add(String(s).trim().toLowerCase());

  const finalConfig: DOMValidatorConfig = Object.freeze({
    ...merged,
    allowedRootSelectors: allowedSet,
    forbiddenRoots: forbiddenSet,
  });

  return new DOMValidator(finalConfig);
}

/**
 * Lazily-constructed default validator to avoid throwing at import-time in non-DOM contexts.
 *
 * @mutates defaultInstance
 */
let defaultInstance: DOMValidator | undefined = undefined;

export function getDefaultDOMValidator(): DOMValidator {
  if (!defaultInstance) defaultInstance = new DOMValidator(DEFAULT_CONFIG);
  return defaultInstance;
}

// Test-only helper: reset the lazily-constructed default instance so unit tests
// can exercise both the creation and the cached-return branches deterministically.
// This is intentionally test-only and should not be used in application code.
export function __test_resetDefaultValidatorForUnitTests(): void {
  (defaultInstance as any) = undefined;
}

/* -------------------------------------------------------------------------- */
/* Test-only exports (intentionally named to indicate non-public API).         */
/* These are provided to support unit tests and debugging; they are small,
 * auditable wrappers that do not change runtime behavior.                   */
export const __test_redactAttributesSafely = redactAttributesSafely;
export const __test_removeQuotedSegmentsSafely = removeQuotedSegmentsSafely;
export const __test_extractAttributeSegments = extractAttributeSegments;
export const __test_fingerprintHexSync = fingerprintHexSync;
export const __test_promiseWithTimeout = promiseWithTimeout;
export const __test_sha256Hex = sha256Hex;
export const __test_sanitizeSelectorForLogs = sanitizeSelectorForLogs;

// Also expose the helpers under their original names for test consumers that
// import the module directly in unit tests. These are considered non-breaking
// for runtime behavior but are intended for test use only.
export {
  redactAttributesSafely,
  removeQuotedSegmentsSafely,
  extractAttributeSegments,
};
