/**
 * Security-kit ESLint configuration (flat-config)
 *
 * Purpose: centralizes lint rules used by local development and CI. This
 * file is authored as an ESM flat-config and includes defensive handling
 * for plugins that export CommonJS shapes. Keep it minimal and review any
 * plugin expansion logic carefully to avoid surprising rule inheritance.
 *
 * SPDX-License-Identifier: MIT
 */
// @ts-nocheck: config file uses dynamic imports and plugin shapes; type checking here is noisy
import process from 'node:process';

/*
 * Local rule documentation (security-kit custom ESLint rules)
 * ---------------------------------------------------------
 * The rules implemented under `tools/eslint-rules/` are security-first
 * lint checks that codify the project's Security Constitution and align
 * with OWASP ASVS L3 requirements. This block documents each local rule
 * so maintainers and reviewers understand the intent, configuration and
 * the OWASP / Constitution mapping.
 *
 * Usage: these rules are registered through the `local` plugin mapping
 * (see the plugin import below). Each rule's identifier is "local/<name>"
 * and the configuration options used by this project are set in the
 * `rules` object later in this file.
 *
 * Documentation index (alphabetical):
 *
 * - enforce-config-immutability
 *   Purpose: Ensure configuration objects are frozen and runtime mutations
 *   are guarded by the kit's sealed-state checks. Prevents accidental or
 *   hostile configuration drift in production.
 *   OWASP mapping: ASVS V14.2.1 (Configuration integrity)
 *   Constitution refs: §1.3 Principle of Least Privilege
 + Options: configPatterns (regex strings), requiredFreezeFor (AST node types)
 *   Failure mode: missing Object.freeze or assignments to config variables
 *   without a getCryptoState() === CryptoState.Sealed guard.
 *
 * - enforce-error-sanitization-at-boundary
 *   Purpose: Require explicit sanitization of Error objects before they
 *   cross logging/telemetry boundaries. Prevents stack trace and PII
 *   leakage in logs.
 *   OWASP mapping: ASVS V7.1.1, V14.3.3 (Error message leakage)
 *   Constitution refs: §1.4 "Fail Loudly, Fail Safely"
 *   Options: approvedSanitizers (list), loggingFunctions (list)
 *
 * - enforce-json-size-guard
 *   Purpose: Flag uses of JSON.parse/stringify on external data without
 *   explicit size validation to mitigate large payload DoS and memory
 *   exhaustion attacks.
 *   OWASP mapping: ASVS V14.2.* (Resource validation)
 *   Options: maxSizeBytes, allowedValidationFunctions
 *
 * - enforce-postmessage-config-consistency
 *   Purpose: Detect incompatible or unsafe combinations of postMessage
 *   options (e.g., sanitize: true + allowTypedArrays: true with structured
 *   wire formats). Encourages consistent, secure postMessage configs.
 *   OWASP mapping: ASVS V5.1.3 (Input validation consistency)
 *
 * - enforce-sealed-kit-startup
 *   Purpose: Ensure `sealSecurityKit()` is invoked in application entry
 *   points at top-level during initialization, preventing runtime tampering.
 *   OWASP mapping: ASVS V14.2.* (Configuration lifecycle)
 *   Options: entryPointPatterns, sealFunctionNames
 *
 * - enforce-secure-logging
 *   Purpose: Disallow direct console logging in most production sources and
 *   require the project's secure logging helpers (redaction, ratelimiting).
 *   OWASP mapping: ASVS V7.* (Logging & telemetry hygiene)
 *   Options: allowInFiles, allowedMethods
 *
 * - enforce-secure-postmessage-listener
 *   Purpose: Require `createSecurePostMessageListener()` calls to include
 *   validation and origin restrictions in non-test code.
 *   OWASP mapping: ASVS V14.1.1 (Message validation and origin verification)
 *   Options: requireValidation, requireOriginRestriction, testDirectoryPatterns
 *
 * - enforce-secure-signer-integrity
 *   Purpose: Enforce strong integrity options for `SecureApiSigner.create()`
 *   to avoid supply-chain / worker-script tampering (forbid 'none', warn on
 *   'compute', require explicit expectedWorkerScriptHash for 'require').
 *   OWASP mapping: ASVS V10.3.3 (Supply chain security)
 *
 * - enforce-secure-wipe
 *   Purpose: Ensure Uint8Array buffers carrying secrets are wiped via
 *   `secureWipe()` (or secureWipeOrThrow) inside a finally block to satisfy
 *   memory hygiene requirements.
 *   OWASP mapping: ASVS L3 memory hygiene and secrets handling
 *
 * - enforce-security-kit-imports
 *   Purpose: Prevent ad-hoc direct Web Crypto / native crypto imports in
 *   application code. Enforces use of the centralized security-kit wrappers
 *   which implement DoS caps, validation and uniform error handling.
 *   OWASP mapping: ASVS V1.1.2 (Security frameworks and libraries)
 *   Options: allowedFiles, securityKitModule, allowedMethods
 *
 * - enforce-security-suppression-format
 *   Purpose: Require justifications for suppressing security rules. Suppress
 *   directives must include a nearby comment with security keywords so
 *   reviewers and auditors can quickly find the rationale.
 *
 * - enforce-test-api-guard
 *   Purpose: Ensure test-only APIs are guarded by `assertTestApiAllowed()` to
 *   prevent accidental production exposure. Identifies functions matching
 *   common test suffix/prefix heuristics and requires guard call at function start.
 *
 * - enforce-text-encoder-decoder
 *   Purpose: Enforce usage of shared TextEncoder/TextDecoder instances
 *   (e.g., SHARED_ENCODER / SHARED_DECODER) to avoid repeated allocations and
 *   reduce attack surface from unnecessary temporary buffers.
 *
 * - enforce-visibility-abort-pattern
 *   Purpose: Require long-running/crypto operations to implement the visibility
 *   change abort pattern (AbortController + visibilitychange listener) to
 *   protect against timing/TOCTOU issues when the page is backgrounded.
 *   Constitution refs: §2.11 visibility-abort pattern (MANDATORY)
 *
 * - no-broad-exception-swallow
 *   Purpose: Disallow empty or generic catch blocks that swallow errors;
 *   require typed rethrows, approved recoveries or reporting via approved
 *   reporters (reportProdError etc.). Aligns with "Fail Safely".
 *
 * - no-date-entropy-security-context
 *   Purpose: Flag use of Date.now(), new Date(), performance.now() and similar
 *   time-based entropy sources in security contexts (tokens, keys, nonces).
 *   Use cryptographically secure random primitives instead.
 *
 * - no-direct-process-env
 *   Purpose: Disallow direct reads from `process.env` outside approved
 *   configuration files (e.g., `environment.ts`, `config.ts`). Centralizes
 *   configuration and prevents accidental secret leakage.
 *
 * - no-direct-subtle-crypto / no-direct-subtle-crypto (overlapping rules)
 *   Purpose: Forbid direct `crypto.subtle` usage in application code; require
 *   the high-level security-kit APIs which provide validation and safer
 *   defaults. Options allow a small set of migration exceptions.
 *
 * - no-direct-url-constructor
 *   Purpose: Prevent `new URL()` usage in application code in favor of
 *   hardened utilities (`validateURL`, `createSecureURL`, `normalizeOrigin`)
 *   that strip credentials and validate origins.
 *
 * - no-insecure-nonce-store
 *   Purpose: Disallow `InMemoryNonceStore` in production code; require a
 *   distributed/persistent nonce store (Redis, Database) to prevent replay attacks.
 *
 * - no-math-random-security-context
 *   Purpose: Disallow `Math.random()` in security contexts (ID/token/nonce
 *   generation). Suggest `getSecureRandom()` / `generateSecureId()` from
 *   security-kit.
 *
 * - no-plaintext-secret-storage
 *   Purpose: Detect plaintext storage of secrets in variables, object props,
 *   or local/session storage and suggest encrypted storage helpers.
 *
 * - no-postmessage-constant-usage
 *   Purpose: Disallow direct runtime reads of `POSTMESSAGE_MAX_*` constants
 *   outside `config.ts` and tests; require `getPostMessageConfig()` to make
 *   runtime limits central and configurable prior to sealing.
 *
 * - no-secret-eq
 *   Purpose: Warn when secret-like identifiers are compared using `===` or
 *   `==` and recommend constant-time comparison helpers (`secureCompareAsync`,
 *   `secureCompareBytes`) to avoid timing side-channels.
 *
 * - no-un-normalized-string-comparison
 *   Purpose: Require Unicode normalization for comparisons involving external
 *   input to prevent homograph and normalization bypass attacks. Suggest
 *   `normalizeInputString()` or canonical String.prototype.normalize() usage.
 *
 * - no-unsafe-object-merge
 *   Purpose: Flag object spread / Object.assign usage with external input to
 *   prevent prototype pollution. Recommend `toNullProto()` or explicit safe
 *   merging helper.
 *
 * - no-unsealed-configuration
 *   Purpose: Ensure configuration-modifying functions check the kit sealed
 *   state before applying changes; enforces State Machine Integrity.
 *
 * - throw-typed-errors
 *   Purpose: Enforce use of typed, project-specific error classes (from
 *   `src/errors.ts`) rather than generic `Error` so callers can handle
 *   failures programmatically.
 *
 * Shared helpers
 * - _shared/analysis.js
 *   Provides common AST helpers used by several rules: alias collection,
 *   secret name detection, member name resolution and taint heuristics.
 *
 * Notes for maintainers:
 * - These rules intentionally avoid automated fixers for security-critical
 *   transformations. Reported violations should be fixed by a human reviewer.
 * - Many rules include test-directory relaxations to avoid noisy errors in
 *   fixtures and demos. If you need to change relaxations, prefer scoped
 *   overrides rather than broadening rule defaults.
 */
import tseslintPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
// Some parser packages are CommonJS and, when imported from an ESM flat-config,
// the module object may be wrapped under a `.default` property. Normalize the
// parser object so `languageOptions.parser` always receives the actual parser
// object which must implement `parseForESLint` (ESLint will warn and ignore a
// parser that doesn't provide that function).
const tsParserObj = tsParser && tsParser.default ? tsParser.default : tsParser;
import securityPlugin from "eslint-plugin-security";
/* eslint-disable-next-line import/no-named-as-default-member -- plugin is CommonJS; access `configs` via the default export */
const securityConfigs = (securityPlugin && securityPlugin.configs) || {};
import noUnsanitized from "eslint-plugin-no-unsanitized";
import importPlugin from "eslint-plugin-import";
import nodePlugin from "eslint-plugin-n";
import securityNode from "eslint-plugin-security-node";
import prettierPlugin from "eslint-plugin-prettier";
import vitestPlugin from "@vitest/eslint-plugin";
import { configs as sonarConfigs } from "eslint-plugin-sonarjs";
import * as regexpPlugin from "eslint-plugin-regexp";
import redosPlugin from "eslint-plugin-redos";
import sdlPlugin from "@microsoft/eslint-plugin-sdl";
import localPlugin from "./tools/eslint-plugin-local/index.js";
import unicornPlugin from "eslint-plugin-unicorn";
import functionalPlugin from "eslint-plugin-functional";
import promisePlugin from "eslint-plugin-promise";
import noSecretsPlugin from "eslint-plugin-no-secrets";
// Resolve recommended config safely (supports flatConfigs or legacy `configs`)
const promiseRecommended = (function () {
  if (!promisePlugin) return undefined;
  if (promisePlugin.flatConfigs) {
    return safeResolveConfigMap(promisePlugin.flatConfigs, 'flat/recommended') || safeResolveConfigMap(promisePlugin.flatConfigs, 'recommended');
  }
  if (promisePlugin.configs) {
    return safeResolveConfigMap(promisePlugin.configs, 'flat/recommended') || safeResolveConfigMap(promisePlugin.configs, 'recommended');
  }
  return undefined;
})();

// Helper: expand a plugin flat-config that may include 'extends' references
// into an ordered array of config objects that are safe to place into the
// top-level flat-config array (no 'extends' key). We prefer the plugin
// 'flatConfigs' entry when available, otherwise fall back to legacy 'configs'.
function safeResolveConfigMap(map, key) {
  if (!map || typeof map !== 'object') return undefined;
  // Only accept string keys and disallow dangerous prototype keys.
  if (typeof key !== 'string') return undefined;
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') return undefined;
  // Restrict key characters to a conservative safe subset to avoid injection-like keys.
  if (!/^[\w@/.-]+$/.test(key)) return undefined;

  // Use hasOwnProperty guard to avoid prototype pollution concerns
  if (!Object.prototype.hasOwnProperty.call(map, key)) return undefined;

  // Access the candidate value only after we've validated the key and existence.
  // The key has been validated above (whitelist of safe characters and prototype checks).
  // eslint-disable-next-line security/detect-object-injection -- validated key; this is a controlled lookup in config
  const candidate = map[key];
  if (candidate === null || candidate === undefined) return undefined;
  if (typeof candidate === 'object') {
    // Only allow plain object literals to be cloned; reject functions/classes
    const proto = Object.getPrototypeOf(candidate);
    if (proto === Object.prototype || proto === null) {
      return { ...candidate };
    }
    // Otherwise, disallow returning complex objects directly
    return undefined;
  }
  // primitives (string/number/boolean) are safe to return
  return candidate;
}

function ensureTypescriptSettings(clone) {
  const ruleKeys = Object.keys(clone.rules || {});
  const hasTsRules = ruleKeys.some((r) => r.startsWith('@typescript-eslint/'));
  if (!hasTsRules) return clone;

  clone.plugins = clone.plugins || {};
  if (!Object.prototype.hasOwnProperty.call(clone.plugins, '@typescript-eslint')) {
    clone.plugins['@typescript-eslint'] = tseslintPlugin;
  }

  if (!clone.files) {
    clone.files = [
      'src/**/*.ts',
      'src/**/*.tsx',
      'server/**/*.ts',
      'server/**/*.tsx',
      'tests/**/*.ts',
      'tests/**/*.tsx',
    ];
  }
  clone.languageOptions = clone.languageOptions || {};
  clone.languageOptions.parser = clone.languageOptions.parser || tsParserObj;
  clone.languageOptions.parserOptions = clone.languageOptions.parserOptions || {};
  if (!('projectService' in clone.languageOptions.parserOptions)) {
    clone.languageOptions.parserOptions.projectService = true;
  }
  if (!('tsconfigRootDir' in clone.languageOptions.parserOptions)) {
    clone.languageOptions.parserOptions.tsconfigRootDir = process.cwd();
  }
    return clone;
  }

function expandPluginFlatConfig(plugin, flatKey) {
  if (!plugin) return [];
  const flatConfigs = plugin.flatConfigs || {};
  const configs = plugin.configs || {};

  const altKey = flatKey.replace(/^flat\//, '');
  const base = safeResolveConfigMap(flatConfigs, flatKey) || safeResolveConfigMap(configs, altKey) || safeResolveConfigMap(configs, flatKey);
  if (!base) return [];

  const expanded = [];
  const extendsList = Array.isArray(base.extends) ? base.extends : [];
  for (const k of extendsList) {
    const candidates = [k, `flat/${k}`];
    let resolved = undefined;
    for (const c of candidates) {
      resolved = safeResolveConfigMap(flatConfigs, c) || safeResolveConfigMap(configs, c);
      if (resolved) break;
    }
    if (resolved) expanded.push(resolved);
  }

  const clone = { ...base };
  if ('extends' in clone) delete clone.extends;

  // Apply TypeScript-aware defaults if needed
  expanded.push(ensureTypescriptSettings(clone));
  return expanded.filter(Boolean);
}
export default [
  // Global ignores
  {
    ignores: [
      "dist/**/*",
      "npm/**/*",  // dnt build output - exclude from linting
      "node_modules/**/*",
      "coverage/**/*",
      "**/*.min.js",
  "tests/**",
      "tests/old_tests/**/*",
      // Tooling and benchmarks are excluded from default lint runs to avoid
      // parse errors and noisy findings that don't affect production code.
      ".husky/**/*",
      "benchmarks/**/*",
      "demo/**/*",
      "tsconfig-paths/**/*",
      "scripts/**/*",
      "tools/**/*",
    ],
  },
  // Global settings to help import resolver find packages and TS files when
  // linting config files and project sources.
  {
    settings: {
      "import/parsers": {
        "@typescript-eslint/parser": [".ts", ".tsx"],
      },
      "import/resolver": {
        typescript: {
          alwaysTryTypes: true,
        },
        node: {
          extensions: [".js", ".cjs", ".mjs", ".ts", ".tsx", ".json"],
        },
      },
    },
  },
  // Include the recommended configuration from eslint-plugin-no-unsanitized
  // to ensure default allowed sanitizer patterns (e.g., Sanitizer API and
  // common escape helpers) are applied before our stricter project rules.
  noUnsanitized.configs.recommended,
  // Import plugin recommendation for import/export static checks and the
  // TypeScript-specific layer. This brings rules like no-unresolved, named
  // and namespace checks which improve module hygiene and prevent misspellings.
  importPlugin.flatConfigs.recommended,
  importPlugin.flatConfigs.typescript,
  // RegExp plugin: recommend safe regexp usage and optimizations
  regexpPlugin.configs["flat/recommended"],
  // SonarJS rules for code quality and additional security heuristics
  sonarConfigs.recommended,
  // Security plugin recommended ruleset (node & generic security heuristics)
  securityConfigs.recommended,
  // Promise plugin recommended ruleset for secure async/await patterns.
  // Use flatConfigs when available, otherwise fall back to legacy `configs`.
  promiseRecommended,
  // Microsoft SDL recommended flat-config (adds additional security-focused rules)
  ...expandPluginFlatConfig(sdlPlugin, 'flat/recommended'),
  // Enable typescript-eslint's strict, type-checked ruleset (more opinionated,
  // recommended for teams proficient in TypeScript). We deliberately avoid
  // stylistic-type-checked as stylistic rules are not desired for security-focused
  // enforcement.
  // Access the plugin-provided flat-config entry by its hyphenated key. The
  // plugin exports config names using hyphenated keys (e.g. 'strict-type-checked'
  // and the flat wrapper 'flat/strict-type-checked'). Using the camelCase
  // property (strictTypeChecked) is undefined in the plugin export and causes
  // ESLint to fail while loading the flat-config array.
  // Expand the typescript-eslint strict-type-checked flat config into
  // concrete config objects (this ensures no object in the exported array
  // contains the unsupported 'extends' key). We try the flatConfigs entry
  // first and fall back to the plugin configs mapping.
  ...expandPluginFlatConfig(tseslintPlugin, 'flat/strict-type-checked'),
  // Intentionally do NOT include the full unicorn recommended config here because
  // it is extremely opinionated and would globally enforce many stylistic rules
  // that are noisy for an existing codebase. We instead opt-in to a small set of
  // high-value unicorn rules below with measured severities.
  // NOTE: Node-specific rules must not apply to browser-targeted `src/**`.
  // We'll enable a focused set of `n/*` rules only for tooling/config files.
  {
    files: ["scripts/**", "scripts/**/*.ts", "*.config.*", "eslint.config.js"],
    languageOptions: {
      parser: tsParserObj,
      parserOptions: {
        ecmaVersion: "2023",
        sourceType: "module",
  tsconfigRootDir: process.cwd(),
  // Scripts/configs: avoid enabling the project service here as these
  // files are not part of the TS project and can confuse the parser.
      },
    },
    plugins: { n: nodePlugin, "@typescript-eslint": tseslintPlugin },
    rules: {
      "n/no-unsupported-features/node-builtins": "warn",
      "n/no-missing-import": "warn",
      "n/no-unpublished-import": "warn",
    },
  },
  // Deno tests: parse as TypeScript and expose Deno globals for linting
  {
    files: ["deno_tests/**/*.ts", "deno_tests/**/*.tsx"],
    languageOptions: {
      parser: tsParserObj,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        // Deno test files don't need the projectService; keep parsing simple
        projectService: false,
        tsconfigRootDir: process.cwd(),
      },
      globals: {
        Deno: 'readonly',
      },
    },
    plugins: { "@typescript-eslint": tseslintPlugin },
    rules: {
      // Tests may use legacy patterns; keep linting useful but not blocking
      "@typescript-eslint/no-explicit-any": "warn",
      // Deno-style import specifiers (jsr: / URLs) and dynamic import(...) calls
      // are used in smoke tests and are executed in Deno only; relax these
      // checks here to avoid false positives from the Node-oriented resolver.
      "import/no-unresolved": "off",
      "no-unsanitized/method": "off",
    },
  },
  {
    files: ["src/**/*.ts", "src/**/*.tsx"],
    languageOptions: {
      parser: tsParserObj,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        // Enable typed linting for strict rules using projectService.
        // Use boolean `projectService: true` so the parser locates nearest
        // tsconfig.json for each file, per typescript-eslint guidance.
        projectService: true,
        tsconfigRootDir: process.cwd(),
      },
    },
    // Help eslint-plugin-import resolve TypeScript modules
    settings: {
      "import/parsers": {
        "@typescript-eslint/parser": [".ts", ".tsx"],
      },
      "import/resolver": {
        typescript: {
          alwaysTryTypes: true,
        },
        node: {
          extensions: [".js", ".jsx", ".ts", ".tsx", ".json"],
        },
      },
    },
    plugins: {
      "@typescript-eslint": tseslintPlugin,
      unicorn: unicornPlugin,
      functional: functionalPlugin,
      redos: redosPlugin,
      security: securityPlugin,
      "no-unsanitized": noUnsanitized,
      "security-node": securityNode,
      prettier: prettierPlugin,
      promise: promisePlugin,
      "no-secrets": noSecretsPlugin,
      // local plugin mapping (resolves to tools/eslint-plugin-local)
      local: localPlugin,
      sdl: sdlPlugin,
    },
    rules: {
      // Allow slightly higher cognitive complexity for complex crypto/url logic
      "sonarjs/cognitive-complexity": ["error", 18],

      // Prettier integration (we don’t format here, but fail if misformatted in non-Astro files)
      "prettier/prettier": "error",

      // TypeScript strictness
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // UPGRADE: Enforce no-explicit-any at error level.
      "@typescript-eslint/no-explicit-any": "error",
      // UPGRADE: Change from "warn" to "error". Force developers to justify suppression.
      "@typescript-eslint/ban-ts-comment": [
        "error",
        {
          "ts-expect-error": "allow-with-description",
          "ts-ignore": "allow-with-description",
          "ts-nocheck": true,
          "ts-check": false,
          minimumDescriptionLength: 10,
        },
      ],
      "@typescript-eslint/no-floating-promises": [
        "error",
        { ignoreVoid: true },
      ],
      "@typescript-eslint/no-deprecated": "error",
      "@typescript-eslint/no-implied-eval": "error",
      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-call": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/no-unsafe-return": "error",
      "@typescript-eslint/no-unsafe-argument": "error",
      "@typescript-eslint/no-unsafe-enum-comparison": "error",
      "@typescript-eslint/no-unsafe-unary-minus": "error",
      "@typescript-eslint/no-empty-function": "error",

      // SECURITY: Template expression and operand restrictions (OWASP ASVS L3)
      "@typescript-eslint/restrict-template-expressions": [
        "error",
        {
          allowAny: false,
          allowBoolean: false,
          allowNever: false,
          allowNullish: false,
          allowNumber: false,
          allowRegExp: false,
        },
      ],
      "@typescript-eslint/restrict-plus-operands": [
        "error",
        {
          allowAny: false,
          allowBoolean: false,
          allowNullish: false,
          allowNumberAndString: false,
          allowRegExp: false,
        },
      ],

      // SECURITY: Prevent information disclosure and unsafe operations
      "@typescript-eslint/no-base-to-string": "error",
      "@typescript-eslint/no-unnecessary-condition": "error",
      "@typescript-eslint/no-array-delete": "error",
      "@typescript-eslint/no-confusing-void-expression": "error",
      "@typescript-eslint/no-meaningless-void-operator": "error",
      "@typescript-eslint/no-unnecessary-type-assertion": "error",
      "@typescript-eslint/use-unknown-in-catch-callback-variable": "error",

      // SECURITY: Additional type safety rules
      "@typescript-eslint/no-duplicate-type-constituents": "error",
      "@typescript-eslint/no-redundant-type-constituents": "error",
      "@typescript-eslint/no-unnecessary-boolean-literal-compare": "error",
      "@typescript-eslint/no-unnecessary-template-expression": "error",
      "@typescript-eslint/no-unnecessary-type-arguments": "error",
      "@typescript-eslint/no-unnecessary-type-constraint": "error",
      "@typescript-eslint/no-unnecessary-type-parameters": "error",
      "@typescript-eslint/no-for-in-array": "error",
      "@typescript-eslint/unbound-method": "error",

      // Auto-fix: prefer const where possible to help remove `let` usage
      "prefer-const": "error",

      // General security hardening
      "no-eval": "error",
  // Turn off base rule in TypeScript files; @typescript-eslint provides a
  // type-aware replacement to avoid duplicate reports and false negatives.
  "no-implied-eval": "off",
      "no-console": ["warn", { allow: ["warn", "error", "info", "debug"] }],

      // eslint-plugin-security (browser + node generic)
      "security/detect-eval-with-expression": "error",
      "security/detect-non-literal-fs-filename": "warn",
      "security/detect-non-literal-regexp": "error",
      "security/detect-non-literal-require": "error",
      "security/detect-object-injection": "error",
      "security/detect-possible-timing-attacks": "error",
      "security/detect-pseudoRandomBytes": "error",
      "security/detect-unsafe-regex": "error",
      // ReDoS vulnerability detection (eslint-plugin-redos)
      "redos/no-vulnerable": [
        "error",
        {
          "ignoreErrors": false,
          "permittableComplexities": [],
          "timeout": 10000,
          "cache": { "strategy": "conservative" },
          "checker": "auto"
        }
      ],
      "security/detect-buffer-noassert": "error",
      "security/detect-child-process": "error",
      "security/detect-disable-mustache-escape": "error",
      "security/detect-new-buffer": "error",
      "security/detect-no-csrf-before-method-override": "error",

      // DOM sanitization
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error",

      // Node-specific hardening
      ...securityNode.configs.recommended.rules,
      "security-node/detect-unhandled-async-errors": "off",

      // UNICORN CUSTOMIZATIONS: Enforce high-value patterns.
      "unicorn/prevent-abbreviations": "warn",
      "unicorn/no-null": "error",
      "unicorn/prefer-node-protocol": "error",
      "unicorn/prefer-string-starts-ends-with": "error",
      "unicorn/no-array-callback-reference": "error",
      // Security-focused unicorn rules (helpful for OWASP ASVS L3 hardening)
      // Improve regex patterns and avoid accidental ReDoS-prone constructs.
      "unicorn/better-regex": "error",
      // Disallow using document.cookie (dangerous in many CSP contexts).
      "unicorn/no-document-cookie": "error",
      // Prefer explicit .length checks to avoid ambiguous truthiness checks.
      "unicorn/explicit-length-check": "error",
      // Discourage use of Array.prototype.reduce which can introduce subtle
      // logic errors and unexpected behaviour in complex code paths.
      "unicorn/no-array-reduce": "error",
      // Discourage low-level for-loops when safer iteration constructs exist.
      "unicorn/no-for-loop": "error",
      // Enforce throwing proper Error objects (avoid throwing strings) and
      // require error messages so that failures are informative and auditable.
      "unicorn/throw-new-error": "error",
      "unicorn/error-message": "error",
      // Prefer optional catch binding to avoid unused error variables leaking
      // or being accidentally relied upon in catch blocks.
      "unicorn/prefer-optional-catch-binding": "error",
      // Disallow redundant `undefined` usage which can mask real type issues.
      "unicorn/no-useless-undefined": "error",

      // IMMUTABILITY RULES (functional plugin)
      "functional/no-let": "error",
      "functional/immutable-data": "error",
      // Prefer readonly types where possible
      "functional/prefer-readonly-type": "error",

      // Project-specific: forbid insecure/forbidden APIs
      "no-restricted-properties": [
        "error",
        {
          object: "Math",
          property: "random",
          message: "Use getSecureRandom()/getSecureRandomInt().",
        },
        {
          object: "document",
          property: "write",
          message: "Forbidden by CSP and Security Constitution.",
        },
        {
          object: "document",
          property: "writeln",
          message: "Forbidden by CSP and Security Constitution.",
        },
        {
          object: "crypto",
          property: "createHash",
          message: "Avoid weak algorithms like MD5/SHA1; use SHA-256 or better.",
        },
      ],
      // Local: discourage direct usage of legacy POSTMESSAGE_MAX_* constants in new runtime logic.
      // (Warn for now to allow incremental refactor in postMessage.ts.)
      "local/no-postmessage-constant-usage": "error",

      // OWASP ASVS L3 Security Hardening Rules - Custom Local Plugin Rules
      // Enforce memory hygiene for sensitive data (secureWipe in finally blocks)
      "local/enforce-secure-wipe": "error",
      // Enforce state machine integrity (sealed configuration checks)
      "local/no-unsealed-configuration": "error", 
      // Enforce typed error handling for programmatic error handling
      "local/throw-typed-errors": ["error", {
        "allowedGenericErrors": [] // No exceptions - always use typed errors
      }],
      // Enforce use of shared TextEncoder/TextDecoder instances for performance and memory efficiency
      "local/enforce-text-encoder-decoder": "error",
      // Prevent direct crypto.subtle usage, enforce high-level security-kit abstractions
      "local/no-direct-subtle-crypto": ["error", {
        "allowInFiles": ["src/encoding-utils.ts", "src/capabilities.ts"],
        "allowedMethods": []
      }],
      // Ensure test-only APIs are properly guarded against production usage
      "local/enforce-test-api-guard": "error",
      
      // NEW HIGH-PRIORITY SECURITY RULES (OWASP ASVS L3)
      // Prevent secure logging bypass - forces use of secureDevLog/reportProdError
      "local/enforce-secure-logging": ["error", {
        "allowInFiles": ["utils.ts", "dev-logger.ts", "reporting.ts", "/tests/", "/demo/", "/benchmarks/"],
        "allowedMethods": ["warn", "error", "info", "debug"]
      }],
      // Enforce error sanitization at logging boundaries to prevent sensitive data leakage
      "local/enforce-error-sanitization-at-boundary": ["error", {
        "approvedSanitizers": ["sanitizeErrorForLogs", "sanitizeErrorMessage", "redactError"],
        "loggingFunctions": ["secureDevLog", "secureDevelopmentLog", "reportProdError", "console.error", "console.warn", "console.log", "console.info"]
      }],
      // CRITICAL: Constitutional mandate - enforce visibility change abort pattern §2.11
      "local/enforce-visibility-abort-pattern": ["error", {
        "sensitiveOperations": ["secureCompareAsync", "secureWipeAsync", "generateSecureId", "generateSecureString", "SecureApiSigner.create", "sendSecurePostMessage", "crypto.subtle.digest", "crypto.subtle.sign", "crypto.subtle.verify", "fetch"]
      }],
      // Prevent direct URL constructor usage, require hardened URL utilities
      "local/no-direct-url-constructor": ["error", {
        "allowInFiles": ["url.ts", "/src/url.ts", "/tests/", "/demo/", "/benchmarks/"],
        "suggestedAlternatives": ["validateURL", "createSecureURL", "normalizeOrigin", "parseSecureURL"]
      }],
      // Enforce configuration immutability per Principle of Least Privilege
      "local/enforce-config-immutability": ["error", {
        "configPatterns": ["config$", "settings$", "options$", "defaults$", "constants$"]
      }],
      
      // POSTMESSAGE & SIGNING SECURITY RULES
      // Enforce proper postMessage listener configuration in production
      "local/enforce-secure-postmessage-listener": ["error", {
        "requireValidation": true,
        "requireOriginRestriction": true,
        "testDirectoryPatterns": ["/tests/", "/test/", "/__tests__/", "/demo/", "/examples/", "/benchmarks/"]
      }],
      // Enforce secure integrity settings for SecureApiSigner
      "local/enforce-secure-signer-integrity": ["error", {
        "forbidIntegrityNone": true,
        "warnIntegrityCompute": true,
        "requireHashForIntegrityRequire": true
      }],
      // Prevent insecure nonce store usage in production
      "local/no-insecure-nonce-store": ["error", {
        "allowedProductionStores": ["RedisNonceStore", "DatabaseNonceStore", "DistributedNonceStore"]
      }],
      // Ensure postMessage configuration consistency
      "local/enforce-postmessage-config-consistency": "error",
  // Require normalization of untrusted UTF-8 inputs before usage in sinks (Unicode hardening boundary)
  "local/require-untrusted-input-normalization": "error",
      
      // NEW SECURITY HARDENING RULES (OWASP ASVS L3)
      // Prevent Unicode normalization attacks (ASVS V5.1.4)
      "local/no-un-normalized-string-comparison": "error",
      // Enforce centralized configuration architecture (Security Constitution §1.3, §1.9)
      "local/no-direct-process-env": ["error", {
        "allowedFiles": ["config.ts", "environment.ts", "eslint.config.mjs", "vitest.config.ts", "tsup.config.ts"]
      }],
      // Enforce "Fail Loudly, Fail Safely" principle (Security Constitution §1.4)
      "local/no-broad-exception-swallow": ["error", {
        "approvedReporters": ["reportProdError", "secureDevLog", "secureDevelopmentLog"],
        "allowedRecoveryPatterns": ["setFallbackState", "activateCircuitBreaker", "switchToSafeMode"]
      }],
      // Ensure security kit is sealed at startup (Security Constitution requirement)
      "local/enforce-sealed-kit-startup": ["error", {
        "entryPointPatterns": ["index.ts", "main.ts", "/src/index.ts"],
        "sealFunctionNames": ["sealSecurityKit", "_sealSecurityKit"]
      }],
      // Prevent Math.random() in security contexts (cryptographic integrity)
      "local/no-math-random-security-context": ["error", {
        "allowedNonSecurityFiles": ["/demo/", "/benchmarks/", "/tests/", "animation", "simulation"]
      }],
      // Enforce centralized crypto utilities over direct Web Crypto API access
      "local/enforce-security-kit-imports": ["error", {
        "allowedFiles": ["crypto.ts", "state.ts", "/src/crypto.ts", "/src/state.ts", "/tests/"],
        "securityKitModule": "./crypto.ts"
      }],

      // Additional hardening rules (aggressively apply to src/**)
      "eqeqeq": "error",
      "no-proto": "error",
      "guard-for-in": "error",
      "prefer-object-has-own": "error",
  // base "no-implied-eval" remains turned off in TS files (use the
  // @typescript-eslint version). Do not enable the base rule here.
      "no-new-func": "error",
      "no-throw-literal": "error",
      "consistent-return": "error",
      "default-case": "error",
      "require-unicode-regexp": "error",
      "no-control-regex": "error",
      "no-implicit-globals": "error",
  // Escalate local secret equality rule for sensitive areas.
  // Note: this rule does not accept options in its schema; scope by file
  // overrides if path-specific behavior is needed.
  "local/no-secret-eq": "error",
      // Detect potential leaked secrets and high-entropy strings in source files
      // Use the plugin's rule to harden against accidental secret leaks.
      "no-secrets/no-secrets": [
        "error",
        {
          "tolerance": 5,
          "ignoreIdentifiers": [],
          "ignoreContent": [],
          "ignoreModules": true,
          "ignoreCase": false
        }
      ],
      // Enable Microsoft SDL rules that align with OWASP ASVS hardening
      "sdl/no-inner-html": "error",
      "sdl/no-document-write": "error",
      "sdl/no-postmessage-star-origin": "error",
      "sdl/no-insecure-url": "error",
      "sdl/no-document-domain": "error",
      "sdl/no-unsafe-alloc": "error",
      // TypeScript strictness
      "@typescript-eslint/strict-boolean-expressions": "error",
      // Import hygiene
      "import/no-extraneous-dependencies": ["error", { "devDependencies": false, "optionalDependencies": false }],
      "import/no-unresolved": "error",
    },
  },

  // Server: lint server-side code with TypeScript-aware rules and Node/security plugins
  {
    files: ["server/**/*.ts", "server/**/*.tsx", "server/**/*.js"],
    languageOptions: {
      parser: tsParserObj,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
  projectService: true,
  tsconfigRootDir: process.cwd(),
      },
    },
    settings: {
      "import/parsers": {
        "@typescript-eslint/parser": [".ts", ".tsx"],
      },
      "import/resolver": {
        typescript: {
          alwaysTryTypes: true,
        },
        node: {
          extensions: [".js", ".cjs", ".mjs", ".ts", ".tsx", ".json"],
        },
      },
    },
    plugins: {
      "@typescript-eslint": tseslintPlugin,
      n: nodePlugin,
      unicorn: unicornPlugin,
      "security-node": securityNode,
      "no-unsanitized": noUnsanitized,
      redos: redosPlugin,
      prettier: prettierPlugin,
      functional: functionalPlugin,
      local: localPlugin,
      security: securityPlugin,
      sdl: sdlPlugin,
    },
    rules: {
      "sonarjs/cognitive-complexity": ["error", 18],
      "prettier/prettier": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/ban-ts-comment": [
        "error",
        {
          "ts-expect-error": "allow-with-description",
          "ts-ignore": "allow-with-description",
          "ts-nocheck": true,
          "ts-check": false,
          minimumDescriptionLength: 10,
        },
      ],
      "@typescript-eslint/no-floating-promises": [
        "error",
        { ignoreVoid: true },
      ],
      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-call": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/no-unsafe-return": "error",
      "@typescript-eslint/no-unsafe-argument": "error",
      "@typescript-eslint/no-unsafe-enum-comparison": "error",
      "@typescript-eslint/no-unsafe-unary-minus": "error",

      // SECURITY: Template expression and operand restrictions (OWASP ASVS L3)
      "@typescript-eslint/restrict-template-expressions": [
        "error",
        {
          allowAny: false,
          allowBoolean: false,
          allowNever: false,
          allowNullish: false,
          allowNumber: false,
          allowRegExp: false,
        },
      ],
      "@typescript-eslint/restrict-plus-operands": [
        "error",
        {
          allowAny: false,
          allowBoolean: false,
          allowNullish: false,
          allowNumberAndString: false,
          allowRegExp: false,
        },
      ],

      // SECURITY: Prevent information disclosure and unsafe operations
      "@typescript-eslint/no-base-to-string": "error",
      "@typescript-eslint/no-unnecessary-condition": "error",
      "@typescript-eslint/no-array-delete": "error",
      "@typescript-eslint/no-confusing-void-expression": "error",
      "@typescript-eslint/no-meaningless-void-operator": "error",
      "@typescript-eslint/no-unnecessary-type-assertion": "error",
      "@typescript-eslint/use-unknown-in-catch-callback-variable": "error",

      // SECURITY: Additional type safety rules
      "@typescript-eslint/no-duplicate-type-constituents": "error",
      "@typescript-eslint/no-redundant-type-constituents": "error",
      "@typescript-eslint/no-unnecessary-boolean-literal-compare": "error",
      "@typescript-eslint/no-unnecessary-template-expression": "error",
      "@typescript-eslint/no-unnecessary-type-arguments": "error",
      "@typescript-eslint/no-unnecessary-type-constraint": "error",
      "@typescript-eslint/no-unnecessary-type-parameters": "error",
      "@typescript-eslint/no-for-in-array": "error",
      "@typescript-eslint/unbound-method": "error",

      "no-eval": "error",
      "no-implied-eval": "error",
      "no-console": ["warn", { allow: ["warn", "error", "info", "debug"] }],
      "security/detect-non-literal-regexp": "error",
      "security/detect-object-injection": "error",
      "security/detect-unsafe-regex": "error",
      // ReDoS vulnerability detection (eslint-plugin-redos)
      "redos/no-vulnerable": [
        "error",
        {
          "ignoreErrors": false,
          "permittableComplexities": [],
          "timeout": 10000,
          "cache": { "strategy": "conservative" },
          "checker": "auto"
        }
      ],
      // Bring in most of security-node. We've fixed a small AST shape that
      // previously triggered a plugin crash, so enable the recommended rules.
      ...securityNode.configs.recommended.rules,
      "functional/no-let": "error",
      "functional/immutable-data": "error",
  // Server-specific unicorn rules: avoid deprecated/unsafe Node APIs and
  // encourage safer patterns in server-side code.
  "unicorn/no-new-buffer": "error",
  "unicorn/no-process-exit": "error",
  "unicorn/better-regex": "error",
  // Server: require thrown values to be proper Error instances with messages
  "unicorn/throw-new-error": "error",
  "unicorn/error-message": "error",
  "unicorn/prefer-optional-catch-binding": "error",
  "unicorn/no-useless-undefined": "error",
      // Server-specific restricted properties (discourage weak crypto and insecure randomness)
      "no-restricted-properties": [
        "error",
        {
          object: "Math",
          property: "random",
          message: "Use getSecureRandom()/getSecureRandomInt().",
        },
        {
          object: "crypto",
          property: "createHash",
          message: "Avoid weak algorithms like MD5/SHA1; use SHA-256 or better.",
        },
      ],
  // Microsoft SDL recommended rules provide additional security checks for web apps.
  // Merge in a minimal selection of their recommended config to avoid noisy stylistic rules.
  ...((sdlPlugin && sdlPlugin.configs && sdlPlugin.configs.recommended && sdlPlugin.configs.recommended.rules) || {}),
  // Microsoft SDL rules for server code
  "sdl/no-inner-html": "error",
  "sdl/no-document-write": "error",
  "sdl/no-postmessage-star-origin": "error",
  "sdl/no-insecure-url": "error",
  "sdl/no-document-domain": "error",
  "sdl/no-unsafe-alloc": "error",
    // Require normalization boundary for untrusted UTF-8 input in server code as well
    "local/require-untrusted-input-normalization": "error",
  // Deprecated API detection intentionally omitted to avoid adding
  // `eslint-plugin-deprecation`. We prefer not to add that dependency.
    },
  },
  // Allow internal encoder/decoder usage inside url.ts which implements safe wrappers
  {
    files: ["src/url.ts"],
    rules: {
      "no-restricted-globals": "off",
    },
  },
  // Allow the legacy `dev-logger.ts` filename; enforce full name elsewhere.
  {
    files: ["src/dev-logger.ts"],
    rules: {
      // The codebase historically used 'dev-logger.ts'; allow this single
      // exception rather than renaming the file to avoid churn across tests.
      "unicorn/prevent-abbreviations": "off",
    },
  },
  // Scoped exception: allow safe internal getRandomValues usage in a small set
  // of modules that implement hardened wrappers (these files must implement
  // secure wiping and iteration caps per project constitution).
  {
    files: ["src/crypto/**", "src/url.ts"],
    rules: {
      "no-restricted-properties": "off",
    },
  },
  // Library-wide overrides: allow legitimate getRandomValues usage and
  // NOTE: Removed the previous relaxation for `src/**` to enforce stricter
  // security checks across the library per owner's request. If particular
  // files require exceptions (e.g., safe internal implementations), scope them
  // explicitly with targeted overrides below.

  // Tests: downgrade noisy legacy checks to warnings so lint remains actionable
  {
    files: ["tests/**", "tests/old_tests/**"],
    // Apply Vitest recommended rules plus some legacy relaxations so tests
    // are checked for common issues but don't block on historical patterns.
    ...vitestPlugin.configs.recommended,
    settings: {
      vitest: {
        typecheck: true,
      },
    },
    languageOptions: {
      globals: {
        ...vitestPlugin.environments.env.globals,
      },
    },
    plugins: { redos: redosPlugin },
    
    rules: {
      "security/detect-object-injection": "warn",
      "no-restricted-properties": "off",
      "no-unsanitized/property": "warn",
      "security/detect-unsafe-regex": "warn",
      // ReDoS detection in tests: warn to avoid blocking but keep checks enabled
      "redos/no-vulnerable": [
        "warn",
        {
          "ignoreErrors": false,
          "permittableComplexities": [],
          "timeout": 10000,
          "cache": true,
          "checker": "auto"
        }
      ],
      // Deprecated API detection intentionally omitted from tests as well.
      "@typescript-eslint/no-deprecated": "warn",
      "@typescript-eslint/no-implied-eval": "warn",
      "@typescript-eslint/no-unsafe-assignment": "warn",
      "@typescript-eslint/no-unsafe-call": "warn",
      "@typescript-eslint/no-unsafe-member-access": "warn",
      "@typescript-eslint/no-unsafe-return": "warn",
      "@typescript-eslint/no-empty-function": "warn",
      // Warn about potential leaked secrets in tests to surface issues
      "no-secrets/no-secrets": [
        "warn",
        {
          "tolerance": 4,
          "ignoreModules": true
        }
      ],
    },
  },
  // Local rule: warn on secret-like identifier equality comparisons
  // NOTE: The `local/no-secret-eq` rule is configured above and scoped for
  // sensitive paths. Avoid defining it multiple times to prevent ESLint key
  // conflicts.
];
