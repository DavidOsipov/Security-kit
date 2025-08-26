// @ts-nocheck
import tseslintPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
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
import localPlugin from "./tools/eslint-plugin-local/index.js";
import unicornPlugin from "eslint-plugin-unicorn";
import functionalPlugin from "eslint-plugin-functional";

export default [
  // Global ignores
  {
    ignores: [
      "dist/**/*",
      "node_modules/**/*",
      "**/*.min.js",
      "tests/**/*",
      "tests/**",
      "tests/old_tests/**/*",
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
  // Intentionally do NOT include the full unicorn recommended config here because
  // it is extremely opinionated and would globally enforce many stylistic rules
  // that are noisy for an existing codebase. We instead opt-in to a small set of
  // high-value unicorn rules below with measured severities.
  // NOTE: Node-specific rules must not apply to browser-targeted `src/**`.
  // We'll enable a focused set of `n/*` rules only for tooling/config files.
  {
    files: ["scripts/**", "scripts/**/*.ts", "*.config.*", "eslint.config.js"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        tsconfigRootDir: process.cwd(),
        project: false,
      },
    },
    plugins: { n: nodePlugin, "@typescript-eslint": tseslintPlugin },
    rules: {
      "n/no-unsupported-features/node-builtins": "warn",
      "n/no-missing-import": "warn",
      "n/no-unpublished-import": "warn",
    },
  },
  {
    files: ["src/**/*.ts", "src/**/*.tsx"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        // Enable typed linting for strict rules
        projectService: true,
        tsconfigRootDir: process.cwd(),
        allowDefaultProject: true,
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
      security: securityPlugin,
      "no-unsanitized": noUnsanitized,
      "security-node": securityNode,
      prettier: prettierPlugin,
      // local plugin mapping (resolves to tools/eslint-plugin-local)
      local: localPlugin,
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
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/ban-ts-comment": [
        "warn",
        { "ts-ignore": "allow-with-description" },
      ],
      "@typescript-eslint/no-floating-promises": [
        "error",
        { ignoreVoid: true },
      ],

      // Auto-fix: prefer const where possible to help remove `let` usage
      // This works well with the functional/no-let rule because ESLint's fixer
      // can convert non-reassigned lets into const automatically.
      "prefer-const": "error",

      // General security hardening
      "no-eval": "error",
      "no-implied-eval": "error",
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
      // UPGRADE: Change from "warn" to "error". There is no excuse for `any`.
      "@typescript-eslint/no-explicit-any": "error",

      // UPGRADE: Change from "warn" to "error". Force developers to justify suppression.
      "@typescript-eslint/ban-ts-comment": [
        "error",
        {
          "ts-expect-error": "allow-with-description",
          "ts-ignore": "allow-with-description", // Keep this for now, but be strict
          "ts-nocheck": true,
          "ts-check": false,
          "minimumDescriptionLength": 10 // Force a real explanation
        }
      ],
      // NEW: Add rules that leverage your type information
      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-call": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/no-unsafe-return": "error",

  // UNICORN CUSTOMIZATIONS: Enforce high-value patterns.
  // Promote these to errors to enforce elite-level patterns across the
  // library; fixes are often automatic or small mechanical edits.
  "unicorn/prevent-abbreviations": "error",
  "unicorn/no-null": "error",
  "unicorn/prefer-node-protocol": "error",
  "unicorn/prefer-string-starts-ends-with": "error",
    "unicorn/no-array-callback-reference": "error",

  // IMMUTABILITY RULES (functional plugin)
  // Enforce immutability strictly for a security-critical library.
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
      ],
    },
  },
  // Allow internal encoder/decoder usage inside url.ts which implements safe wrappers
  {
    files: ["src/url.ts"],
    rules: {
      "no-restricted-globals": "off",
    },
  },
  // Library-wide overrides: allow legitimate getRandomValues usage and
  // relax object-injection checks for internal implementations.
  {
    files: ["src/**"],
    rules: {
      "no-restricted-properties": "off",
      "security/detect-object-injection": "off",
      "no-restricted-globals": "off",
    },
  },
  
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
    rules: {
      "security/detect-object-injection": "warn",
      "no-restricted-properties": "off",
      "no-unsanitized/property": "warn",
      "security/detect-unsafe-regex": "warn",
    },
  },
  // Local rule: warn on secret-like identifier equality comparisons
  {
    files: ["src/**","server/**","scripts/**"],
    plugins: { local: localPlugin },
    rules: {
      // Use a relative require to load the local rule implementation.
      "local/no-secret-eq": "warn",
    },
  },
];
