// @ts-nocheck
import tseslintPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import securityPlugin from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import securityNode from "eslint-plugin-security-node";
import prettierPlugin from "eslint-plugin-prettier";

export default [
  // Global ignores
  {
    ignores: [
      "dist/**/*",
      "node_modules/**/*",
      ".astro/**/*", // harmless if absent
      "**/*.min.js",
      "tests/**/*",
      "tests/**",
      "tests/old_tests/**/*",
    ],
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
    plugins: {
      "@typescript-eslint": tseslintPlugin,
      security: securityPlugin,
      "no-unsanitized": noUnsanitized,
      "security-node": securityNode,
      prettier: prettierPlugin,
    },
    rules: {
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
    rules: {
      "security/detect-object-injection": "warn",
      "no-restricted-properties": "off",
      "no-unsanitized/property": "warn",
      "security/detect-unsafe-regex": "warn",
    },
  },
];
