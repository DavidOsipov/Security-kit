import { RuleTester } from "eslint";
import rule from "../../tools/eslint-rules/no-date-entropy-security-context.js";

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2020, sourceType: "module" },
  },
});

ruleTester.run("no-date-entropy-security-context", rule, {
  valid: [
    // Non-security contexts should be allowed
    "console.log(Date.now());",
    "const timestamp = Date.now();",
    "function logTime() { return Date.now(); }",

    // Math.random in non-security contexts
    "const random = Math.random();",
    "function getRandom() { return Math.random(); }",

    // Security functions using proper crypto
    "function generateToken() { return crypto.getRandomValues(new Uint8Array(32)); }",
    "function createSecureId() { return getSecureRandomBytesSync(16); }",

    // Aliases in non-security contexts
    "const D = Date; const time = D.now();",
    "const M = Math; const rand = M.random();",
  ],
  invalid: [
    // Date.now() in security-critical functions
    {
      code: `
        function generateToken() {
          return Date.now().toString();
        }
      `,
      errors: [{ messageId: "avoidDateEntropy" }],
    },
    {
      code: `
        function createSecureId() {
          const timestamp = Date.now();
          return timestamp + Math.random();
        }
      `,
      errors: [
        { messageId: "avoidDateEntropy" },
        { messageId: "avoidMathRandom" }
      ],
    },
    // new Date() in security contexts
    {
      code: `
        function generateNonce() {
          return new Date().getTime().toString();
        }
      `,
      errors: [{ messageId: "avoidDateEntropy" }],
    },
    // Date() constructor in security contexts
    {
      code: `
        function createToken() {
          return Date() + Math.random();
        }
      `,
      errors: [
        { messageId: "avoidDateEntropy" },
        { messageId: "avoidMathRandom" }
      ],
    },
    // Aliases in security contexts
    {
      code: `
        const D = Date;
        function generateKey() {
          return D.now().toString();
        }
      `,
      errors: [{ messageId: "avoidDateEntropy" }],
    },
    {
      code: `
        const M = Math;
        function createSecret() {
          return M.random().toString();
        }
      `,
      errors: [{ messageId: "avoidMathRandom" }],
    },
    // Performance.now() in security contexts
    {
      code: `
        function generateSecureToken() {
          return performance.now().toString();
        }
      `,
      errors: [{ messageId: "avoidDateInSecurityContext" }],
    },
  ],
});