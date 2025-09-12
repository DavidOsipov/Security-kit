import { RuleTester } from "eslint";
import rule from "../../tools/eslint-rules/no-secret-eq.js";

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2020, sourceType: "module" },
  },
});

ruleTester.run("no-secret-eq", rule, {
  valid: [
    "if (a === b) {}",
    "if (token === 'abc') {}", // Identifier === Literal should not be flagged by the tuned rule
    "if (userId === otherId) {}",
    // Non-secret identifiers
    "if (userName === otherName) {}",
    "if (count === total) {}",
  ],
  invalid: [
    {
      code: "if (token === otherToken) {}",
      errors: [{ messageId: "preferSecureCompare" }],
    },
    {
      code: "if (secretKey === key) {}",
      errors: [{ messageId: "preferSecureCompare" }],
    },
    // MemberExpression comparisons
    {
      code: "if (user.token === expectedToken) {}",
      errors: [{ messageId: "preferSecureCompare" }],
    },
    {
      code: "if (config.secret === storedSecret) {}",
      errors: [{ messageId: "preferSecureCompare" }],
    },
    // Additional secret names
    {
      code: "if (jwt === storedJwt) {}",
      errors: [{ messageId: "preferSecureCompare" }],
    },
    {
      code: "if (bearerToken === authToken) {}",
      errors: [{ messageId: "preferSecureCompare" }],
    },
    // Typed array comparisons
    {
      code: "if (keyBuffer === otherBuffer) {}",
      errors: [{ messageId: "preferSecureCompareBytes" }],
    },
    {
      code: "if (uint8Key === storedKey) {}",
      errors: [{ messageId: "preferSecureCompareBytes" }],
    },
    // String literal comparisons with secrets
    {
      code: "if (token === 'hardcoded-token') {}",
      errors: [{ messageId: "preferSecureCompare" }],
    },
    {
      code: "if ('secret-key' === apiKey) {}",
      errors: [{ messageId: "preferSecureCompare" }],
    },
  ],
});

// Test with custom configuration
const ruleTesterWithConfig = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2020, sourceType: "module" },
  },
});

ruleTesterWithConfig.run("no-secret-eq with custom config", rule, {
  valid: [
    // Non-secret names should not trigger with custom patterns
    {
      code: "if (regularVariable === other) {}",
      options: [{ secretPatterns: ["customSecret"] }],
    },
  ],
  invalid: [
    {
      code: "if (customSecret === other) {}",
      options: [{ secretPatterns: ["customSecret"] }],
      errors: [{ messageId: "preferSecureCompare" }],
    },
    {
      code: "if (myToken === stored) {}",
      options: [{ additionalSecretNames: ["myToken"] }],
      errors: [{ messageId: "preferSecureCompare" }],
    },
  ],
});
