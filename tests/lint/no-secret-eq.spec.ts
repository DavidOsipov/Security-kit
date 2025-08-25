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
  ],
});
