import { RuleTester } from "eslint";
import rule from "../../tools/eslint-rules/enforce-security-suppression-format.js";

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2020, sourceType: "module" },
  },
});

ruleTester.run("enforce-security-suppression-format", rule, {
  valid: [
    // Non-security rules should be allowed without justification
  "/* eslint-disable no-console */ console.log('test');",
  `// eslint-disable-next-line no-unused-vars
const x = 1;`,

    // Security rules with proper justification (using test prefixes)
    {
      code: `
        /* SECURITY: Using controlled Date.now() for logging only, not entropy */
        /* eslint-disable-next-line no-console */
        console.log(Date.now());
      `,
      options: [{ securityRulePrefixes: ["no-console", "no-unused-vars", "no-undef"] }]
    },
    {
      code: `
        // REVIEWED: This JSON parsing is safe as input is from trusted source
        // eslint-disable-next-line no-undef
        const data = JSON.parse(input);
      `,
      options: [{ securityRulePrefixes: ["no-console", "no-unused-vars", "no-undef"] }]
    },
    {
      code: `
        /* SAFE: Token is encrypted before storage */
        /* eslint-disable-next-line no-unused-vars */
        const token = encryptedToken;
      `,
      options: [{ securityRulePrefixes: ["no-console", "no-unused-vars", "no-undef"] }]
    },
    // Multiple rules with justification
    {
      code: `
        /* AUDITED: Both operations are safe in this controlled context */
        /* eslint-disable-next-line no-console, no-unused-vars */
        const timestamp = Date.now();
        const key = 'safe-key';
      `,
      options: [{ securityRulePrefixes: ["no-console", "no-unused-vars", "no-undef"] }]
    },
  ],
  invalid: [
    // Security rule suppression without justification
    {
      code: `
        // eslint-disable-next-line no-console
        const time = Date.now();
      `,
      options: [{ securityRulePrefixes: ["no-console", "no-unused-vars", "no-undef"] }],
      errors: [{ messageId: "invalidSuppressionFormat" }],
    },
    {
      code: `
        /* eslint-disable no-unused-vars */
        const data = JSON.parse(input);
      `,
      options: [{ securityRulePrefixes: ["no-console", "no-unused-vars", "no-undef"] }],
      errors: [{ messageId: "invalidSuppressionFormat" }],
    },
    // Suppression without required keywords
    {
      code: `
        /* This is just a comment without security keywords */
        // eslint-disable-next-line no-undef
        const secret = 'token';
      `,
      options: [{ securityRulePrefixes: ["no-console", "no-unused-vars", "no-undef"] }],
      errors: [{ messageId: "invalidSuppressionFormat" }],
    },
    // Multiple security rules without justification
    {
      code: `
        /* eslint-disable-next-line no-console, no-unused-vars */
        if (token === otherToken) {
          secretKey = 'value';
        }
      `,
      options: [{ securityRulePrefixes: ["no-console", "no-unused-vars", "no-undef"] }],
      errors: [
        { messageId: "invalidSuppressionFormat" },
        { messageId: "invalidSuppressionFormat" }
      ],
    },
  ],
});