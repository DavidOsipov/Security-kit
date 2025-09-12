import { RuleTester } from "eslint";
import rule from "../../tools/eslint-rules/enforce-security-kit-imports.js";

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2020, sourceType: "module" },
  },
});

ruleTester.run("enforce-security-kit-imports", rule, {
  valid: [
    // Proper imports from security-kit
    "import { getSecureRandomBytesSync } from '@david-osipov/security-kit';",
    "import { generateSecureIdSync, secureCompareAsync } from '@david-osipov/security-kit';",
    "const { createAesGcmKey256 } = require('@david-osipov/security-kit');",

    // Non-crypto operations should be allowed
    "const hash = 'some-hash';",
    "console.log('not crypto');",

    // Destructuring from security-kit
    "const { getSecureRandomInt, generateSecureStringSync } = require('@david-osipov/security-kit');",

    // Global crypto usage (allowed for compatibility)
    "crypto.subtle.generateKey(algo, true, ['encrypt', 'decrypt']);",
    "self.crypto.getRandomValues(new Uint8Array(32));",
    "globalThis.crypto.subtle.sign('HMAC', key, data);",
  ],
  invalid: [
    // Direct crypto.subtle usage
    {
      code: "crypto.subtle.generateKey(algo, true, ['encrypt']);",
      errors: [
        { messageId: "noSubtle" },
        { messageId: "useSecurityKit" },
        { messageId: "importSecurityKit" }
      ],
    },
    {
      code: "window.crypto.subtle.encrypt(algo, key, data);",
      errors: [{ messageId: "noSubtleGeneric" }],
    },
    // Destructuring from crypto
    {
      code: "const { subtle } = crypto;",
      errors: [{ messageId: "noSubtleGeneric" }],
    },
    {
      code: "const { getRandomValues } = crypto;",
      errors: [{ messageId: "useSecurityKit" }],
    },
    // Method-specific violations
    {
      code: "crypto.subtle.sign('HMAC', key, data);",
      errors: [
        { messageId: "noSubtle" },
        { messageId: "useSecurityKit" },
        { messageId: "importSecurityKit" }
      ],
    },
    {
      code: "crypto.subtle.verify('HMAC', key, signature, data);",
      errors: [
        { messageId: "noSubtle" },
        { messageId: "useSecurityKit" },
        { messageId: "importSecurityKit" }
      ],
    },
    // Aliases should be detected
    {
      code: `
        const c = crypto;
        c.subtle.generateKey(algo, true, ['encrypt']);
      `,
      errors: [
        { messageId: "importSecurityKit" },
        { messageId: "noSubtle" },
        { messageId: "useSecurityKit" }
      ],
    },
    {
      code: `
        const { subtle: s } = crypto;
        s.generateKey(algo, true, ['encrypt']);
      `,
      errors: [
        { messageId: "noSubtleGeneric" }
      ],
    },
  ],
});