import { RuleTester } from "eslint";
import rule from "../../tools/eslint-rules/no-plaintext-secret-storage.js";

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2020, sourceType: "module" },
  },
});

ruleTester.run("no-plaintext-secret-storage", rule, {
  valid: [
    // Non-secret variables should be allowed
    "const userId = '123';",
    "const name = 'John';",
    "let count = 0;",

    // Encrypted storage should be allowed
    "secureEncryptedStorage.setItem('token', encryptedToken);",
    "encryptedStorage.setItem('key', cipherText);",
    "encryptAndStore('secret', sensitiveData);",

    // Object properties that aren't secrets
    "const user = { id: 123, name: 'John' };",
    "config.database = { host: 'localhost' };",

    // Non-sensitive localStorage usage
    "localStorage.setItem('theme', 'dark');",
    "sessionStorage.setItem('language', 'en');",
  ],
  invalid: [
    // Plaintext secret variables
    {
      code: "const token = 'secret-token-123';",
      errors: [{ messageId: "plaintextSecretStorage" }],
    },
    {
      code: "let password = 'my-password';",
      errors: [{ messageId: "plaintextSecretStorage" }],
    },
    // Secret assignments
    {
      code: "secretKey = 'abc123';",
      errors: [{ messageId: "plaintextSecretStorage" }],
    },
    // Object properties with secrets
    {
      code: "const config = { apiKey: 'secret-key' };",
      errors: [{ messageId: "insecureObjectStorage" }],
    },
    {
      code: "user.token = 'jwt-token';",
      errors: [{ messageId: "insecureObjectStorage" }],
    },
    // localStorage with sensitive data
    {
      code: "localStorage.setItem('authToken', 'secret-token');",
      errors: [{ messageId: "insecureLocalStorage" }],
    },
    {
      code: "sessionStorage.setItem('password', 'user-password');",
      errors: [{ messageId: "insecureLocalStorage" }],
    },
    // Sensitive keys in localStorage
    {
      code: "localStorage.setItem('token', userToken);",
      errors: [
        { messageId: "insecureLocalStorage" },
        { messageId: "plaintextSecretStorage" }
      ],
    },
    // Insecure storage function calls
    {
      code: "storeData('secret', sensitiveValue);",
      errors: [{ messageId: "plaintextSecretStorage" }],
    },
  ],
});