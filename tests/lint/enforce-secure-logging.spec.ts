import { RuleTester } from "eslint";
import rule from "../../tools/eslint-rules/enforce-secure-logging.js";

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2020, sourceType: "module" },
  },
});

ruleTester.run("enforce-secure-logging", rule, {
  valid: [
    // Non-logging calls should be allowed
    "console.error('Error message');",
    "console.warn('Warning message');",
    "console.info('Info message');",

    // Logging with non-sensitive data
    "console.log('User count:', count);",
    "console.log('Request processed successfully');",

    // Logging with sanitized data
    "console.log('User ID:', sanitize(userId));",
    "console.log('Token length:', token.length);",

    // Non-console logging
    "logger.info('Request received');",
    "log('Debug message');",
  ],
  invalid: [
    // Direct console logging of sensitive data
    {
      code: "console.log('Token:', token);",
      errors: [{ messageId: "useSecureLogging" }],
      output: "secureDevLog('info', 'Component', 'Token:', token);"
    },
    {
      code: "console.error('Password:', password);",
      errors: [{ messageId: "useSecureLogging" }],
      output: "secureDevLog('error', 'Component', 'Password:', password);"
    },
    // Multiple sensitive variables
    {
      code: "console.log('Credentials:', { username, password, token });",
      errors: [{ messageId: "useSecureLogging" }],
      output: "secureDevLog('info', 'Component', 'Credentials:', { username, password, token });"
    },
    // Aliased console usage
    {
      code: `
        const c = console;
        c.log('Secret key:', secretKey);
      `,
      errors: [{ messageId: "useSecureLogging" }],
      output: `
        const c = console;
        secureDevLog('info', 'Component', 'Secret key:', secretKey);
      `
    },
    {
      code: `
        const { log } = console;
        log('JWT:', jwtToken);
      `,
      errors: [{ messageId: "useSecureLogging" }],
      output: `
        const { log } = console;
        secureDevLog('info', 'Component', 'JWT:', jwtToken);
      `
    },
    // Destructuring console methods
    {
      code: `
        const { error, warn } = console;
        error('API Key:', apiKey);
      `,
      errors: [{ messageId: "useSecureLogging" }],
      output: `
        const { error, warn } = console;
        secureDevLog('error', 'Component', 'API Key:', apiKey);
      `
    },
    // Sensitive data in template literals
    {
      code: "console.log(`User token: ${userToken}`);",
      errors: [{ messageId: "useSecureLogging" }],
      output: "secureDevLog('info', 'Component', `User token: ${userToken}`);"
    },
    // Object spread with sensitive data
    {
      code: "console.log('Config:', { ...config, secret: apiSecret });",
      errors: [{ messageId: "useSecureLogging" }],
      output: "secureDevLog('info', 'Component', 'Config:', { ...config, secret: apiSecret });"
    },
  ],
});