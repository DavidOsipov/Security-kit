/**
 * @fileoverview Comprehensive autofix tests for all custom ESLint rules
 * Tests the autofix functionality of all rules that support `fixable: "code"`
 * Ensures autofixes are safe, correct, and preserve code semantics
 */
import { RuleTester } from "eslint";

// Import all fixable rules
import noUnNormalizedStringComparisonRule from "../../tools/eslint-rules/no-un-normalized-string-comparison.js";
import throwTypedErrorsRule from "../../tools/eslint-rules/throw-typed-errors.js";
import enforceSecureWipeRule from "../../tools/eslint-rules/enforce-secure-wipe.js";
import enforceSecureLoggingRule from "../../tools/eslint-rules/enforce-secure-logging.js";
import enforcePostmessageConfigConsistencyRule from "../../tools/eslint-rules/enforce-postmessage-config-consistency.js";
import enforceTextEncoderDecoderRule from "../../tools/eslint-rules/enforce-text-encoder-decoder.js";
import enforceErrorSanitizationAtBoundaryRule from "../../tools/eslint-rules/enforce-error-sanitization-at-boundary.js";
import noUnsafeObjectMergeRule from "../../tools/eslint-rules/no-unsafe-object-merge.js";
import noPostmessageConstantUsageRule from "../../tools/eslint-rules/no-postmessage-constant-usage.js";
import enforceConfigImmutabilityRule from "../../tools/eslint-rules/enforce-config-immutability.js";
import enforceTestApiGuardRule from "../../tools/eslint-rules/enforce-test-api-guard.js";
import noUnsealedConfigurationRule from "../../tools/eslint-rules/no-unsealed-configuration.js";
import enforceVisibilityAbortPatternRule from "../../tools/eslint-rules/enforce-visibility-abort-pattern.js";

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { 
      ecmaVersion: 2020, 
      sourceType: "module",
      ecmaFeatures: { jsx: false }
    },
  },
});

describe("Autofix Comprehensive Tests", () => {
  describe("no-un-normalized-string-comparison autofix", () => {
    ruleTester.run("no-un-normalized-string-comparison", noUnNormalizedStringComparisonRule, {
      valid: [
        // Already normalized strings
        "if (normalizeInputString(userInput) === 'expected') {}",
        "if (input.normalize('NFC') === target) {}",
        "const result = safeList.includes(normalizeInputString(searchTerm));",
      ],
      invalid: [
        // Binary expression comparisons
        {
          code: "if (userInput === 'expected') {}",
          output: "if (normalizeInputString(userInput) === 'expected') {}",
          errors: [{ messageId: "requireNormalization" }]
        },
        {
          code: "if (param !== target) {}",
          output: "if (normalizeInputString(param) !== target) {}",
          errors: [{ messageId: "requireNormalization" }]
        },
        // String method calls
        {
          code: "const found = input.includes(searchTerm);",
          output: "const found = normalizeInputString(input).includes(searchTerm);",
          errors: [{ messageId: "unsafeMethodCall" }]
        },
        {
          code: "if (data.startsWith(safePrefix)) {}",
          output: "if (normalizeInputString(data).startsWith(safePrefix)) {}",
          errors: [{ messageId: "unsafeMethodCall" }]
        },
        {
          code: "const position = rawData.indexOf(searchString);",
          output: "const position = normalizeInputString(rawData).indexOf(searchString);",
          errors: [{ messageId: "unsafeMethodCall" }]
        },
        // Switch statements
        {
          code: "switch (userInput) { case 'admin': break; }",
          output: "switch (normalizeInputString(userInput)) { case 'admin': break; }",
          errors: [{ messageId: "unsafeSwitchCase" }]
        },
        // RegExp tests
        {
          code: "if (pattern.test(userInput)) {}",
          output: "if (pattern.test(normalizeInputString(userInput))) {}",
          errors: [{ messageId: "unsafeRegexTest" }]
        }
      ],
    });
  });

  describe("throw-typed-errors autofix", () => {
    ruleTester.run("throw-typed-errors", throwTypedErrorsRule, {
      valid: [
        // Already using typed errors
        "throw new InvalidParameterError('Invalid input');",
        "throw new CryptoUnavailableError('Crypto not available');",
        "throw existingError;", // Re-throwing is allowed
      ],
      invalid: [
        // Generic Error with parameter-related message
        {
          code: "throw new Error('Invalid parameter value');",
          output: "throw new InvalidParameterError('Invalid parameter value');",
          errors: [{ messageId: "useTypedError" }]
        },
        // Generic Error with crypto-related message
        {
          code: "throw new Error('Crypto operation failed');",
          output: "throw new CryptoUnavailableError('Crypto operation failed');",
          errors: [{ messageId: "useTypedError" }]
        },
        // Generic Error with encoding-related message
        {
          code: "throw new Error('Base64 encoding failed');",
          output: "throw new EncodingError('Base64 encoding failed');",
          errors: [{ messageId: "useTypedError" }]
        },
        // Generic Error with configuration-related message
        {
          code: "throw new Error('Configuration is sealed');",
          output: "throw new InvalidConfigurationError('Configuration is sealed');",
          errors: [{ messageId: "useTypedError" }]
        },
        // TypeError should be replaced
        {
          code: "throw new TypeError('Wrong type provided');",
          output: "throw new InvalidParameterError('Wrong type provided');",
          errors: [{ messageId: "useTypedError" }]
        },
        // RangeError should be replaced
        {
          code: "throw new RangeError('Value out of range');",
          output: "throw new InvalidParameterError('Value out of range');",
          errors: [{ messageId: "useTypedError" }]
        }
      ],
    });
  });

  describe("enforce-secure-wipe autofix", () => {
    ruleTester.run("enforce-secure-wipe", enforceSecureWipeRule, {
      valid: [
        // Already has secure wipe in finally block
        `try {
          const keyBuffer = new Uint8Array(32);
        } finally {
          secureWipe(keyBuffer);
        }`,
        // Non-sensitive buffers should not trigger
        "const displayBuffer = new Uint8Array(10);",
        "const outputData = new Uint8Array(16);", 
        // Non-Uint8Array types with sensitive names should not trigger
        "const ALLOWED_TAG_KEYS = new Set(['user', 'session']);",
        "const secretMap = new Map();", 
        "const keyCache = new WeakMap();",
        "const tokenList = [];",
        "const secretConfig = { apiKey: 'value' };",
        // String and primitive values
        "const secretValue = 'not-a-buffer';",
        "const keyCount = 42;",
        // Functions that don't return buffers
        "const keyValidator = () => true;",
        // Already using crypto functions that return non-buffers
        "const randomId = generateSecureIdSync();",
      ],
      invalid: [
        // Missing secure wipe for sensitive Uint8Array
        {
          code: `function processKey() {
            const keyBuffer = new Uint8Array(32);
            return keyBuffer;
          }`,
          output: `function processKey() {
            const keyBuffer = new Uint8Array(32);
            try {
              return keyBuffer;
            } finally {
              secureWipe(keyBuffer);
            }
          }`,
          errors: [{ messageId: "missingSecureWipe" }]
        },
        // Missing secure wipe for crypto function result
        {
          code: `function generateSecret() {
            const secretData = getSecureRandomBytesSync(16);
            processSecret(secretData);
          }`,
          output: `function generateSecret() {
            const secretData = getSecureRandomBytesSync(16);
            try {
              processSecret(secretData);
            } finally {
              secureWipe(secretData);
            }
          }`,
          errors: [{ messageId: "missingSecureWipe" }]
        },
        // Missing secure wipe in existing try-catch
        {
          code: `try {
            const secretData = new Uint8Array(16);
            processSecret(secretData);
          } catch (error) {
            handleError(error);
          }`,
          output: `try {
            const secretData = new Uint8Array(16);
            processSecret(secretData);
          } catch (error) {
            handleError(error);
          } finally {
            secureWipe(secretData);
          }`,
          errors: [{ messageId: "missingSecureWipe" }]
        },
        // Async crypto call
        {
          code: `async function processToken() {
            const tokenBytes = await getSecureRandomBytesAsync(32);
            return processBytes(tokenBytes);
          }`,
          output: `async function processToken() {
            const tokenBytes = await getSecureRandomBytesAsync(32);
            try {
              return processBytes(tokenBytes);
            } finally {
              secureWipe(tokenBytes);
            }
          }`,
          errors: [{ messageId: "missingSecureWipe" }]
        },
        // Different buffer types
        {
          code: `function handleSensitiveData() {
            const passwordHash = new ArrayBuffer(64);
            return hashData(passwordHash);
          }`,
          output: `function handleSensitiveData() {
            const passwordHash = new ArrayBuffer(64);
            try {
              return hashData(passwordHash);
            } finally {
              secureWipe(passwordHash);
            }
          }`,
          errors: [{ messageId: "missingSecureWipe" }]
        },
      ],
    });
  });

  describe("enforce-text-encoder-decoder autofix", () => {
    ruleTester.run("enforce-text-encoder-decoder", enforceTextEncoderDecoderRule, {
      valid: [
        // Already using shared instances
        "import { SHARED_ENCODER } from './encoding.ts'; const result = SHARED_ENCODER.encode('test');",
        "import { SHARED_DECODER } from './encoding.ts'; const result = SHARED_DECODER.decode(buffer);",
      ],
      invalid: [
        // Direct TextEncoder usage
        {
          code: "const encoder = new TextEncoder(); const result = encoder.encode('test');",
          output: "import { SHARED_ENCODER } from \"./src/encoding.ts\";\nconst encoder = SHARED_ENCODER; const result = encoder.encode('test');",
          errors: [{ messageId: "useSharedEncoder" }]
        },
        // Direct TextDecoder usage  
        {
          code: "const decoder = new TextDecoder(); const result = decoder.decode(buffer);",
          output: "import { SHARED_DECODER } from \"./src/encoding.ts\";\nconst decoder = SHARED_DECODER; const result = decoder.decode(buffer);",
          errors: [{ messageId: "useSharedDecoder" }]
        },
        // Combined encoder creation and usage
        {
          code: "const bytes = new TextEncoder().encode(message);",
          output: "import { SHARED_ENCODER } from \"./src/encoding.ts\";\nconst bytes = SHARED_ENCODER.encode(message);",
          errors: [{ messageId: "useSharedEncoder" }]
        }
      ],
    });
  });

  describe("no-unsafe-object-merge autofix", () => {
    ruleTester.run("no-unsafe-object-merge", noUnsafeObjectMergeRule, {
      valid: [
        // Safe merging with validated input
        "const merged = { ...validateInput(userInput), safe: true };",
        "Object.assign(target, sanitize(data));",
      ],
      invalid: [
        // Unsafe spread of user input
        {
          code: "const merged = { ...userInput, default: true };",
          output: "const merged = { ...toNullProto(userInput), default: true };",
          errors: [{ messageId: "unsafeObjectSpread" }]
        },
        // Unsafe Object.assign
        {
          code: "Object.assign(target, userData);",
          output: "Object.assign(target, toNullProto(userData));",
          errors: [{ messageId: "unsafeObjectAssign" }]
        },
        // Unsafe spread in nested object
        {
          code: "const result = { data: { ...requestData } };",
          output: "const result = { data: { ...toNullProto(requestData) } };",
          errors: [{ messageId: "unsafeObjectSpread" }]
        }
      ],
    });
  });

  describe("no-postmessage-constant-usage autofix", () => {
    ruleTester.run("no-postmessage-constant-usage", noPostmessageConstantUsageRule, {
      valid: [
        // Proper dynamic configuration
        "const config = createPostMessageConfig({ allowedOrigins: origins });",
        "postMessage(data, { origin: dynamicOrigin });",
      ],
      invalid: [
        // Hardcoded origin
        {
          code: "postMessage(data, 'https://example.com');",
          output: "postMessage(data, validateOrigin('https://example.com'));",
          errors: [{ messageId: "avoidHardcodedOrigin" }]
        },
        // Hardcoded configuration object
        {
          code: "const config = { allowedOrigins: ['https://app.com'], targetOrigin: '*' };",
          output: "const config = createPostMessageConfig({ allowedOrigins: ['https://app.com'], targetOrigin: '*' });",
          errors: [{ messageId: "useConfigFactory" }]
        }
      ],
    });
  });

  describe("enforce-config-immutability autofix", () => {
    ruleTester.run("enforce-config-immutability", enforceConfigImmutabilityRule, {
      valid: [
        // Already immutable configurations
        "const config = Object.freeze({ key: 'value' });",
        "const settings = deepFreeze(userSettings);",
      ],
      invalid: [
        // Mutable configuration object
        {
          code: "const config = { maxRetries: 3, timeout: 5000 };",
          output: "const config = { maxRetries: 3, timeout: 5000 };\nObject.freeze(config);",
          errors: [{ messageId: "configNotFrozen" }]
        },
        // Configuration passed to function
        {
          code: "function setupConfig() { return { secure: true, debug: false }; }",
          output: "function setupConfig() { return Object.freeze({ secure: true, debug: false }); }",
          errors: [{ messageId: "configNotFrozen" }]
        }
      ],
    });
  });

  describe("enforce-test-api-guard autofix", () => {
    ruleTester.run("enforce-test-api-guard", enforceTestApiGuardRule, {
      valid: [
        // Already guarded test API
        "if (isDevelopment()) { exposeTestAPI(); }",
        "const api = __TEST__ ? testHelpers : {};",
      ],
      invalid: [
        // Unguarded test API exposure
        {
          code: "window.__TEST_UTILS__ = testUtils;",
          output: "if (isDevelopment()) { window.__TEST_UTILS__ = testUtils; }",
          errors: [{ messageId: "requireTestGuard" }]
        },
        // Direct test helper assignment
        {
          code: "global.testHelpers = helpers;",
          output: "if (isDevelopment()) { global.testHelpers = helpers; }",
          errors: [{ messageId: "requireTestGuard" }]
        }
      ],
    });
  });

  describe("no-unsealed-configuration autofix", () => {
    ruleTester.run("no-unsealed-configuration", noUnsealedConfigurationRule, {
      valid: [
        // Configuration with seal check
        "if (isSealed()) throw new Error('Config sealed'); config.value = newValue;",
        // Already has seal check
        "checkSealState(); updateConfig(changes);",
      ],
      invalid: [
        // Configuration change without seal check
        {
          code: "securityConfig.maxAttempts = 10;",
          output: "if (isSealed()) throw new IllegalStateError('Configuration is sealed'); securityConfig.maxAttempts = 10;",
          errors: [{ messageId: "requireSealCheck" }]
        },
        // Function call that modifies config
        {
          code: "setSecurityPolicy(newPolicy);",
          output: "if (isSealed()) throw new IllegalStateError('Configuration is sealed'); setSecurityPolicy(newPolicy);",
          errors: [{ messageId: "requireSealCheck" }]
        }
      ],
    });
  });

  describe("enforce-visibility-abort-pattern autofix", () => {
    ruleTester.run("enforce-visibility-abort-pattern", enforceVisibilityAbortPatternRule, {
      valid: [
        // Already has visibility check
        "function process() { if (document.visibilityState === 'hidden') return; processData(); }",
        "document.addEventListener('visibilitychange', handleVisibilityChange);",
      ],
      invalid: [
        // Long-running operation without visibility check
        {
          code: `function processLargeDataset() {
            for (let i = 0; i < 1000000; i++) {
              processItem(data[i]);
            }
          }`,
          output: `function processLargeDataset() {
            for (let i = 0; i < 1000000; i++) {
              if (document.visibilityState === 'hidden') return;
              processItem(data[i]);
            }
          }`,
          errors: [{ messageId: "addVisibilityCheck" }]
        },
        // Timer without visibility abort
        {
          code: "setInterval(() => updateStats(), 1000);",
          output: `setInterval(() => {
            if (document.visibilityState === 'hidden') return;
            updateStats();
          }, 1000);`,
          errors: [{ messageId: "addVisibilityCheck" }]
        }
      ],
    });
  });
});