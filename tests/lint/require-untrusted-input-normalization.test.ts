import { RuleTester } from 'eslint';
import rule from '../../tools/eslint-rules/require-untrusted-input-normalization.js';

const ruleTester = new RuleTester({
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
});

ruleTester.run('require-untrusted-input-normalization', rule, {
  valid: [
    // Case 1: Normalized string from risky parameter
    {
      code: `
        function processInput(input) {
          const normalized = normalizeInputString(input);
          return normalized;
        }
      `,
      options: [{ taintNamePattern: 'input' }],
    },
    // Case 2: Using validateAndNormalizeInput result.value
    {
      code: `
        function handleData(data) {
          const result = validateAndNormalizeInput(data);
          if (result.success) {
            return result.value;
          }
        }
      `,
      options: [{ taintNamePattern: 'data' }],
    },
    // Case 3: String.prototype.normalize
    {
      code: `
        function processText(text) {
          const normalized = text.normalize('NFC');
          return normalized;
        }
      `,
      options: [{ taintNamePattern: 'text' }],
    },
    // Case 4: Non-tainted parameter (doesn't match pattern)
    {
      code: `
        function processSafe(safeInput) {
          return safeInput;
        }
      `,
      options: [{ taintNamePattern: 'input' }],
    },
    // Case 5: Normalized in a different scope
    {
      code: `
        function outer(input) {
          const normalized = normalizeInputString(input);
          function inner() {
            return normalized;
          }
          return inner;
        }
      `,
      options: [{ taintNamePattern: 'input' }],
    },
    // Case 6: Multiple normalizations
    {
      code: `
        function multiNorm(payload) {
          const step1 = normalizeInputString(payload);
          const step2 = step1.normalize('NFKD');
          return step2;
        }
      `,
      options: [{ taintNamePattern: 'payload' }],
    },
    // Case 7: Normalization via member expression
    {
      code: `
        function memberNorm(userInput) {
          const normalized = userInput.normalize();
          return normalized;
        }
      `,
      options: [{ taintNamePattern: 'userInput' }],
    },
    // Case 8: Default options (no custom taint pattern)
    {
      code: `
        function defaultTest(input) {
          const normalized = normalizeInputString(input);
          return normalized;
        }
      `,
    },
    // Case 9: Non-string return (no violation)
    {
      code: `
        function returnNumber(input) {
          return 42;
        }
      `,
      options: [{ taintNamePattern: 'input' }],
    },
    // Case 10: Tainted but not used in sink
    {
      code: `
        function noSink(input) {
          const temp = input;
          // temp not returned or exported
        }
      `,
      options: [{ taintNamePattern: 'input' }],
    },
    // Depth limit prevents deeper detection (should not report)
    {
      code: `
        function deepLimit(userInput) {
          return { a: { b: { c: userInput } } };
        }
      `,
      filename: 'src/strict/file.ts',
      options: [{ taintNamePattern: 'userInput', nestedObjectArrayDepth: 1 }],
    },
    // strictDirOk remains valid under ultra strict
    {
      code: `
        import { normalizeInputStringUltraStrict } from './canonical';
        function strictDirOk(input) {
          const v = normalizeInputStringUltraStrict(input);
          return v;
        }
      `,
      filename: 'src/strict/beta.ts',
      options: [{ taintNamePattern: 'input', strictDirectories: ['src/strict/'] }],
      errors: [],
    },
  ],
  invalid: [
    // Case 1: Unnormalized tainted string in return
    {
      code: `
        function processInput(input) {
          return input;
        }
      `,
      options: [{ taintNamePattern: 'input' }],
      filename: 'src/some.js',
      errors: [
        {
          messageId: 'unnormalizedReturn',
          type: 'Identifier',
        },
      ],
    },
    // Case 2: Unnormalized in concatenation
    {
      code: `
        function concatInput(data) {
          return 'prefix' + data;
        }
      `,
      options: [{ taintNamePattern: 'data' }],
      filename: 'src/some.js',
      errors: [
        {
          messageId: 'unnormalizedConcat',
          type: 'Identifier',
        },
      ],
    },
    // Case 3: Skip export for now, as top-level export of tainted is hard to test
    // Case 4: Partial normalization (still tainted)
    {
      code: `
        function partialNorm(payload) {
          const partial = payload;
          return partial;
        }
      `,
      options: [{ taintNamePattern: 'payload' }],
      filename: 'src/some.js',
      errors: [
        {
          messageId: 'unnormalizedReturn',
          type: 'Identifier',
        },
      ],
    },
    // Case 5: Tainted from assignment
    {
      code: `
        function assignTaint(input) {
          let tainted = input;
          return tainted;
        }
      `,
      options: [{ taintNamePattern: 'input' }],
      filename: 'src/some.js',
      errors: [
        {
          messageId: 'unnormalizedReturn',
          type: 'Identifier',
        },
      ],
    },
    // Case 6: Multiple tainted variables
    {
      code: `
        function multiTaint(userInput, payload) {
          return userInput + payload;
        }
      `,
      options: [{ taintNamePattern: 'userInput|payload' }],
      filename: 'src/some.js',
      errors: [
        {
          messageId: 'unnormalizedConcat',
          type: 'Identifier',
        },
        {
          messageId: 'unnormalizedConcat',
          type: 'Identifier',
        },
      ],
    },
    // Case 7: Tainted in function call argument
    {
      code: `
        function callSink(input) {
          someFunction(input);
        }
      `,
      options: [{ taintNamePattern: 'input' }],
      filename: 'src/some.js',
      errors: [
        {
          messageId: 'unnormalizedArg',
          type: 'Identifier',
        },
      ],
    },
    // Case 8: Array return with tainted element
    {
      code: `
        function arraySink(input) {
          return [input];
        }
      `,
      options: [{ taintNamePattern: 'input' }],
      filename: 'src/some.js',
      errors: [
        { messageId: 'unnormalizedReturn', type: 'Identifier' },
      ],
    },
    // Case 9: Object return with tainted property
    {
      code: `
        function objectSink(data) {
          return { value: data };
        }
      `,
      options: [{ taintNamePattern: 'data' }],
      filename: 'src/some.js',
      errors: [
        { messageId: 'unnormalizedReturn', type: 'Identifier' },
      ],
    },
    // Case 10: Default taint pattern (common risky names)
    {
      code: `
        function defaultTaint(userInput) {
          return userInput;
        }
      `,
      filename: 'src/some.js',
      errors: [
        {
          messageId: 'unnormalizedReturn',
          type: 'Identifier',
        },
      ],
    },
    // Deep nested object (within depth)
    {
      code: `
        function deepObj(userInput) {
          return { level1: { level2: userInput } };
        }
      `,
      filename: 'src/strict/file.ts',
      options: [{ taintNamePattern: 'userInput', nestedObjectArrayDepth: 2 }],
      errors: [ { messageId: 'unnormalizedReturn', type: 'Identifier' } ],
    },
    // deepArray propagation through nested structures
    {
      code: `
        function deepArray(payload) {
          const inner = [payload];
          return [{ items: [...inner] }];
        }
      `,
      filename: 'src/strict/file.ts',
      options: [{ taintNamePattern: 'payload', nestedObjectArrayDepth: 4 }],
      errors: [ { messageId: 'unnormalizedReturn', type: 'Identifier' } ],
    },
    // strictDir should now report (normalizeInputString not allowed in strict dir) – two errors (arg + return)
    {
      code: `
        import { normalizeInputString } from './canonical';
        function strictDir(input) {
          const v = normalizeInputString(input); // not strict approved
          return v;
        }
      `,
      filename: 'src/strict/alpha.ts',
      options: [{ taintNamePattern: 'input', strictDirectories: ['src/strict/'] }],
      errors: [ { messageId: 'unnormalizedArg', type: 'Identifier' }, { messageId: 'unnormalizedReturn', type: 'Identifier' } ],
    },
  ],
});