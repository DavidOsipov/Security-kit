import { RuleTester } from "eslint";
import rule from "../../tools/eslint-rules/enforce-json-size-guard.js";

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2020, sourceType: "module" },
  },
});

ruleTester.run("enforce-json-size-guard", rule, {
  valid: [
    // JSON operations with validation
    `
      function parseData(input) {
        validateJsonSize(input, 1024);
        return JSON.parse(input);
      }
    `,
    `
      function stringifyData(data) {
        validatePayloadSize(data, 2048);
        return JSON.stringify(data);
      }
    `,
    // Custom validation functions
    `
      function processJson(input) {
        checkSizeLimit(input);
        return JSON.parse(input);
      }
    `,
    // Non-JSON operations should be allowed
    "const data = { key: 'value' };",
    "console.log('not json');",
  ],
  invalid: [
    // JSON.parse without validation
    {
      code: `
        function parseUserInput(input) {
          return JSON.parse(input);
        }
      `,
      errors: [{ messageId: "missingSizeGuard", suggestions: [{ desc: "Add size validation before parsing", output: `
        function parseUserInput(input) {
          validateJsonSize(input, 1048576);
return JSON.parse(input);
        }
      ` }] }],
    },
    // JSON.stringify without validation
    {
      code: `
        function serializeData(data) {
          return JSON.stringify(data);
        }
      `,
      errors: [{ messageId: "missingSizeGuard", suggestions: [{ desc: "Add size validation before stringify", output: `
        function serializeData(data) {
          validatePayloadSize(data, 1048576);
return JSON.stringify(data);
        }
      ` }] }],
    },
    // External input detection
    {
      code: `
        function handleRequest(req) {
          const data = JSON.parse(req.body);
          return data;
        }
      `,
      errors: [{ messageId: "missingSizeGuard", suggestions: [{ desc: "Add size validation before parsing", output: `
        function handleRequest(req) {
          validateJsonSize(req.body, 1048576);
const data = JSON.parse(req.body);
          return data;
        }
      ` }] }],
    },
    // Multiple JSON operations without validation
    {
      code: `
        function processAndRespond(input, output) {
          const parsed = JSON.parse(input);
          const stringified = JSON.stringify(output);
          return { parsed, stringified };
        }
      `,
      errors: [
        { messageId: "missingSizeGuard", suggestions: [{ desc: "Add size validation before parsing", output: `
        function processAndRespond(input, output) {
          validateJsonSize(input, 1048576);
const parsed = JSON.parse(input);
          const stringified = JSON.stringify(output);
          return { parsed, stringified };
        }
      ` }] },
        { messageId: "missingSizeGuard", suggestions: [{ desc: "Add size validation before stringify", output: `
        function processAndRespond(input, output) {
          const parsed = JSON.parse(input);
          validatePayloadSize(output, 1048576);
const stringified = JSON.stringify(output);
          return { parsed, stringified };
        }
      ` }] }
      ],
    },
  ],
});