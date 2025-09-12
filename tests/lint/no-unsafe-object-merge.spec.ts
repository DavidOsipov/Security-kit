import { RuleTester } from "eslint";
import rule from "../../tools/eslint-rules/no-unsafe-object-merge.js";

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2020, sourceType: "module" },
  },
});

ruleTester.run("no-unsafe-object-merge", rule, {
  valid: [
    // Safe object operations
    "const obj = { a: 1, b: 2 };",
    "const merged = { ...safeObj, c: 3 };",
    "Object.assign(target, { key: 'value' });",

    // Non-external inputs
    "const config = { ...defaultConfig, userSetting };",
    "Object.assign(settings, localData);",

    // Safe merging with validation
    "const safe = validateInput(input); const merged = { ...safe };",
    "const validated = sanitize(data); Object.assign(target, validated);",
  ],
  invalid: [
    // Spread with external input
    {
      code: "const merged = { ...userInput, default: true };",
      output: "const merged = { ...toNullProto(userInput), default: true };",
      errors: [{ messageId: "unsafeObjectSpread" }],
    },
    {
      code: "const data = { ...req, processed: true };",
      output: "const data = { ...toNullProto(req), processed: true };",
      errors: [{ messageId: "unsafeObjectSpread" }],
    },
    // Object.assign with external input
    {
      code: "Object.assign(target, userData);",
      output: "Object.assign(target, toNullProto(userData));",
      errors: [{ messageId: "unsafeObjectAssign" }],
    },
    {
      code: "const result = Object.assign({}, request);",
      output: "const result = Object.assign({}, toNullProto(request));",
      errors: [{ messageId: "unsafeObjectAssign" }],
    },
    // Multiple unsafe operations
    {
      code: `
        const config = { ...userConfig };
        Object.assign(config, externalData);
      `,
      output: `
        const config = { ...toNullProto(userConfig) };
        Object.assign(config, toNullProto(externalData));
      `,
      errors: [
        { messageId: "unsafeObjectSpread" },
        { messageId: "unsafeObjectAssign" }
      ],
    },
    // Nested object operations
    {
      code: "const nested = { data: { ...input } };",
      output: "const nested = { data: { ...toNullProto(input) } };",
      errors: [{ messageId: "unsafeObjectSpread" }],
    },
    // Function parameters that are external
    {
      code: `
        function process(data) {
          return { ...data, processed: true };
        }
      `,
      output: `
        function process(data) {
          return { ...toNullProto(data), processed: true };
        }
      `,
      errors: [{ messageId: "unsafeObjectSpread" }],
    },
  ],
});