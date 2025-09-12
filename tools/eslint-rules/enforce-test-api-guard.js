/**
 * @fileoverview ESLint rule: enforce-test-api-guard
 * Ensures that functions intended for testing are guarded by a call to assertTestApiAllowed()
 * to prevent production usage. This protects against accidental exposure of internal test APIs
 * in production environments.
 * This aligns with OWASP ASVS L3 V1.1.3 (Security Requirements) and our Security Constitution's
 * Pillars #1 (Zero Trust) and #4 (Absolute Testability).
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description:
        "Ensures that functions intended for testing are guarded by a call to assertTestApiAllowed().",
      category: "Security",
      recommended: true,
      url: "https://github.com/david-osipov/security-kit/docs/Constitutions/The%20Official%20Testing%20&%20Quality%20Assurance%20Constitution.md",
    },
  // fixable removed to prevent unsafe automated edits; rule is error-only
    schema: [
      {
        type: "object",
        properties: {
          testFunctionPatterns: {
            type: "array",
            items: { type: "string" },
            description: "Additional patterns to identify test-only functions"
          },
          guardFunctionName: {
            type: "string",
            description: "Name of the guard function to enforce (default: assertTestApiAllowed)"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      missingGuard:
        "Test-only function '{{functionName}}' must call '{{guardFunction}}()' at the beginning of its body " +
        "to prevent production usage. This is required by our Security Constitution to maintain Zero Trust principles.",
      requireTestGuard:
        "Test-only function '{{functionName}}' must call '{{guardFunction}}()' at the beginning of its body " +
        "to prevent production usage. This is required by our Security Constitution to maintain Zero Trust principles.",
      missingImport:
        "Function '{{functionName}}' calls '{{guardFunction}}()' but the guard function is not imported. " +
        "Add 'import { {{guardFunction}} } from \"./development-guards.ts\";' to the imports.",
      suggestGuard:
        "Add '{{guardFunction}}();' as the first statement in the function body.",
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const customPatterns = options.testFunctionPatterns || [];
    const guardFunctionName = options.guardFunctionName || "assertTestApiAllowed";
    
    const filename = context.getFilename() || "";
    
    // Skip test files themselves
    if (/\btests?\b|\.test\.|\.spec\./i.test(filename)) {
      return {};
    }

    /**
     * Determines if a function name indicates it's for testing only
     */
    function isTestFunction(functionName) {
      if (!functionName) return false;
      
      const defaultPatterns = [
        /^__test_/,
        /ForUnitTests$/,
        /ForTests$/,
        /ForTesting$/,
        /_test_/,
        /TestUtils$/,
        /TestUtilities$/,
        /TestHelper$/,
        /MockData$/,
        /MockConfig$/,
        /_resetCrypto.*ForUnitTests$/,
        /_reset.*ForTests$/,
        /getInternalTestUtils$/,
        /getInternalTestUtilities$/,
      ];
      
      const allPatterns = [...defaultPatterns, ...customPatterns.map(p => new RegExp(p))];
      
      return allPatterns.some(pattern => pattern.test(functionName));
    }

    /**
     * Checks if the guard call exists at the beginning of the function body
     */
    function hasGuardCall(functionBody) {
      if (!functionBody || functionBody.type !== "BlockStatement") {
        return false;
      }
      
      // Check first few statements for the guard call (allowing for variable declarations first)
      const statementsToCheck = functionBody.body.slice(0, 3);
      
      return statementsToCheck.some(statement => {
        // Direct call: assertTestApiAllowed();
        if (
          statement.type === "ExpressionStatement" &&
          statement.expression.type === "CallExpression" &&
          statement.expression.callee.type === "Identifier" &&
          statement.expression.callee.name === guardFunctionName
        ) {
          return true;
        }
        
        // Await call: await assertTestApiAllowed();
        if (
          statement.type === "ExpressionStatement" &&
          statement.expression.type === "AwaitExpression" &&
          statement.expression.argument.type === "CallExpression" &&
          statement.expression.argument.callee.type === "Identifier" &&
          statement.expression.argument.callee.name === guardFunctionName
        ) {
          return true;
        }
        
        return false;
      });
    }

    /**
     * Gets the function name from various node types
     */
    function getFunctionName(node) {
      // Function declaration: function foo() {}
      if (node.id && node.id.name) {
        return node.id.name;
      }
      
      // Variable declarator with function expression: const foo = function() {}
      if (
        node.parent &&
        node.parent.type === "VariableDeclarator" &&
        node.parent.id.type === "Identifier"
      ) {
        return node.parent.id.name;
      }
      
      // Property with function value: { foo: function() {} } or { foo() {} }
      if (
        node.parent &&
        node.parent.type === "Property" &&
        node.parent.key.type === "Identifier"
      ) {
        return node.parent.key.name;
      }
      
      // Assignment: obj.foo = function() {}
      if (
        node.parent &&
        node.parent.type === "AssignmentExpression" &&
        node.parent.left.type === "MemberExpression" &&
        node.parent.left.property.type === "Identifier"
      ) {
        return node.parent.left.property.name;
      }
      
      return null;
    }

    /**
     * Check a function node for test function patterns and guard calls
     */
    function checkFunction(node) {
      const functionName = getFunctionName(node);
      
      if (functionName && isTestFunction(functionName)) {
        if (!hasGuardCall(node.body)) {
          context.report({
            node,
            messageId: "requireTestGuard",
            data: { 
              functionName,
              guardFunction: guardFunctionName 
            }
          });
        }
      }
    }

    return {
      FunctionDeclaration: checkFunction,
      FunctionExpression: checkFunction,
      ArrowFunctionExpression: checkFunction,
    };
  },
};