/**
 * @fileoverview ESLint rule: enforce-secure-postmessage-listener
 * Ensures createSecurePostMessageListener is configured with proper validation
 * and origin restrictions in production code. Prevents security vulnerabilities
 * from missing validation or origin checks.
 * 
 * OWASP ASVS V14.1.1: Message validation and origin verification
 * Security Constitution: postMessage security requirements
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Enforce proper validation and origin restrictions for createSecurePostMessageListener in production",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          requireValidation: {
            type: "boolean",
            description: "Whether validate property is required (default: true for production)"
          },
          requireOriginRestriction: {
            type: "boolean", 
            description: "Whether origin restriction is required (default: true for production)"
          },
          testDirectoryPatterns: {
            type: "array",
            items: { type: "string" },
            description: "Directory patterns where requirements are relaxed"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      missingValidation: "createSecurePostMessageListener in production code must include 'validate' property to prevent injection attacks",
      missingOriginRestriction: "createSecurePostMessageListener must include either 'allowedOrigins' or 'expectedSource' for origin validation", 
      suggestValidation: "Add validation: validate: (data) => typeof data === 'object' && data !== null && 'action' in data",
      suggestOriginRestriction: "Add origin restriction: allowedOrigins: ['https://trusted.example.com']",
      emptyAllowedOrigins: "allowedOrigins array cannot be empty - specify allowed origins or use expectedSource"
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const requireValidation = options.requireValidation !== false; // default true
    const requireOriginRestriction = options.requireOriginRestriction !== false; // default true
    const testDirectoryPatterns = options.testDirectoryPatterns || [
      "/tests/", "/test/", "/__tests__/", "/demo/", "/examples/", "/benchmarks/"
    ];

    const filename = context.getFilename() || "";
    const isTestFile = testDirectoryPatterns.some(pattern => filename.includes(pattern));

    // Relax requirements in test files
    if (isTestFile) {
      return {};
    }

    /**
     * Check if options object has validation property
     */
    function hasValidation(optionsNode) {
      if (optionsNode?.type !== "ObjectExpression") return false;
      return optionsNode.properties.some(prop => 
        prop.type === "Property" && 
        prop.key?.name === "validate"
      );
    }

    /**
     * Check if options object has origin restriction
     */
    function hasOriginRestriction(optionsNode) {
      if (optionsNode?.type !== "ObjectExpression") return false;
      
      const allowedOrigins = optionsNode.properties.find(prop =>
        prop.type === "Property" && prop.key?.name === "allowedOrigins"
      );
      
      const expectedSource = optionsNode.properties.find(prop =>
        prop.type === "Property" && prop.key?.name === "expectedSource"
      );

      // Check for empty allowedOrigins array
      if (allowedOrigins?.value?.type === "ArrayExpression" &&
          allowedOrigins.value.elements.length === 0) {
        return { hasRestriction: false, isEmpty: true };
      }

      return { 
        hasRestriction: Boolean(allowedOrigins || expectedSource),
        isEmpty: false
      };
    }

    return {
      CallExpression(node) {
        // Check for createSecurePostMessageListener calls
        if (node.callee?.name === "createSecurePostMessageListener" ||
            (node.callee?.type === "MemberExpression" && 
             node.callee?.property?.name === "createSecurePostMessageListener")) {
          
          const optionsArg = node.arguments[0];
          if (!optionsArg) {
            context.report({
              node,
              messageId: "missingValidation"
            });
            return;
          }

          // Check for validation requirement
          if (requireValidation && !hasValidation(optionsArg)) {
            context.report({
              node: optionsArg,
              messageId: "missingValidation"
            });
          }

          // Check for origin restriction requirement  
          if (requireOriginRestriction) {
            const originCheck = hasOriginRestriction(optionsArg);
            
            if (originCheck.isEmpty) {
              context.report({
                node: optionsArg,
                messageId: "emptyAllowedOrigins"
              });
            } else if (!originCheck.hasRestriction) {
              context.report({
                node: optionsArg,
                messageId: "missingOriginRestriction"
              });
            }
          }
        }
      }
    };
  }
};