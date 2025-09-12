/**
 * @fileoverview ESLint rule: throw-typed-errors
 * Enforces the use of custom, typed error classes from src/errors.ts instead
 * of generic Error objects. This ensures consumers can handle failures
 * programmatically, aligning with OWASP ASVS L3 error handling requirements.
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description:
        "Require custom typed errors instead of generic Error objects",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          allowedGenericErrors: {
            type: "array",
            items: { type: "string" },
            description: "Generic error types that are allowed (e.g., for very specific cases)"
          }
        },
        additionalProperties: false,
      }
    ],
    messages: {
      useTypedError:
        "Use custom typed error from src/errors.ts instead of {{errorType}}. " +
        "Consider: {{suggestions}}",
      unknownErrorPattern:
        "This error pattern is not recognized. Consider using a specific error type from src/errors.ts",
      preferSpecificError:
        "Consider using a more specific error type: {{suggestions}}",
    },
  // fixable removed to prevent unsafe automated edits; rule is error-only
  },

  create(context) {
    // Skip tests and scripts unless they're testing error handling
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\//i.test(filename) && !filename.includes("error")) {
      return {};
    }

    const options = context.options[0] || {};
    const allowedGenericErrors = new Set(options.allowedGenericErrors || []);

    /**
     * Maps error message patterns to appropriate custom error types
     */
    const errorMappings = [
      {
        patterns: [/invalid|bad|wrong|incorrect/i, /parameter|argument|input|value/i],
        errorType: "InvalidParameterError",
        description: "for invalid parameters or arguments"
      },
      {
        patterns: [/crypto|random|key|digest|sign/i, /unavailable|missing|unsupported/i],
        errorType: "CryptoUnavailableError", 
        description: "for missing or unsupported crypto features"
      },
      {
        patterns: [/encoding|decode|base64|utf/i],
        errorType: "EncodingError",
        description: "for encoding/decoding issues"
      },
      {
        patterns: [/config|setting|option/i, /sealed|frozen|locked/i],
        errorType: "InvalidConfigurationError",
        description: "for configuration issues"
      },
      {
        patterns: [/signature|verify|auth/i, /invalid|failed|wrong/i],
        errorType: "SignatureVerificationError",
        description: "for signature verification failures" 
      },
      {
        patterns: [/replay|duplicate|reuse/i],
        errorType: "ReplayAttackError",
        description: "for replay attack detection"
      },
      {
        patterns: [/timestamp|time|expired|stale/i],
        errorType: "TimestampError",
        description: "for timestamp validation issues"
      },
      {
        patterns: [/worker|thread|concurrent/i],
        errorType: "WorkerError",
        description: "for worker/threading issues"
      },
      {
        patterns: [/rate|limit|throttle|too many/i],
        errorType: "RateLimitError",
        description: "for rate limiting"
      },
      {
        patterns: [/circuit|breaker|iteration|loop/i, /limit|max|exceeded/i],
        errorType: "CircuitBreakerError",
        description: "for circuit breaker protection"
      },
      {
        patterns: [/transfer|clone|serialize/i, /not allowed|forbidden/i],
        errorType: "TransferableNotAllowedError",
        description: "for transferable object restrictions"
      },
      {
        patterns: [/state|illegal|invalid/i, /sealed|configured/i],
        errorType: "IllegalStateError",
        description: "for illegal state transitions"
      },
    ];

    /**
     * Analyzes error message to suggest appropriate error type
     */
    function suggestErrorType(message) {
      if (!message) return ["InvalidParameterError"];

      const messageStr = String(message).toLowerCase();
      const suggestions = [];

      for (const mapping of errorMappings) {
        const allPatternsMatch = mapping.patterns.every(pattern => 
          pattern.test(messageStr)
        );
        if (allPatternsMatch) {
          suggestions.push(mapping.errorType);
        }
      }

      // If no specific match, suggest based on common keywords
      for (const mapping of errorMappings) {
        if (mapping.patterns.some(pattern => pattern.test(messageStr))) {
          if (!suggestions.includes(mapping.errorType)) {
            suggestions.push(mapping.errorType);
          }
        }
      }

      return suggestions.length > 0 ? suggestions : ["InvalidParameterError"];
    }

    /**
     * Checks if an error type is from our custom errors module
     */
    function isCustomErrorType(errorName) {
      const customErrors = [
        "CryptoUnavailableError",
        "InvalidParameterError", 
        "EncodingError",
        "RandomGenerationError",
        "InvalidConfigurationError",
        "SignatureVerificationError",
        "ReplayAttackError",
        "TimestampError",
        "WorkerError",
        "RateLimitError",
        "CircuitBreakerError", 
        "TransferableNotAllowedError",
        "IllegalStateError",
        "SecurityKitError"
      ];
      return customErrors.includes(errorName);
    }

    /**
     * Extracts error message from throw statement for analysis
     */
    function extractErrorMessage(throwNode) {
      const argument = throwNode.argument;
      if (argument?.type === "NewExpression") {
        const firstArg = argument.arguments?.[0];
        if (firstArg?.type === "Literal" && typeof firstArg.value === "string") {
          return firstArg.value;
        }
        if (firstArg?.type === "TemplateLiteral") {
          // Handle template literals by examining the raw parts
          return firstArg.raw || firstArg.quasis?.map(q => q.value?.cooked || q.value?.raw).join("");
        }
      }
      return null;
    }

    return {
      ThrowStatement(node) {
        const argument = node.argument;
        
        if (argument?.type === "NewExpression") {
          const errorConstructor = argument.callee;
          const errorName = errorConstructor?.name;

          // Skip if already using custom error type
          if (isCustomErrorType(errorName)) {
            return;
          }

          // Skip if explicitly allowed
          if (allowedGenericErrors.has(errorName)) {
            return;
          }

          // Flag generic error types
          const genericErrors = ["Error", "RangeError", "TypeError", "ReferenceError"];
          if (genericErrors.includes(errorName)) {
            const message = extractErrorMessage(node);
            const suggestions = suggestErrorType(message);
            
            context.report({
              node: argument,
              messageId: "useTypedError",
              data: { 
                errorType: errorName,
                suggestions: suggestions.slice(0, 2).join(" or ")
              }
            });
          }
        } 
        
        // Handle direct identifier throws (e.g., throw someError)
        else if (argument?.type === "Identifier") {
          // This might be re-throwing an existing error, which could be acceptable
          // We'll be lenient here unless the variable name suggests it's a generic error
          const varName = argument.name;
          if (varName === "error" || varName === "err" || varName === "e") {
            // This is likely a re-throw, which is generally acceptable
            return;
          }
        }
        
        // Handle other throw patterns
        else {
          context.report({
            node: argument || node,
            messageId: "unknownErrorPattern",
          });
        }
      },

      // Check variable declarations that create Error objects
      VariableDeclarator(node) {
        if (node.init?.type === "NewExpression") {
          const errorConstructor = node.init.callee;
          const errorName = errorConstructor?.name;
          
          if (errorName === "Error" && !isCustomErrorType(errorName)) {
            // This might be creating an error to throw later
            const message = extractErrorMessage({ argument: node.init });
            const suggestions = suggestErrorType(message);
            
            context.report({
              node: node.init,
              messageId: "preferSpecificError", 
              data: { suggestions: suggestions.slice(0, 2).join(" or ") },
            });
          }
        }
      },
    };
  },
};