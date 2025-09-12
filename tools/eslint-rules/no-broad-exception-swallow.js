/**
 * @fileoverview ESLint rule: no-broad-exception-swallow
 * Prevents broad exception swallowing that violates "Fail Loudly, Fail Safely" principle.
 * Enforces Security Constitution §1.4 by ensuring exceptions are either handled specifically
 * with appropriate recovery actions or rethrown as typed errors.
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description:
        "Prevent broad exception swallowing that violates 'Fail Loudly, Fail Safely' principle",
      recommended: true,
    },
    schema: [
      {
        type: "object", 
        properties: {
          allowedRecoveryPatterns: {
            type: "array",
            items: { type: "string" },
            description: "Function names that represent approved recovery actions"
          },
          approvedReporters: {
            type: "array",
            items: { type: "string" }, 
            description: "Approved error reporting function names"
          }
        },
        additionalProperties: false,
      }
    ],
    messages: {
      emptyCatch:
        "Empty catch blocks violate Security Constitution §1.4 'Fail Loudly, Fail Safely'. " +
        "Either handle the error specifically or rethrow a typed error.",
      genericLogging:
        "Generic console logging without rethrowing violates fail-safe principles. " +
        "Use reportProdError() or throw a typed error from errors.ts.",
      requireSpecificHandling:
        "Catch blocks must either: 1) Call an approved error reporter, 2) Throw a typed error, " +
        "or 3) Perform specific recovery actions. Generic error swallowing is forbidden.",
      approvedPattern:
        "Security-approved error handling pattern detected.",
    },
  },

  create(context) {
    // Skip tests and scripts where exception swallowing might be acceptable
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\//i.test(filename)) {
      return {};
    }

    const options = context.options[0] || {};
    
    // Default approved error reporting functions
    const defaultReporters = [
      "reportProdError", 
      "reportError", 
      "reportSecurityError",
      "secureDevelopmentLog",
      "secureDevLog",
      "logSecurityEvent"
    ];
    
    // Default approved recovery patterns
    const defaultRecoveryPatterns = [
      "setFallbackState",
      "activateCircuitBreaker", 
      "switchToSafeMode",
      "disableFeature",
      "returnDefaultValue"
    ];

    const approvedReporters = options.approvedReporters || defaultReporters;
    const allowedRecoveryPatterns = options.allowedRecoveryPatterns || defaultRecoveryPatterns;

    /**
     * Checks if a statement represents an approved error handling pattern
     */
    function isApprovedErrorHandling(statement) {
      if (!statement) return false;

      // Check for approved error reporter calls
      if (statement.type === "ExpressionStatement" && 
          statement.expression?.type === "CallExpression") {
        const callee = statement.expression.callee;
        
        if (callee?.type === "Identifier") {
          return approvedReporters.includes(callee.name);
        }
        
        // Handle property access like "logger.reportError"
        if (callee?.type === "MemberExpression" && 
            callee.property?.type === "Identifier") {
          return approvedReporters.includes(callee.property.name);
        }
      }

      // Check for typed error throws
      if (statement.type === "ThrowStatement") {
        const argument = statement.argument;
        
        // New typed error instantiation
        if (argument?.type === "NewExpression" && 
            argument.callee?.type === "Identifier") {
          const errorTypeName = argument.callee.name;
          // Your project's typed error patterns
          const typedErrorPatterns = [
            /Error$/,                    // Any custom error class
            /Exception$/,                // Custom exception classes
            /^(Invalid|Crypto|Random|IllegalState|InvalidConfiguration)/, // Your specific errors
          ];
          
          return typedErrorPatterns.some(pattern => pattern.test(errorTypeName));
        }
        
        // Re-throwing the caught error (but enhanced)
        if (argument?.type === "Identifier") {
          return true; // Allow rethrow
        }
      }

      // Check for approved recovery actions
      if (statement.type === "ExpressionStatement" &&
          statement.expression?.type === "CallExpression") {
        const callee = statement.expression.callee;
        
        if (callee?.type === "Identifier") {
          return allowedRecoveryPatterns.some(pattern => 
            callee.name.includes(pattern) || callee.name === pattern
          );
        }
      }

      // Check for return statements with safe default values
      if (statement.type === "ReturnStatement") {
        const argument = statement.argument;
        
        // Returning safe defaults is acceptable in some cases
        if (!argument || // return;
            (argument.type === "Literal" && 
             (argument.value === null || argument.value === false)) ||
            (argument.type === "ObjectExpression" && 
             argument.properties.some(prop => 
               prop.type === "Property" && 
               prop.key?.type === "Identifier" && 
               (prop.key.name === "ok" || prop.key.name === "error")
             ))) {
          return true;
        }
      }

      return false;
    }

    /**
     * Checks if catch block contains only generic console logging
     */
    function hasOnlyGenericLogging(statements) {
      if (statements.length !== 1) return false;
      
      const statement = statements[0];
      if (statement.type !== "ExpressionStatement" || 
          statement.expression?.type !== "CallExpression") {
        return false;
      }
      
      const callee = statement.expression.callee;
      if (callee?.type === "MemberExpression" && 
          callee.object?.type === "Identifier" &&
          callee.object.name === "console") {
        const method = callee.property?.name;
        return ["log", "error", "warn", "info"].includes(method);
      }
      
      return false;
    }

    return {
      CatchClause(node) {
        const body = node.body.body;
        
        // Empty catch block - always forbidden
        if (body.length === 0) {
          context.report({
            node: node.body,
            messageId: "emptyCatch",
          });
          return;
        }

        // Check if any statement in the catch block follows approved patterns
        const hasApprovedPattern = body.some(stmt => isApprovedErrorHandling(stmt));
        
        if (!hasApprovedPattern) {
          // Special case: only generic console logging without proper error handling
          if (hasOnlyGenericLogging(body)) {
            context.report({
              node: node.body,
              messageId: "genericLogging",
            });
            return;
          }
          
          // Generic catch block that doesn't follow security patterns
          context.report({
            node: node.body,
            messageId: "requireSpecificHandling",
          });
        }
      },

      // Also check for promise .catch() handlers
      CallExpression(node) {
        const callee = node.callee;
        
        if (callee?.type === "MemberExpression" && 
            callee.property?.type === "Identifier" &&
            callee.property.name === "catch") {
          
          const handler = node.arguments[0];
          
          if (handler && handler.type === "ArrowFunctionExpression") {
            const body = handler.body;
            
            // Empty arrow function body
            if (body.type === "BlockStatement" && body.body.length === 0) {
              context.report({
                node: body,
                messageId: "emptyCatch",
              });
            }
            
            // Single console.log without proper handling
            if (body.type === "BlockStatement" && 
                hasOnlyGenericLogging(body.body)) {
              context.report({
                node: body,
                messageId: "genericLogging",
              });
            }
          }
        }
      }
    };
  },
};