/**
 * @fileoverview ESLint rule: enforce-error-sanitization-at-boundary
 * Ensures error objects are sanitized using sanitizeErrorForLogs before being
 * passed to logging functions. Prevents stack trace and sensitive error content
 * leakage at error boundary crossings.
 * 
 * OWASP ASVS V7.1.1, V14.3.3: Error message leakage prevention
 * Security Constitution §1.4 "Fail Loudly, Fail Safely"
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Require sanitization of error objects before logging to prevent sensitive data leakage",
      recommended: true,
    },
    schema: [
      {
        type: "object", 
        properties: {
          approvedSanitizers: {
            type: "array",
            items: { type: "string" },
            description: "Functions that properly sanitize errors for logging"
          },
          loggingFunctions: {
            type: "array",
            items: { type: "string" },
            description: "Functions that are considered logging boundaries"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      unsanitizedError: "Error object passed to {{logFunction}} must be sanitized. Use sanitizeErrorForLogs({{errorName}}) to prevent sensitive data leakage.",
      suggestSanitization: "Wrap error with: sanitizeErrorForLogs({{errorName}})"
    },
    // fixable removed to prevent unsafe automated edits; rule is error-only
  },

  create(context) {
    const options = context.options[0] || {};
    const approvedSanitizers = new Set(options.approvedSanitizers || [
      "sanitizeErrorForLogs", 
      "sanitizeErrorMessage",
      "redactError"
    ]);
    const loggingFunctions = new Set(options.loggingFunctions || [
      "secureDevLog",
      "secureDevelopmentLog", 
      "reportProdError",
      "console.error",
      "console.warn",
      "console.log",
      "console.info",
      "console.debug"
    ]);

    // Skip tests and scripts
    const filename = context.getFilename() || "";
    if (/\b(tests?|demo|benchmarks|scripts)\b/i.test(filename)) {
      return {};
    }

    /**
     * Track error variables declared in catch blocks
     */
    const errorVariables = new Set();

    /**
     * Check if an identifier is a known error variable
     */
    function isErrorVariable(name) {
      return errorVariables.has(name) || /^(err|error|exception|ex)$/i.test(name);
    }

    /**
     * Check if expression is already sanitized
     */
    function isSanitized(node) {
      if (node.type === "CallExpression" && node.callee?.name) {
        return approvedSanitizers.has(node.callee.name);
      }
      return false;
    }

    /**
     * Check if this is a logging function call
     */
    function isLoggingCall(node) {
      if (node.type !== "CallExpression") return false;
      
      // Direct function calls (secureDevLog)
      if (node.callee?.name && loggingFunctions.has(node.callee.name)) {
        return true;
      }
      
      // Member expression calls (console.error)
      if (node.callee?.type === "MemberExpression") {
        const fullName = `${node.callee.object?.name}.${node.callee.property?.name}`;
        return loggingFunctions.has(fullName);
      }
      
      return false;
    }

    /**
     * Find error identifiers in arguments recursively
     */
    function findErrorIdentifiers(node, errors = []) {
      if (!node) return errors;

      if (node.type === "Identifier" && isErrorVariable(node.name)) {
        errors.push(node);
      } else if (node.type === "ObjectExpression") {
        // Check object properties: { error: errorVar, data: {...} }
        node.properties?.forEach(prop => {
          if (prop.type === "Property") {
            findErrorIdentifiers(prop.value, errors);
          }
        });
      } else if (node.type === "ArrayExpression") {
        node.elements?.forEach(el => findErrorIdentifiers(el, errors));
      } else if (node.type === "ConditionalExpression") {
        findErrorIdentifiers(node.consequent, errors);
        findErrorIdentifiers(node.alternate, errors);
      }

      return errors;
    }

    return {
      CatchClause(node) {
        // Track error parameter in catch blocks
        if (node.param?.type === "Identifier") {
          errorVariables.add(node.param.name);
        }
      },

      "CatchClause:exit"(node) {
        // Remove error parameter when exiting catch block
        if (node.param?.type === "Identifier") {
          errorVariables.delete(node.param.name);
        }
      },

      CallExpression(node) {
        if (!isLoggingCall(node)) return;

        const logFunctionName = node.callee?.name || 
          `${node.callee?.object?.name}.${node.callee?.property?.name}`;

        // Check all arguments for unsanitized errors
        node.arguments.forEach(arg => {
          if (isSanitized(arg)) return; // Already sanitized

          const errorIds = findErrorIdentifiers(arg);
          errorIds.forEach(errorId => {
            context.report({
              node: errorId,
              messageId: "unsanitizedError",
              data: {
                logFunction: logFunctionName,
                errorName: errorId.name
              }
            });
          });
        });
      }
    };
  }
};
