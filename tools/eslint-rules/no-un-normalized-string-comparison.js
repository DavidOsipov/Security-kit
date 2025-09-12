/**
 * @fileoverview ESLint rule: no-un-normalized-string-comparison
 * Requires Unicode normalization for external string comparisons to prevent
 * homograph attacks and Unicode normalization bypasses (ASVS V5.1.4).
 * Flags binary string comparisons and method calls where one operand appears
 * to be from an external source and hasn't been normalized.
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description:
        "Require Unicode normalization for external string comparisons to prevent homograph attacks",
      recommended: true,
    },
    // fixable removed: convert to error-only reporting to avoid unsafe automated edits
    schema: [],
    messages: {
      requireNormalization:
        "String comparison with external input requires normalization. Use normalizeInputString() from url.ts or similar normalization function",
      unsafeMethodCall:
        "String method '{{method}}' on external input requires normalization first. External strings may contain visually identical but canonically different characters",
      unsafeSwitchCase:
        "Switch statement with external input requires normalization. Use normalizeInputString() before the switch",
      unsafeRegexTest:
        "RegExp test with external input requires normalization to prevent Unicode bypass attacks",
    },
  },

  create(context) {
    // Skip tests and scripts
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\//i.test(filename)) {
      return {};
    }

    /**
     * Detects if a node represents potentially external/untrusted input
     */
    function isTaintedInput(node, context) {
      if (!node) return false;

      // Function parameters are considered external input
      if (node.type === "Identifier") {
        // Look for parameter-like names
        const name = node.name;
        const externalPatterns = [
          /^(input|data|value|param|arg|query|search|filter|term)$/i,
          /^user/i,
          /^external/i,
          /^raw/i,
          /Input$/,
          /Data$/,
          /Param$/,
        ];
        
        if (externalPatterns.some(pattern => pattern.test(name))) {
          return true;
        }

        // Check if this identifier is a function parameter
        // Use modern ESLint API - sourceCode.getScope is available in flat config
        const sourceCode = context.sourceCode || context.getSourceCode();
        let scope = sourceCode.getScope ? sourceCode.getScope(node) : context.getScope();
        while (scope) {
          const variable = scope.variables.find(v => v.name === name);
          if (variable && variable.defs.length > 0) {
            const def = variable.defs[0];
            if (def.type === "Parameter") {
              return true;
            }
          }
          scope = scope.upper;
        }
      }

      // Property access that looks like external data
      if (node.type === "MemberExpression") {
        const property = node.property;
        if (property && property.type === "Identifier") {
          const externalProperties = [
            "value", "textContent", "innerText", "data", 
            "search", "hash", "pathname", "hostname", "href"
          ];
          if (externalProperties.includes(property.name)) {
            return true;
          }
        }
      }

      // URLSearchParams.get(), new URL().hash, etc.
      if (node.type === "CallExpression") {
        const callee = node.callee;
        if (callee && callee.type === "MemberExpression") {
          const object = callee.object;
          const method = callee.property;
          
          if (method && method.type === "Identifier") {
            // URLSearchParams methods
            if (method.name === "get" || method.name === "getAll") {
              return true;
            }
            // URL parsing methods
            if (method.name === "toString" && object && 
                object.type === "NewExpression" && 
                object.callee && object.callee.name === "URL") {
              return true;
            }
          }
        }
      }

      return false;
    }

    /**
     * Checks if a string has been normalized using approved functions
     */
    function isNormalizedString(node) {
      if (!node) return false;
      
      // Check for calls to normalization functions
      if (node.type === "CallExpression") {
        const callee = node.callee;
        if (callee && callee.type === "Identifier") {
          const normalizationFunctions = [
            "normalizeInputString",
            "normalizeUnicode", 
            "sanitizeInput",
            "normalizeString"
          ];
          return normalizationFunctions.includes(callee.name);
        }
        
        // Check for String.prototype.normalize() calls
        if (callee && callee.type === "MemberExpression" &&
            callee.property && callee.property.name === "normalize") {
          return true;
        }
      }
      
      return false;
    }

    return {
      BinaryExpression(node) {
        if (node.operator !== "===" && node.operator !== "!==") {
          return;
        }

        const left = node.left;
        const right = node.right;

        // Check if either side is tainted and the other is not normalized
        if (isTaintedInput(left, context) && !isNormalizedString(left)) {
          context.report({
            node: left,
            messageId: "requireNormalization",
          });
        }

        if (isTaintedInput(right, context) && !isNormalizedString(right)) {
          context.report({
            node: right,
            messageId: "requireNormalization",
          });
        }
      },

      CallExpression(node) {
        const callee = node.callee;
        if (!callee || callee.type !== "MemberExpression") {
          return;
        }

        const object = callee.object;
        const method = callee.property;

        if (!method || method.type !== "Identifier") {
          return;
        }

        // String methods that require normalization
        const dangerousMethods = [
          "includes", "startsWith", "endsWith", "indexOf", 
          "lastIndexOf", "match", "search"
        ];

        if (dangerousMethods.includes(method.name)) {
          if (isTaintedInput(object, context) && !isNormalizedString(object)) {
            context.report({
              node: object,
              messageId: "unsafeMethodCall",
              data: { method: method.name },
            });
          }

          // Also check arguments for tainted input
          node.arguments.forEach(arg => {
            if (isTaintedInput(arg, context) && !isNormalizedString(arg)) {
              context.report({
                node: arg,
                messageId: "unsafeMethodCall",
                data: { method: method.name },
              });
            }
          });
        }

        // RegExp.test() calls
        if (method.name === "test" && 
            object.type === "Identifier" && /regex|regexp|pattern/i.test(object.name)) {
          node.arguments.forEach(arg => {
            if (isTaintedInput(arg, context) && !isNormalizedString(arg)) {
              context.report({
                node: arg,
                messageId: "unsafeRegexTest",
              });
            }
          });
        }
      },

      SwitchStatement(node) {
        const discriminant = node.discriminant;
        if (isTaintedInput(discriminant, context) && !isNormalizedString(discriminant)) {
          context.report({
            node: discriminant,
            messageId: "unsafeSwitchCase",
          });
        }
      },
    };
  },
};