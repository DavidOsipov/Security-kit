/**
 * @fileoverview ESLint rule: enforce-visibility-abort-pattern
 * Enforces that crypto operations and timing-sensitive tasks implement the
 * mandatory visibility change abort pattern required by Security Constitution §2.11.
 * 
 * OWASP ASVS V1.14.4, V11.1.2: Session management, timing attack prevention
 * Security Constitution §2.11 "Data Integrity on Visibility Change (MUST)"
 * 
 * NOTE: This rule provides error reporting only - no autofix.
 * Security-critical patterns must be manually implemented and audited.
 */

export default {
  meta: {
    type: "problem", 
    docs: {
      description: "Enforce visibility change abort pattern for crypto operations per Security Constitution §2.11",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          sensitiveOperations: {
            type: "array",
            items: { type: "string" },
            description: "Function names that require visibility abort pattern"
          },
          allowTestFiles: {
            type: "boolean",
            description: "Allow test files to skip visibility pattern requirements"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      missingVisibilityAbort: "Security violation: {{operation}} requires visibility change abort pattern per Security Constitution §2.11. Implement manual pattern: 1) Create AbortController, 2) Add visibilitychange listener that calls abort(), 3) Pass signal to operation",
      longRunningWithoutVisibilityCheck: "Security violation: Long-running {{operation}} must check document.visibilityState === 'hidden' to prevent timing attacks per Security Constitution §2.11",
      suggestVisibilityPattern: "Required pattern: document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') controller.abort(); })",
      missingAbortController: "Security violation: {{operation}} requires AbortController for safe cancellation. Create: const controller = new AbortController()",
      abortSignalNotPassed: "Security violation: Pass abort signal to {{operation}}: add { signal: controller.signal } parameter"
    },
    // Removed fixable property - security patterns must be manually implemented
  },

  create(context) {
    const options = context.options[0] || {};
    const sensitiveOperations = new Set(options.sensitiveOperations || [
      "secureCompareAsync",
      "secureWipeAsync", 
      "generateSecureId",
      "generateSecureString",
      "createSecureZeroingBuffer",
      "SecureApiSigner.create",
      "sendSecurePostMessage",
      "crypto.subtle.digest",
      "crypto.subtle.sign",
      "crypto.subtle.verify",
      "crypto.getRandomValues",
      "fetch" // Network operations can be timing-sensitive
    ]);

    // Skip tests and demos if allowTestFiles is true (default)
    const allowTestFiles = options.allowTestFiles !== false;
    const filename = context.getFilename() || "";
    if (allowTestFiles && /\b(tests?|demo|benchmarks)\b/i.test(filename)) {
      return {};
    }

    const abortControllers = new Set();
    const visibilityListeners = new Set();
    const sensitiveOperationCalls = new Map();

    /**
     * Check if node is a sensitive operation call
     */
    function isSensitiveOperation(node) {
      if (node.type !== "CallExpression") return false;

      // Direct function calls
      if (node.callee?.name && sensitiveOperations.has(node.callee.name)) {
        return node.callee.name;
      }

      // Member expression calls (crypto.subtle.digest)
      if (node.callee?.type === "MemberExpression") {
        const object = node.callee.object?.name;
        const property = node.callee.property?.name;
        if (object && property) {
          const fullName = `${object}.${property}`;
          if (sensitiveOperations.has(fullName)) {
            return fullName;
          }
        }

        // Static method calls (SecureApiSigner.create)
        if (node.callee.object?.type === "Identifier" && 
            node.callee.property?.type === "Identifier") {
          const staticCall = `${object}.${property}`;
          if (sensitiveOperations.has(staticCall)) {
            return staticCall;
          }
        }
      }

      return null;
    }

    /**
     * Check if operation has abort signal in options
     */
    function hasAbortSignal(callNode) {
      return callNode.arguments.some(arg => {
        if (arg.type === "ObjectExpression") {
          return arg.properties.some(prop => 
            prop.type === "Property" && 
            prop.key?.name === "signal"
          );
        }
        return false;
      });
    }

    /**
     * Find function containing a node
     */
    function findContainingFunction(node) {
      let current = node;
      while (current) {
        if (["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(current.type)) {
          return current;
        }
        current = current.parent;
      }
      return null;
    }

    /**
     * Check if node has visibility state check in its containing function
     */
    function hasVisibilityCheck(node) {
      const containingFunc = findContainingFunction(node);
      if (!containingFunc) {
        // Check if visibility check exists in current scope
        let parent = node.parent;
        while (parent) {
          if (parent.type === "IfStatement" &&
              parent.test?.type === "BinaryExpression" &&
              parent.test.operator === "===" &&
              parent.test.left?.type === "MemberExpression" &&
              parent.test.left.object?.type === "MemberExpression" &&
              parent.test.left.object.object?.name === "document" &&
              parent.test.left.object.property?.name === "visibilityState" &&
              parent.test.right?.type === "Literal" &&
              parent.test.right.value === "hidden") {
            return true;
          }
          parent = parent.parent;
        }
        return false;
      }
      
      // For functions, check the body for visibility checks
      const body = containingFunc.body;
      if (body?.type === "BlockStatement") {
        return body.body.some(stmt => 
          stmt.type === "IfStatement" &&
          stmt.test?.type === "BinaryExpression" &&
          stmt.test.operator === "===" &&
          stmt.test.left?.type === "MemberExpression" &&
          stmt.test.left.object?.type === "MemberExpression" &&
          stmt.test.left.object.object?.name === "document" &&
          stmt.test.left.object.property?.name === "visibilityState" &&
          stmt.test.right?.type === "Literal" &&
          stmt.test.right.value === "hidden"
        );
      }
      return false;
    }

    /**
     * Check if setTimeout/setInterval is immediate scheduling (0 delay or very short)
     */
    function isImmediateScheduling(callNode) {
      // Check if second argument (delay) is 0 or very small number
      if (callNode.arguments.length >= 2) {
        const delay = callNode.arguments[1];
        if (delay?.type === "Literal" && typeof delay.value === "number") {
          // Consider delays <= 16ms as immediate scheduling (single frame)
          return delay.value <= 16;
        }
      }
      // If no delay specified for setTimeout, it's treated as 0
      if (callNode.callee?.name === "setTimeout" && callNode.arguments.length === 1) {
        return true;
      }
      return false;
    }

    return {
      // Track AbortController declarations
      VariableDeclarator(node) {
        if (node.init?.type === "NewExpression" && 
            node.init.callee?.name === "AbortController" &&
            node.id?.type === "Identifier") {
          abortControllers.add(node.id.name);
        }
      },

      // Track visibility change listeners  
      CallExpression(node) {
        // Track addEventListener('visibilitychange', ...)
        if (node.callee?.type === "MemberExpression" &&
            node.callee?.object?.name === "document" &&
            node.callee?.property?.name === "addEventListener" &&
            node.arguments[0]?.type === "Literal" &&
            node.arguments[0]?.value === "visibilitychange") {
          visibilityListeners.add(node);
        }

        // Check for setInterval/setTimeout - but exclude immediate scheduling (delay 0 or very short)
        if ((node.callee?.name === "setInterval" || node.callee?.name === "setTimeout") &&
            !hasVisibilityCheck(node) && 
            !isImmediateScheduling(node)) {
          context.report({
            node,
            messageId: "longRunningWithoutVisibilityCheck",
            data: { operation: node.callee.name }
          });
        }

        // Track sensitive operations
        const operationName = isSensitiveOperation(node);
        if (operationName) {
          const containingFunc = findContainingFunction(node);
          if (containingFunc) {
            if (!sensitiveOperationCalls.has(containingFunc)) {
              sensitiveOperationCalls.set(containingFunc, []);
            }
            sensitiveOperationCalls.get(containingFunc).push({
              node,
              operationName,
              hasAbortSignal: hasAbortSignal(node)
            });
          }
        }
      },

      // Check for ForStatement loops
      ForStatement(node) {
        if (!hasVisibilityCheck(node)) {
          context.report({
            node,
            messageId: "longRunningWithoutVisibilityCheck",
            data: { operation: "for loop" }
          });
        }
      },

      "Program:exit"() {
        // Check each function with sensitive operations
        sensitiveOperationCalls.forEach((operations, _functionNode) => {
          const functionHasAbortController = operations.some(op => 
            abortControllers.size > 0 || op.hasAbortSignal
          );

          const functionHasVisibilityListener = visibilityListeners.size > 0;

          operations.forEach(({ node, operationName, hasAbortSignal }) => {
            if (!functionHasVisibilityListener) {
              context.report({
                node,
                messageId: "missingVisibilityAbort",
                data: { operation: operationName }
              });
            }

            if (!hasAbortSignal && !functionHasAbortController) {
              context.report({
                node,
                messageId: "missingAbortController", 
                data: { operation: operationName }
              });
            }

            if (functionHasAbortController && !hasAbortSignal) {
              context.report({
                node,
                messageId: "abortSignalNotPassed",
                data: { operation: operationName }
              });
            }
          });
        });
      }
    };
  }
};