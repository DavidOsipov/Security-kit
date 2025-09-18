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

    // Map of containing function node (or null for program-level) -> Set of abort controller identifiers
    const abortControllers = new Map();
    // Map of containing function node (or null for program-level) -> boolean (has visibility listener or helper)
    const visibilityListeners = new Map();
    const sensitiveOperationCalls = new Map();
    // Configurable helper names that implement the visibility-abort pattern (to avoid false positives)
    const helperVisibilityFunctions = new Set(options.visibilityHelpers || [
      'setupVisibilityAbort',
      'withVisibilityAbort',
      'ensureVisibilityAbort',
    ]);
    // Configurable helper names that perform an abort-check (return boolean) inside loops
    const abortCheckFunctions = new Set(options.abortCheckFunctions || [
      'shouldAbortForVisibility',
      'isHidden',
    ]);

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
      // Helper: check a block statement body for a direct visibilityState === 'hidden' check
      function bodyHasVisibilityCheck(body) {
        if (!body || body.type !== 'BlockStatement') return false;
        return body.body.some(stmt =>
          stmt.type === 'IfStatement' &&
          stmt.test?.type === 'BinaryExpression' &&
          stmt.test.operator === '===' &&
          stmt.test.left?.type === 'MemberExpression' &&
          // match document.visibilityState === 'hidden'
          stmt.test.left.object?.type === 'Identifier' &&
          stmt.test.left.object?.name === 'document' &&
          stmt.test.left.property?.name === 'visibilityState' &&
          stmt.test.right?.type === 'Literal' &&
          stmt.test.right.value === 'hidden'
        );
      }

      if (!containingFunc) {
        // Walk up parents to try to find a direct visibility check in the scope
        let parent = node.parent;
        while (parent) {
          if (parent.type === 'IfStatement') {
            if (bodyHasVisibilityCheck({ body: [parent] })) return true;
          }
          parent = parent.parent;
        }
        return false;
      }

      // For functions, check for explicit checks, direct abort helper calls, or for a registered visibility listener/helper
      if (bodyHasVisibilityCheck(containingFunc.body)) return true;

      // Walk the function body to find calls to known abort-check helper functions
      let foundAbortCheck = false;
      function scanForAbortCheck(n) {
        if (!n || foundAbortCheck) return;
        if (n.type === 'CallExpression' && n.callee?.type === 'Identifier' && abortCheckFunctions.has(n.callee.name)) {
          foundAbortCheck = true;
          return;
        }
        for (const key in n) {
          if (key === 'parent') continue;
          const child = n[key];
          if (Array.isArray(child)) child.forEach(scanForAbortCheck);
          else if (child && typeof child === 'object' && child.type) scanForAbortCheck(child);
        }
      }
      scanForAbortCheck(containingFunc.body);
      if (foundAbortCheck) return true;

      // Also accept registered listeners/helpers tracked earlier
      if (visibilityListeners.has(containingFunc)) return true;
      if (visibilityListeners.has(null)) return true; // program-level listener/helper
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

    /**
     * Check if a loop is likely to be long-running and require visibility checks
     */
    function isLongRunningLoop(node) {
      // If loop already has visibility check, it's compliant
      if (hasVisibilityCheck(node)) {
        return false;
      }

      // Check for explicit markers in comments that indicate long-running operations
      const sourceCode = context.getSourceCode();
      const comments = sourceCode.getCommentsBefore(node);
      for (const comment of comments) {
        if (comment.value.includes('long-running') || 
            comment.value.includes('crypto') ||
            comment.value.includes('expensive') ||
            comment.value.includes('timing-sensitive')) {
          return true;
        }
      }

      // Heuristic 1: Check if loop contains sensitive operations
      let containsSensitiveOps = false;
      let containsNetworkOps = false;
      let containsUnboundedOperation = false;

      // Walk through loop body to check for sensitive operations
      function checkNode(n) {
        if (!n) return;

        // Check for sensitive crypto operations
        if (n.type === "CallExpression") {
          const opName = isSensitiveOperation(n);
          if (opName) {
            containsSensitiveOps = true;
          }

          // Check for network operations
          if (n.callee?.name === "fetch" || 
              (n.callee?.type === "MemberExpression" && 
               n.callee.property?.name === "fetch")) {
            containsNetworkOps = true;
          }

          // Check for potentially unbounded operations
          if (n.callee?.name === "crypto.getRandomValues" ||
              n.callee?.name === "Math.random" ||
              (n.callee?.type === "MemberExpression" &&
               (n.callee.property?.name === "getRandomValues" ||
                n.callee.property?.name === "random"))) {
            containsUnboundedOperation = true;
          }
        }

        // Recursively check child nodes
        for (const key in n) {
          if (key === 'parent') continue; // Avoid circular references
          const child = n[key];
          if (Array.isArray(child)) {
            child.forEach(checkNode);
          } else if (child && typeof child === 'object' && child.type) {
            checkNode(child);
          }
        }
      }

      checkNode(node.body);

      // If loop contains sensitive operations, it needs visibility checks
      if (containsSensitiveOps || containsNetworkOps || containsUnboundedOperation) {
        return true;
      }

      // Heuristic 2: Check loop bounds and iteration patterns
      if (node.test) {
        // Check for potentially large bounds
        if (node.test.type === "BinaryExpression") {
          const right = node.test.right;
          if (right?.type === "Literal" && typeof right.value === "number") {
            // Consider loops with more than 1000 iterations as potentially long-running
            if (right.value > 1000) {
              return true;
            }
          }
          
          // Check for unbounded loops or loops based on external data
          if (right?.type === "MemberExpression") {
            // Loops like `i < array.length` where array could be large
            if (right.property?.name === "length") {
              // Exception: Object.keys() results are typically small for object property iteration
              if (right.object?.type === "CallExpression" &&
                  right.object.callee?.type === "MemberExpression" &&
                  right.object.callee.object?.name === "Object" &&
                  right.object.callee.property?.name === "keys") {
                return false; // Object property iteration is safe
              }
              return true; // Other .length-based loops might be large
            }
          }
        }
      }

      // Heuristic 3: Check for nested loops (O(n²) or worse complexity)
      let nestedLoopCount = 0;
      function countNestedLoops(n) {
        if (!n) return;
        if (n.type === "ForStatement" || 
            n.type === "WhileStatement" || 
            n.type === "DoWhileStatement") {
          nestedLoopCount++;
        }
        for (const key in n) {
          if (key === 'parent') continue;
          const child = n[key];
          if (Array.isArray(child)) {
            child.forEach(countNestedLoops);
          } else if (child && typeof child === 'object' && child.type) {
            countNestedLoops(child);
          }
        }
      }
      
      countNestedLoops(node.body);
      if (nestedLoopCount > 0) { // Has nested loops
        return true;
      }

      // Heuristic 4: Simple bounded loops with small, known limits are safe
      if (node.init?.type === "VariableDeclaration" &&
          node.test?.type === "BinaryExpression" &&
          node.test.right?.type === "Literal" &&
          typeof node.test.right.value === "number" &&
          node.test.right.value <= 100) { // Small, bounded iteration
        return false;
      }

      // Default: for safety, consider other loops as potentially needing checks
      // but provide a more nuanced message
      return false; // Changed: be conservative and only flag clearly problematic cases
    }

    return {
      // Track AbortController declarations
      VariableDeclarator(node) {
        if (node.init?.type === 'NewExpression' &&
            node.init.callee?.name === 'AbortController' &&
            node.id?.type === 'Identifier') {
          const func = findContainingFunction(node) || null;
          let set = abortControllers.get(func);
          if (!set) {
            set = new Set();
            abortControllers.set(func, set);
          }
          set.add(node.id.name);
        }
      },

      // Track visibility change listeners  
      CallExpression(node) {
        // Track addEventListener('visibilitychange', ...)
        if (node.callee?.type === 'MemberExpression' &&
            node.callee?.object?.name === 'document' &&
            node.callee?.property?.name === 'addEventListener' &&
            node.arguments[0]?.type === 'Literal' &&
            node.arguments[0]?.value === 'visibilitychange') {
          const func = findContainingFunction(node) || null;
          visibilityListeners.set(func, true);
        }

        // Recognize calls to helper functions that implement the visibility-abort pattern
        if (node.callee?.type === 'Identifier' && helperVisibilityFunctions.has(node.callee.name)) {
          const func = findContainingFunction(node) || null;
          visibilityListeners.set(func, true);
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
          const key = containingFunc || null;
          if (!sensitiveOperationCalls.has(key)) {
            sensitiveOperationCalls.set(key, []);
          }
          sensitiveOperationCalls.get(key).push({
            node,
            operationName,
            hasAbortSignal: hasAbortSignal(node)
          });
        }
      },

      // Check for ForStatement loops
      ForStatement(node) {
        if (isLongRunningLoop(node)) {
          context.report({
            node,
            messageId: "longRunningWithoutVisibilityCheck",
            data: { operation: "for loop" }
          });
        }
      },

      "Program:exit"() {
        // Check each function (or program-level key) with sensitive operations
        sensitiveOperationCalls.forEach((operations, _functionNode) => {
          const funcKey = _functionNode || null;
          const controllersForFunction = abortControllers.get(funcKey);
          const functionHasAbortController = (controllersForFunction && controllersForFunction.size > 0) || false;

          const functionHasVisibilityListener = Boolean(visibilityListeners.get(funcKey) || visibilityListeners.get(null));

          operations.forEach(({ node, operationName, hasAbortSignal }) => {
            if (!functionHasVisibilityListener) {
              context.report({
                node,
                messageId: 'missingVisibilityAbort',
                data: { operation: operationName }
              });
            }

            if (!hasAbortSignal && !functionHasAbortController) {
              context.report({
                node,
                messageId: 'missingAbortController', 
                data: { operation: operationName }
              });
            }

            if (functionHasAbortController && !hasAbortSignal) {
              context.report({
                node,
                messageId: 'abortSignalNotPassed',
                data: { operation: operationName }
              });
            }
          });
        });
      }
    };
  }
};