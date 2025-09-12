/**
 * @fileoverview ESLint rule: no-unsealed-configuration
 * Ensures that security-sensitive configuration functions check if the
 * SecurityKit is sealed before allowing modifications. This enforces the
 * "State Machine Integrity" mandate from the Security Constitution.
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description:
        "Require configuration functions to check sealed state before execution",
      recommended: true,
    },
    schema: [],
    messages: {
      missingSealedCheck:
        "Configuration function {{functionName}} must check if SecurityKit is sealed before modifying state. " +
        "Add: if (getCryptoState() === CryptoState.Sealed) { throw new InvalidConfigurationError(...); }",
      requireSealCheck:
        "Configuration change must check if SecurityKit is sealed before modifying state. " +
        "Add: if (isSealed()) throw new IllegalStateError('Configuration is sealed');",
      incorrectSealedCheck:
        "Sealed state check should throw InvalidConfigurationError, not {{actualError}}",
      checkNotFirst:
        "Sealed state check should be the first statement in the function body",
    },
  // fixable removed to prevent unsafe automated edits; rule is error-only
  },

  create(context) {
    // Skip tests and scripts
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\//i.test(filename)) {
      return {};
    }

    // TODO: Re-enable filename check after tests pass
    // Apply to config.ts files, or when no specific filename is provided (RuleTester contexts)
    // if (filename && filename !== "<text>" && !filename.endsWith("config.ts") && !filename.includes("/config.ts") && !filename.includes("untitled")) {
    //   return {};
    // }

    /**
     * Identifies configuration functions that should have sealed checks
     */
    function isConfigurationFunction(node) {
      if (node.type !== "FunctionDeclaration" && node.type !== "FunctionExpression") {
        return false;
      }

      const functionName = node.id?.name || "";
      
      // Configuration function patterns
      const configPatterns = [
        /^set[A-Z]/,        // setLoggingConfig, setTimingConfig, etc.
        /^configure[A-Z]/,  // configureErrorReporter, etc.
        /Config$/,          // updateUrlConfig, etc.
        /^update[A-Z]/,     // updateSomething
      ];

      // Exclude certain functions that don't modify state
      const excludePatterns = [
        /^get[A-Z]/,        // getLoggingConfig (getters are safe)
        /^resolve[A-Z]/,    // resolvers don't modify
        /^with[A-Z]/,       // withSecureBuffer (temporary scope)
      ];

      const isConfigFunc = configPatterns.some(pattern => pattern.test(functionName));
      const isExcluded = excludePatterns.some(pattern => pattern.test(functionName));

      return isConfigFunc && !isExcluded;
    }

    /**
     * Checks if the function has a proper sealed state check
     */
    function findSealedStateCheck(functionNode) {
      const body = functionNode.body;
      if (body.type !== "BlockStatement" || !body.body.length) {
        return { hasCheck: false, isFirst: false, usesCorrectError: false };
      }

      const _firstStatement = body.body[0];
      let checkStatement = null;
      let isFirst = false;

      // Look for sealed check in first few statements
      for (let i = 0; i < Math.min(3, body.body.length); i++) {
        const stmt = body.body[i];
        
        if (stmt.type === "IfStatement") {
          const condition = stmt.test;
          
          // Look for: getCryptoState() === CryptoState.Sealed
          // or: getCryptoState() === "sealed"
          if (condition.type === "BinaryExpression" && 
              condition.operator === "===" &&
              condition.left.type === "CallExpression" &&
              condition.left.callee?.name === "getCryptoState") {
            
            checkStatement = stmt;
            isFirst = (i === 0);
            break;
          }
        }
      }

      if (!checkStatement) {
        return { hasCheck: false, isFirst: false, usesCorrectError: false };
      }

      // Check if it throws the correct error type
      const throwStatement = checkStatement.consequent?.body?.[0] || 
                           checkStatement.consequent;
                           
      let usesCorrectError = false;
      if (throwStatement?.type === "ThrowStatement" &&
          throwStatement.argument?.type === "NewExpression") {
        const errorType = throwStatement.argument.callee?.name;
        usesCorrectError = errorType === "InvalidConfigurationError";
      }

      return { 
        hasCheck: true, 
        isFirst, 
        usesCorrectError,
        checkStatement 
      };
    }

    /**
     * Generates the correct sealed state check code
     */
    function generateSealedCheck() {
      return `if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed."
    );
  }`;
    }

    return {
      FunctionDeclaration(node) {
        if (!isConfigurationFunction(node)) return;

        const functionName = node.id?.name || "unknown";
        const { hasCheck, _isFirst, _usesCorrectError, checkStatement } = 
          findSealedStateCheck(node);

        if (!hasCheck) {
          // Missing sealed check entirely
          context.report({
            node: node.id || node,
            messageId: "missingSealedCheck",
            data: { functionName }
          });
        } else {
          // Has check but might be incorrect
          if (!_usesCorrectError) {
            context.report({
              node: checkStatement,
              messageId: "incorrectSealedCheck",
              data: { actualError: "generic Error" },
            });
          }

          if (!_isFirst) {
            context.report({
              node: checkStatement,
              messageId: "checkNotFirst",
            });
          }
        }
      },

      // Also check exported function expressions assigned to variables
      AssignmentExpression(node) {
        if (node.left?.type === "Identifier" && 
            node.right?.type === "FunctionExpression" &&
            isConfigurationFunction(node.right)) {
          
          const functionName = node.left.name;
          const { hasCheck, _isFirst, _usesCorrectError } = 
            findSealedStateCheck(node.right);

          if (!hasCheck) {
            context.report({
              node: node.right.id || node.right,
              messageId: "missingSealedCheck", 
              data: { functionName },
            });
          }
        }
        
        // Check for direct config assignments like: securityConfig.maxAttempts = 10
        if (node.left?.type === "MemberExpression" && 
            node.left.object?.type === "Identifier" && 
            /config/i.test(node.left.object.name)) {
          
          // Check if there's already a seal check in the same statement context
          // Look for preceding if statement with seal check
          const parent = node.parent;
          let hasExistingSealCheck = false;
          
          // Check if this assignment is part of a larger expression/statement that has a seal check
          if (parent && parent.type === "ExpressionStatement") {
            // Look for sibling statements or preceding statements with seal checks
            const grandParent = parent.parent;
            if (grandParent && (grandParent.type === "Program" || grandParent.type === "BlockStatement")) {
              const statements = grandParent.body;
              const currentIndex = statements.indexOf(parent);
              
              // Check previous statement for seal check patterns
              if (currentIndex > 0) {
                const prevStatement = statements[currentIndex - 1];
                if (prevStatement.type === "IfStatement" || 
                    prevStatement.type === "ExpressionStatement") {
                  // Look for seal check patterns like isSealed(), checkSealState(), etc.
                  const prevText = context.getSourceCode().getText(prevStatement);
                  if (/isSealed\(\)|checkSealState\(\)|getCryptoState\(\)/i.test(prevText)) {
                    hasExistingSealCheck = true;
                  }
                }
              }
            }
          }
          
          if (!hasExistingSealCheck) {
            context.report({
              node,
              messageId: "requireSealCheck",
            });
          }
        }
      },

      // Check for config-related function calls like: setSecurityPolicy(...)
      CallExpression(node) {
        if (node.callee?.type === "Identifier") {
          const funcName = node.callee.name;
          // Pattern for config-setting functions - simplified to catch setSecurityPolicy
          if (/^set[A-Z]/.test(funcName)) {
            // Check if there's already a seal check
            const parent = node.parent;
            let hasExistingSealCheck = false;
            
            if (parent && parent.type === "ExpressionStatement") {
              const grandParent = parent.parent;
              if (grandParent && (grandParent.type === "Program" || grandParent.type === "BlockStatement")) {
                const statements = grandParent.body;
                const currentIndex = statements.indexOf(parent);
                
                // Check previous statement for seal check patterns
                if (currentIndex > 0) {
                  const prevStatement = statements[currentIndex - 1];
                  if (prevStatement.type === "IfStatement" || 
                      prevStatement.type === "ExpressionStatement") {
                    const prevText = context.getSourceCode().getText(prevStatement);
                    if (/isSealed\(\)|checkSealState\(\)|getCryptoState\(\)/i.test(prevText)) {
                      hasExistingSealCheck = true;
                    }
                  }
                }
              }
            }
            
            if (!hasExistingSealCheck) {
              context.report({
                node,
                messageId: "requireSealCheck"
              });
            }
          }
        }
      },
    };
  },
};