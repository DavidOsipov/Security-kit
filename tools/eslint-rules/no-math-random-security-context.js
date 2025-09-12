/**
 * @fileoverview ESLint rule: no-math-random-security-context
 * Prevents use of Math.random() in security-sensitive contexts where cryptographically
 * secure randomness is required. Enforces use of Web Crypto API through centralized
 * security-kit utilities.
 */

export default {
  meta: {
    type: "error",
    docs: {
      description:
        "Prevent Math.random() usage in security contexts; require cryptographically secure randomness",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          allowedNonSecurityFiles: {
            type: "array",
            items: { type: "string" },
            description: "File patterns where Math.random() is allowed for non-security purposes"
          },
          securityContextIndicators: {
            type: "array",
            items: { type: "string" },
            description: "Variable/function name patterns that indicate security context"
          }
        },
        additionalProperties: false,
      }
    ],
    messages: {
      mathRandomInSecurity:
        "Math.random() is forbidden in security contexts. Use getSecureRandom() or getSecureRandomInt() from security-kit instead. " +
        "Math.random() is not cryptographically secure and can be predicted.",
      mathRandomForId:
        "Math.random() cannot be used for ID generation. Use generateSecureId() or generateSecureUUID() from security-kit for unpredictable IDs.",
      mathRandomForToken:
        "Math.random() cannot be used for token/key generation. Use the appropriate crypto utilities from security-kit for secure token generation.",
      mathRandomNearCrypto:
        "Math.random() found near cryptographic operations. Consider using secure randomness from security-kit for consistency.",
    },
  },

  create(context) {
    const filename = String(context.getFilename() || "");
    const options = context.options[0] || {};
    
    // Files where Math.random() might be acceptable for non-security purposes
    const defaultAllowedFiles = [
      "/demo/",
      "/benchmarks/",
      "/tests/", 
      "/scripts/",
      "simulation",
      "animation",
      "game",
      "visualization"
    ];
    
    // Patterns that indicate security-sensitive context
    const defaultSecurityIndicators = [
      "token", "secret", "key", "password", "salt", "nonce", "iv", 
      "session", "csrf", "jwt", "auth", "credential", "signature",
      "random", "entropy", "seed", "uuid", "guid", "id"
    ];

    const allowedNonSecurityFiles = options.allowedNonSecurityFiles || defaultAllowedFiles;
    const securityContextIndicators = options.securityContextIndicators || defaultSecurityIndicators;

    /**
     * Checks if the current file is allowed to use Math.random()
     */
    function isNonSecurityFile() {
      return allowedNonSecurityFiles.some(pattern => 
        filename.includes(pattern)
      );
    }

    /**
     * Checks if a name suggests security-sensitive context
     */
    function isSecurityContext(name) {
      if (!name || typeof name !== "string") return false;
      
      const lowerName = name.toLowerCase();
      return securityContextIndicators.some(indicator => 
        lowerName.includes(indicator)
      );
    }

    /**
     * Analyzes the context around a Math.random() call
     */
    function analyzeSecurityContext(node) {
      let current = node;
      const contextNames = new Set();
      
      // Walk up the AST to gather context
      while (current && current.parent) {
        current = current.parent;
        
        // Collect variable names, function names, property names
        if (current.type === "VariableDeclarator" && current.id?.type === "Identifier") {
          contextNames.add(current.id.name);
        }
        
        if (current.type === "FunctionDeclaration" && current.id?.type === "Identifier") {
          contextNames.add(current.id.name);
        }
        
        if (current.type === "AssignmentExpression" && 
            current.left?.type === "Identifier") {
          contextNames.add(current.left.name);
        }
        
        if (current.type === "Property" && current.key?.type === "Identifier") {
          contextNames.add(current.key.name);
        }
        
        if (current.type === "MemberExpression" && 
            current.property?.type === "Identifier") {
          contextNames.add(current.property.name);
        }
      }

      // Check for security-sensitive context
      const securityNames = Array.from(contextNames).filter(name => 
        isSecurityContext(name)
      );
      
      return {
        hasSecurityContext: securityNames.length > 0,
        securityNames,
        allNames: Array.from(contextNames)
      };
    }

    /**
     * Checks if Math.random() is being used in proximity to crypto operations
     */
    function isNearCryptoOperations(node) {
      const sourceCode = context.getSourceCode();
      const program = sourceCode.ast;
      
      // Look for crypto-related imports or calls in the same file
      const cryptoPatterns = [
        "crypto", "webcrypto", "subtle", "getRandomValues",
        "generateSecureId", "getSecureRandom", "CryptoUnavailableError"
      ];
      
      const fullText = sourceCode.getText(program);
      return cryptoPatterns.some(pattern => 
        fullText.includes(pattern)
      );
    }

    if (isNonSecurityFile()) {
      return {};
    }

    return {
      CallExpression(node) {
        const callee = node.callee;
        
        // Check for Math.random() calls
        if (callee?.type === "MemberExpression" &&
            callee.object?.type === "Identifier" &&
            callee.object.name === "Math" &&
            callee.property?.type === "Identifier" &&
            callee.property.name === "random") {
          
          const context = analyzeSecurityContext(node);
          
          // Determine the most appropriate error message
          let messageId = "mathRandomInSecurity";
          
          if (context.securityNames.some(name => 
              /\b(id|uuid|guid)\b/i.test(name))) {
            messageId = "mathRandomForId";
          } else if (context.securityNames.some(name => 
              /\b(token|key|secret|password|salt)\b/i.test(name))) {
            messageId = "mathRandomForToken";
          } else if (!context.hasSecurityContext && isNearCryptoOperations(node)) {
            messageId = "mathRandomNearCrypto";
          }
          
          context.report({
            node,
            messageId,
          });
        }
      },

      // Also check for stored references to Math.random
      VariableDeclarator(node) {
        if (node.init?.type === "MemberExpression" &&
            node.init.object?.type === "Identifier" &&
            node.init.object.name === "Math" &&
            node.init.property?.type === "Identifier" &&
            node.init.property.name === "random") {
          
          context.report({
            node: node.init,
            messageId: "mathRandomInSecurity",
          });
        }
      }
    };
  },
};