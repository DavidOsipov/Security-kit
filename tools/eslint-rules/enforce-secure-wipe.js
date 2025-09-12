/**
 * @fileoverview ESLint rule: enforce-secure-wipe
 * Enforces that functions handling sensitive data in Uint8Array buffers
 * must call secureWipe() or secureWipeOrThrow() in a finally block.
 * This prevents secrets from lingering in memory, aligning with OWASP ASVS L3
 * and the Security Constitution's memory hygiene requirements.
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description:
        "Require secureWipe() calls in finally blocks for Uint8Array handling sensitive data",
      recommended: true,
    },
    schema: [],
    messages: {
      missingSecureWipe:
        "Uint8Array containing sensitive data must be securely wiped in a finally block. " +
        "Use secureWipe({{bufferName}}) or secureWipeOrThrow({{bufferName}}) to prevent memory leaks.",
      wipeNotInFinally:
        "secureWipe() call for {{bufferName}} should be in a finally block to ensure cleanup even if errors occur.",
      suggestTryFinally:
        "Consider wrapping this code in try...finally and call secureWipe({{bufferName}}) in the finally block.",
    },
    // fixable removed: convert to error-only reporting to avoid unsafe automated edits
  },

  create(context) {
    // Skip tests and scripts
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\//i.test(filename)) {
      return {};
    }

    function isSensitiveBufferName(name) {
      const sensitivePatterns = [
        /key/i,
        /secret/i,
        /token/i,
        /password/i,
        /salt/i,
        /nonce/i,
        /iv/i,
        /pad/i,
        /random/i,
        /entropy/i,
        /seed/i,
        /hash/i,
        /signature/i,
        /credential/i,
      ];
      return sensitivePatterns.some((pattern) => pattern.test(name));
    }

    function isUint8ArrayFromCrypto(node) {
      if (!node || !node.init) return false;

      // Explicitly exclude non-Uint8Array initializations
      if (node.init.type === "NewExpression") {
        const constructorName = node.init.callee?.name;
        
        // Only allow Uint8Array, ArrayBuffer, and related buffer types
        if (constructorName === "Uint8Array" || constructorName === "ArrayBuffer" || 
            constructorName === "Int8Array" || constructorName === "Uint16Array" ||
            constructorName === "Int16Array" || constructorName === "Uint32Array" ||
            constructorName === "Int32Array" || constructorName === "Float32Array" ||
            constructorName === "Float64Array") {
          return true; // These are buffer types that might contain sensitive data
        }
        
        // Exclude other constructor types (Set, Map, Array, Object, etc.)
        return false;
      }

      // Check for object literals, arrays, and other non-buffer types
      if (["ObjectExpression", "ArrayExpression", "Literal"].includes(node.init.type)) {
        return false;
      }

      // Check for: await secureRandomBytes(...) or other crypto calls that return buffers
      if (node.init.type === "AwaitExpression" && node.init.argument) {
        const call = node.init.argument;
        if (call.type === "CallExpression" && call.callee) {
          const funcName = call.callee.name || call.callee.property?.name;
          const cryptoFunctions = [
            "secureRandomBytes",
            "getRandomValues", 
            "generateKey",
            "deriveBits",
            "deriveKey", 
            "digest",
            "sign",
            "getSecureRandomBytesSync",
            "generateSecureBytesAsync",
          ];
          return cryptoFunctions.includes(funcName);
        }
      }

      // Check for: secureRandomBytes(...) without await
      if (node.init.type === "CallExpression" && node.init.callee) {
        const funcName = node.init.callee.name || node.init.callee.property?.name;
        const cryptoFunctions = [
          "secureRandomBytes",
          "getRandomValues", 
          "generateSecureStringSync",
          "createSecureZeroingArray",
          "getSecureRandomBytesSync",
          "generateSecureBytesAsync",
          "createSecureZeroingBuffer",
        ];
        return cryptoFunctions.includes(funcName);
      }

      return false;
    }

    function findSecureWipeCall(startNode, bufferName) {
      let wipeCall = null;
      let isInFinally = false;

      function traverse(node, inFinallyBlock = false) {
        if (!node || typeof node !== "object") return;

        if (node.type === "TryStatement" && node.finalizer) {
          traverse(node.finalizer, true);
        }

        if (
          node.type === "CallExpression" &&
          node.callee &&
          (node.callee.name === "secureWipe" || node.callee.name === "secureWipeOrThrow")
        ) {
          const arg = node.arguments?.[0];
          if (arg && arg.type === "Identifier" && arg.name === bufferName) {
            wipeCall = node;
            isInFinally = inFinallyBlock;
          }
        }

        for (const key in node) {
          if (key === "type" || key === "parent") continue;
          const child = node[key];
          if (Array.isArray(child)) {
            child.forEach((item) => traverse(item, inFinallyBlock));
          } else if (child && typeof child === "object") {
            traverse(child, inFinallyBlock);
          }
        }
      }

      if (!startNode) return { wipeCall: null, isInFinally: false };
      const start = startNode.body ? startNode.body : startNode;
      traverse(start);
      return { wipeCall, isInFinally };
    }

    const sensitiveBuffers = new Map();

    return {
      VariableDeclarator(node) {
        if (node.id?.type === "Identifier") {
          // Only flag variables that are both:
          // 1. Have sensitive names AND
          // 2. Are actually initialized with Uint8Array/crypto operations
          const hasSensitiveName = isSensitiveBufferName(node.id.name);
          const isActuallyUint8Array = isUint8ArrayFromCrypto(node);
          
          if (hasSensitiveName && isActuallyUint8Array) {
            let container = node;
            const containerTypes = new Set([
              "FunctionDeclaration",
              "FunctionExpression",
              "ArrowFunctionExpression",
              "Program",
              "TryStatement",
              "BlockStatement",
            ]);
            while (container && !containerTypes.has(container.type)) {
              container = container.parent;
            }

            if (container) {
              sensitiveBuffers.set(node.id.name, {
                declarationNode: node,
                containerNode: container,
                bufferName: node.id.name,
              });
            }
          }
        }
      },

      "Program:exit"() {
        for (const [bufferName, info] of sensitiveBuffers) {
          const searchNode = info.containerNode && (info.containerNode.body || info.containerNode);
          const { wipeCall, isInFinally } = findSecureWipeCall(searchNode, bufferName);

          if (!wipeCall) {
            context.report({
              node: info.declarationNode,
              messageId: "missingSecureWipe",
              data: { bufferName },
            });
          } else if (!isInFinally) {
            context.report({
              node: wipeCall,
              messageId: "wipeNotInFinally",
              data: { bufferName },
            });
          }
        }
      },
    };
  },
};