/**
 * @fileoverview ESLint rule: no-insecure-nonce-store
 * Prevents usage of InMemoryNonceStore in production code. InMemoryNonceStore
 * is designed for testing only and provides no protection against replay attacks
 * in distributed production environments.
 * 
 * OWASP ASVS V14.2.4: Replay attack prevention
 * Security Constitution: Production-ready security controls
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Prevent usage of InMemoryNonceStore in production code - use distributed nonce storage instead",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          testDirectoryPatterns: {
            type: "array",
            items: { type: "string" },
            description: "Directory patterns where InMemoryNonceStore is allowed"
          },
          allowedProductionStores: {
            type: "array", 
            items: { type: "string" },
            description: "Production-safe nonce store class names"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      insecureNonceStore: "InMemoryNonceStore is not safe for production - provides no protection against replay attacks in distributed environments",
      suggestProductionStore: "Use a distributed nonce store: {{suggestions}}",
      suggestRedisStore: "Example: new RedisNonceStore(redisClient) or new DatabaseNonceStore(dbConnection)"
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const testDirectoryPatterns = options.testDirectoryPatterns || [
      "/tests/", "/test/", "/__tests__/", "/demo/", "/examples/", "/benchmarks/"
    ];
    const allowedProductionStores = options.allowedProductionStores || [
      "RedisNonceStore",
      "DatabaseNonceStore", 
      "DistributedNonceStore",
      "PersistentNonceStore"
    ];

    const filename = context.getFilename() || "";
    const isTestFile = testDirectoryPatterns.some(pattern => filename.includes(pattern));

    // Allow in test files
    if (isTestFile) {
      return {};
    }

    return {
      NewExpression(node) {
        if (node.callee?.name === "InMemoryNonceStore") {
          context.report({
            node,
            messageId: "insecureNonceStore",
            data: {
              suggestions: allowedProductionStores.join(", ")
            }
          });
        }
      },

      // Also check for variable assignments that might use InMemoryNonceStore
      VariableDeclarator(node) {
        if (node.init?.type === "NewExpression" && 
            node.init.callee?.name === "InMemoryNonceStore") {
          context.report({
            node: node.init,
            messageId: "insecureNonceStore",
            data: {
              suggestions: allowedProductionStores.join(", ")
            }
          });
        }
      }
    };
  }
};