/**
 * @fileoverview ESLint rule: no-plaintext-secret-storage
 * Flags storage of sensitive data in plaintext variables, objects, or local storage
 * without proper encryption. Requires using secure storage mechanisms for secrets.
 *
 * OWASP ASVS V6.1.1: Data Classification
 * OWASP ASVS V6.5.4: Sensitive Information Storage
 * Security Constitution §1.1: Zero Trust & Verifiable Security
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Prevent storing sensitive data in plaintext without encryption",
      recommended: false,
    },
    schema: [
      {
        type: "object",
        properties: {
          secretPatterns: {
            type: "array",
            items: { type: "string" },
            description: "Additional regex patterns for secret-like variable names"
          },
          additionalSecretNames: {
            type: "array",
            items: { type: "string" },
            description: "Additional secret variable names to check"
          },
          allowedStorageFunctions: {
            type: "array",
            items: { type: "string" },
            description: "Function names that are allowed to handle plaintext secrets"
          },
          encryptedStoragePatterns: {
            type: "array",
            items: { type: "string" },
            description: "Patterns for encrypted storage function names"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      plaintextSecretStorage:
        "Storing secret '{{secretName}}' in plaintext violates OWASP ASVS V6.5.4. Use encrypted storage or secure key management.",
      insecureLocalStorage:
        "Storing sensitive data in localStorage/sessionStorage is insecure. Use secure encrypted storage instead.",
      insecureObjectStorage:
        "Storing secret in object property '{{property}}' without encryption. Consider using sealed objects or encrypted storage.",
      suggestSecureStorage:
        "Use secureEncryptedStorage.setItem() or similar encrypted storage mechanism instead of plaintext storage."
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const customPatterns = options.secretPatterns || [];
    const additionalSecretNames = options.additionalSecretNames || [];
    const allowedStorageFunctions = new Set([
      'secureEncryptedStorage', 'encryptedStorage', 'secureStorage',
      'encryptAndStore', 'storeEncrypted',
      ...(options.allowedStorageFunctions || [])
    ]);
    const encryptedStoragePatterns = [
      /encrypt/i,
      /secure/i,
      /crypto/i,
      /cipher/i,
      ...(options.encryptedStoragePatterns || []).map(p => new RegExp(p, 'i'))
    ];

    // Combine default and custom secret patterns
    const allSecretPatterns = [
      /token|secret|key|password|jwt|credential|bearer|hash|signature|mac|nonce|iv|salt|private|auth/i,
      ...customPatterns.map(p => new RegExp(p, 'i'))
    ];

    const allSecretNames = new Set([
      'token', 'secret', 'key', 'password', 'jwt', 'credential', 'bearer', 'hash', 'signature', 'mac', 'nonce', 'iv', 'salt', 'privateKey', 'authToken',
      ...additionalSecretNames
    ]);

    // Skip tests and scripts
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\/|\/demo\/|\/benchmarks\//i.test(filename)) {
      return {};
    }

    /**
     * Check if identifier name suggests sensitive data
     */
    function isSecretIdentifier(node) {
      if (!node || node.type !== "Identifier") return false;

      const name = node.name;
      return allSecretNames.has(name.toLowerCase()) ||
             allSecretPatterns.some(pattern => pattern.test(name));
    }

    /**
     * Check if a storage call is using encrypted storage
     */
    function isEncryptedStorage(callee) {
      if (callee.type === "Identifier") {
        return allowedStorageFunctions.has(callee.name) ||
               encryptedStoragePatterns.some(pattern => pattern.test(callee.name));
      }

      if (callee.type === "MemberExpression") {
        const fullName = callee.object.name + '.' + callee.property.name;
        return allowedStorageFunctions.has(fullName) ||
               encryptedStoragePatterns.some(pattern => pattern.test(fullName));
      }

      return false;
    }

    return {
      // Check variable declarations
      VariableDeclarator(node) {
        if (node.id.type === "Identifier" && isSecretIdentifier(node.id)) {
          // Check if the init value is a sensitive literal or call
          if (node.init) {
            if (node.init.type === "Literal" && typeof node.init.value === "string") {
              context.report({
                node,
                messageId: "plaintextSecretStorage",
                data: { secretName: node.id.name }
              });
            }
          }
        }
      },

      // Check assignments
      AssignmentExpression(node) {
        // Direct assignment to secret variable
        if (node.left.type === "Identifier" && isSecretIdentifier(node.left)) {
          if (node.right.type === "Literal" && typeof node.right.value === "string") {
            context.report({
              node,
              messageId: "plaintextSecretStorage",
              data: { secretName: node.left.name }
            });
          }
        }

        // Property assignment
        if (node.left.type === "MemberExpression" &&
            node.left.property.type === "Identifier" &&
            isSecretIdentifier(node.left.property)) {
          context.report({
            node,
            messageId: "insecureObjectStorage",
            data: { property: node.left.property.name }
          });
        }
      },

      // Check localStorage/sessionStorage usage
      CallExpression(node) {
        const callee = node.callee;

        // Check localStorage.setItem() or sessionStorage.setItem()
        if (callee.type === "MemberExpression" &&
            callee.object.type === "Identifier" &&
            ["localStorage", "sessionStorage"].includes(callee.object.name) &&
            callee.property.type === "Identifier" &&
            callee.property.name === "setItem") {

          const args = node.arguments;
          if (args.length >= 2) {
            // Check if the key or value suggests sensitive data
            const keyArg = args[0];
            const valueArg = args[1];

            if ((keyArg.type === "Literal" && typeof keyArg.value === "string" &&
                 allSecretPatterns.some(pattern => pattern.test(keyArg.value))) ||
                (valueArg.type === "Literal" && typeof valueArg.value === "string" &&
                 allSecretPatterns.some(pattern => pattern.test(valueArg.value)))) {

              context.report({
                node,
                messageId: "insecureLocalStorage"
              });
            }
          }
        }

        // Check for insecure storage function calls
        if (!isEncryptedStorage(callee)) {
          const args = node.arguments;
          for (const arg of args) {
            if (arg.type === "Identifier" && isSecretIdentifier(arg)) {
              context.report({
                node,
                messageId: "plaintextSecretStorage",
                data: { secretName: arg.name }
              });
            }
          }
        }
      },

      // Check object property assignments
      Property(node) {
        if (node.key.type === "Identifier" && isSecretIdentifier(node.key)) {
          if (node.value.type === "Literal" && typeof node.value.value === "string") {
            context.report({
              node,
              messageId: "insecureObjectStorage",
              data: { property: node.key.name }
            });
          }
        }
      }
    };
  },
};