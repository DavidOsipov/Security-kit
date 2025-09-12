/**
 * @fileoverview ESLint rule: no-direct-subtle-crypto
 * Disallows direct use of crypto.subtle, enforcing the use of high-level abstractions
 * from the security-kit. This prevents bypassing validation, hardening, and consistent
 * error handling that our wrappers provide.
 * This aligns with OWASP ASVS L3 V1.1.2 (Security Frameworks and Libraries) and our
 * Security Constitution's Pillar #3 (Ergonomic & Pitfall-Free API Design).
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description:
        "Disallow direct use of 'crypto.subtle'. Use the high-level abstractions from the security-kit instead.",
      category: "Security",
      recommended: true,
      url: "https://github.com/david-osipov/security-kit/docs/Constitutions/Security%20Constitution.md",
    },
    schema: [
      {
        type: "object",
        properties: {
          allowInFiles: {
            type: "array",
            items: { type: "string" },
            description: "Array of file patterns where direct crypto.subtle usage is allowed"
          },
          allowedMethods: {
            type: "array",
            items: { type: "string" },
            description: "Array of crypto.subtle methods that are allowed (for gradual migration)"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      noSubtle:
        "Direct use of 'crypto.subtle.{{method}}' is forbidden. Use a high-level abstraction from the security-kit instead " +
        "(e.g., 'sha256Base64' for digest, 'createAesGcmKey256' for key generation) to ensure proper validation and error handling.",
      noSubtleGeneric:
        "Direct access to 'crypto.subtle' is forbidden. Use high-level abstractions from the security-kit to ensure " +
        "proper validation, hardening, and consistent error handling per our Security Constitution.",
      suggestAlternative:
        "Consider using these security-kit alternatives: {{alternatives}}",
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const allowInFiles = options.allowInFiles || [];
    const allowedMethods = new Set(options.allowedMethods || []);
    
    const filename = context.getFilename() || "";
    
    // Check if this file is explicitly allowed
    const isFileAllowed = allowInFiles.some(pattern => {
      if (typeof pattern === "string") {
        return filename.includes(pattern);
      }
      return false;
    });
    
    if (isFileAllowed) {
      return {};
    }
    
    // Skip for encoding-utils.ts and other internal crypto modules that may legitimately use crypto.subtle
    if (filename.includes("encoding-utils.ts") || filename.includes("capabilities.ts")) {
      return {};
    }

    /**
     * Get suggested alternatives for common crypto.subtle methods
     */
    function getSuggestedAlternatives(method) {
      const alternatives = {
        digest: "sha256Base64() from encoding-utils.ts",
        generateKey: "createAesGcmKey256(), createHmacKey() from crypto.ts",
        sign: "createSecureSignature() from postMessage.ts",
        verify: "verifySecureSignature() from postMessage.ts",
        encrypt: "secure encryption utilities from crypto.ts",
        decrypt: "secure decryption utilities from crypto.ts",
        deriveBits: "secure key derivation utilities from crypto.ts",
        deriveKey: "secure key derivation utilities from crypto.ts",
        importKey: "key import utilities from crypto.ts",
        exportKey: "key export utilities from crypto.ts",
        wrapKey: "secure key wrapping utilities from crypto.ts",
        unwrapKey: "secure key unwrapping utilities from crypto.ts"
      };
      
      return alternatives[method] || "appropriate security-kit abstraction";
    }

    return {
      MemberExpression(node) {
        // Check for crypto.subtle access
        if (
          node.object.type === "Identifier" &&
          node.object.name === "crypto" &&
          node.property.type === "Identifier" &&
          node.property.name === "subtle"
        ) {
          // Check if this is a method call (crypto.subtle.methodName)
          if (node.parent && node.parent.type === "MemberExpression" && node.parent.object === node) {
            const method = node.parent.property.name;
            
            // Skip if method is explicitly allowed
            if (allowedMethods.has(method)) {
              return;
            }
            
            const alternatives = getSuggestedAlternatives(method);
            
            context.report({
              node: node.parent,
              messageId: "noSubtle",
              data: { 
                method,
                alternatives 
              },
            });
          } else {
            // Generic crypto.subtle access without method call
            context.report({
              node,
              messageId: "noSubtleGeneric",
            });
          }
        }
      },
      
      // Also catch cases where crypto.subtle is destructured
      VariableDeclarator(node) {
        if (
          node.init &&
          node.init.type === "MemberExpression" &&
          node.init.object.type === "Identifier" &&
          node.init.object.name === "crypto" &&
          node.init.property.type === "Identifier" &&
          node.init.property.name === "subtle"
        ) {
          context.report({
            node,
            messageId: "noSubtleGeneric",
          });
        }
        
        // Check for destructuring: const { subtle } = crypto
        if (
          node.id &&
          node.id.type === "ObjectPattern" &&
          node.init &&
          node.init.type === "Identifier" &&
          node.init.name === "crypto"
        ) {
          const subtleProperty = node.id.properties.find(
            prop => prop.type === "Property" &&
                   prop.key.type === "Identifier" &&
                   prop.key.name === "subtle"
          );
          
          if (subtleProperty) {
            context.report({
              node: subtleProperty,
              messageId: "noSubtleGeneric",
            });
          }
        }
      },
    };
  },
};