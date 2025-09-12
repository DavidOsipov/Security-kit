/**
 * @fileoverview ESLint rule: no-direct-url-constructor
 * Prevents direct usage of new URL() constructor, requiring use of hardened
 * URL utilities that provide security validation, credential stripping, and
 * other protections against malicious URLs.
 * 
 * OWASP ASVS V5.1.3, V5.1.4: Input validation for URLs
 * Security Constitution: Hardened URL parsing requirements
 */

export default {
  meta: {
    type: "suggestion",
    docs: {
      description: "Prevent direct URL constructor usage, require hardened URL utilities",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          allowInFiles: {
            type: "array", 
            items: { type: "string" },
            description: "File patterns where direct URL constructor is allowed"
          },
          suggestedAlternatives: {
            type: "array",
            items: { type: "string" },
            description: "Recommended hardened URL functions to suggest"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      useHardenedUrl: "Use hardened URL utilities ({{alternatives}}) instead of direct 'new URL()'. Direct URL constructor bypasses security validation, credential stripping, and other protections.",
      suggestValidateUrl: "For validation: validateURL(url, { allowedOrigins: [...] })",
      suggestCreateSecureUrl: "For construction: createSecureURL(base, path, options)"
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const allowInFiles = options.allowInFiles || [
      "url.ts",
      "/src/url.ts",
      "/tests/", 
      "/test/",
      "/demo/",
      "/benchmarks/"
    ];
    const suggestedAlternatives = options.suggestedAlternatives || [
      "validateURL",
      "createSecureURL", 
      "normalizeOrigin",
      "parseSecureURL"
    ];

    const filename = context.getFilename() || "";
    
    // Skip if in allowed files
    if (allowInFiles.some(pattern => filename.includes(pattern))) {
      return {};
    }

    return {
      NewExpression(node) {
        if (node.callee?.name === "URL") {
          context.report({
            node,
            messageId: "useHardenedUrl",
            data: { 
              alternatives: suggestedAlternatives.join(", ")
            }
          });
        }
      }
    };
  }
};