/**
 * @fileoverview ESLint rule: enforce-text-encoder-decoder
 * Enforces the use of shared TextEncoder/TextDecoder instances from 'src/encoding.ts'
 * to prevent unnecessary memory allocation and improve performance.
 * This aligns with OWASP ASVS L3 V10.2.1 (Resource Management) and our
 * Security Constitution's Pillar #2 (Hardened Simplicity & Performance).
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description:
        "Enforce the use of shared TextEncoder/TextDecoder instances from 'src/encoding.ts' to prevent unnecessary memory allocation.",
      category: "Performance",
      recommended: true,
      url: "https://github.com/david-osipov/security-kit/docs/Constitutions/Security%20Constitution.md",
    },
    schema: [],
    messages: {
      useSharedEncoder:
        "Do not create new TextEncoder instances. Import and use SHARED_ENCODER from 'src/encoding.ts' instead. " +
        "This prevents unnecessary memory allocation and improves performance per our Security Constitution.",
      useSharedDecoder:
        "Do not create new TextDecoder instances. Import and use SHARED_DECODER from 'src/encoding.ts' instead. " +
        "This prevents unnecessary memory allocation and improves performance per our Security Constitution.",
      suggestImport:
        "Add 'import { {{sharedInstance}} } from \"./encoding.ts\";' at the top of the file.",
    },
  // fixable removed: convert to error-only reporting to avoid unsafe automated edits
  },

  create(context) {
    const filename = context.getFilename() || "";
    
    // Skip this rule for encoding.ts itself and test files
    if (filename.includes("encoding.ts") || /\btests?\b/i.test(filename)) {
      return {};
    }

    let hasSharedEncoderImport = false;
    let hasSharedDecoderImport = false;
    let importDeclarations = [];

    /**
     * Check if SHARED_ENCODER or SHARED_DECODER is already imported
     */
    function checkForSharedImports(node) {
      if (
        node.type === "ImportDeclaration" &&
        node.source.value &&
        (node.source.value.includes("encoding.ts") || node.source.value.includes("encoding"))
      ) {
        importDeclarations.push(node);
        
        if (node.specifiers) {
          for (const spec of node.specifiers) {
            if (spec.type === "ImportSpecifier") {
              if (spec.imported.name === "SHARED_ENCODER") {
                hasSharedEncoderImport = true;
              }
              if (spec.imported.name === "SHARED_DECODER") {
                hasSharedDecoderImport = true;
              }
            }
          }
        }
      }
    }

    return {
      ImportDeclaration: checkForSharedImports,

      NewExpression(node) {
        if (node.callee.type === "Identifier") {
          if (node.callee.name === "TextEncoder") {
            context.report({
              node,
              messageId: "useSharedEncoder"
            });
          } else if (node.callee.name === "TextDecoder") {
            context.report({
              node,
              messageId: "useSharedDecoder"
            });
          }
        }
      },
    };
  },
};