/**
 * @fileoverview ESLint rule: enforce-secure-signer-integrity
 * Enforces secure integrity settings for SecureApiSigner.create() in production.
 * Prevents supply chain attacks by requiring script integrity verification.
 * 
 * OWASP ASVS V14.2.4, V10.3.3: Supply chain security, script integrity
 * Security Constitution: Script integrity requirements
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Enforce secure integrity settings for SecureApiSigner in production",
      recommended: true,
    },
    schema: [
      {
        type: "object", 
        properties: {
          forbidIntegrityNone: {
            type: "boolean",
            description: "Whether to forbid integrity: 'none' (default: true)"
          },
          warnIntegrityCompute: {
            type: "boolean",
            description: "Whether to warn on integrity: 'compute' (default: true)"
          },
          requireHashForIntegrityRequire: {
            type: "boolean",
            description: "Whether to require expectedWorkerScriptHash when integrity: 'require' (default: true)"
          },
          testDirectoryPatterns: {
            type: "array",
            items: { type: "string" },
            description: "Directory patterns where requirements are relaxed"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      integrityNoneForbidden: "integrity: 'none' is forbidden in production. Use 'require' with expectedWorkerScriptHash for maximum security.",
      integrityComputeWarning: "integrity: 'compute' is not recommended for production due to TOCTOU risks. Consider 'require' with expectedWorkerScriptHash.",
      missingExpectedHash: "integrity: 'require' needs expectedWorkerScriptHash property to verify worker script integrity",
      suggestSecureConfig: "Use: { integrity: 'require', expectedWorkerScriptHash: 'sha256-...' }"
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const forbidIntegrityNone = options.forbidIntegrityNone !== false; // default true
    const warnIntegrityCompute = options.warnIntegrityCompute !== false; // default true  
    const requireHashForIntegrityRequire = options.requireHashForIntegrityRequire !== false; // default true
    const testDirectoryPatterns = options.testDirectoryPatterns || [
      "/tests/", "/test/", "/__tests__/", "/demo/", "/examples/", "/benchmarks/"
    ];

    const filename = context.getFilename() || "";
    const isTestFile = testDirectoryPatterns.some(pattern => filename.includes(pattern));

    // Relax requirements in test files
    if (isTestFile) {
      return {};
    }

    /**
     * Find integrity property in options object
     */
    function findIntegrityProperty(optionsNode) {
      if (optionsNode?.type !== "ObjectExpression") return null;
      
      return optionsNode.properties.find(prop =>
        prop.type === "Property" && 
        prop.key?.name === "integrity"
      );
    }

    /**
     * Check if expectedWorkerScriptHash property exists
     */
    function hasExpectedWorkerScriptHash(optionsNode) {
      if (optionsNode?.type !== "ObjectExpression") return false;
      
      return optionsNode.properties.some(prop =>
        prop.type === "Property" && 
        prop.key?.name === "expectedWorkerScriptHash"
      );
    }

    /**
     * Check if this is a SecureApiSigner.create call
     */
    function isSecureApiSignerCreate(node) {
      if (node.callee?.type === "MemberExpression") {
        return (
          node.callee.object?.name === "SecureApiSigner" &&
          node.callee.property?.name === "create"
        );
      }
      return false;
    }

    return {
      CallExpression(node) {
        if (!isSecureApiSignerCreate(node)) return;

        const optionsArg = node.arguments[0];
        if (!optionsArg || optionsArg.type !== "ObjectExpression") return;

        const integrityProp = findIntegrityProperty(optionsArg);
        if (!integrityProp || integrityProp.value?.type !== "Literal") return;

        const integrityValue = integrityProp.value.value;

        switch (integrityValue) {
          case "none":
            if (forbidIntegrityNone) {
              context.report({
                node: integrityProp,
                messageId: "integrityNoneForbidden"
              });
            }
            break;

          case "compute":
            if (warnIntegrityCompute) {
              context.report({
                node: integrityProp,
                messageId: "integrityComputeWarning"
              });
            }
            break;

          case "require":
            if (requireHashForIntegrityRequire && !hasExpectedWorkerScriptHash(optionsArg)) {
              context.report({
                node: integrityProp,
                messageId: "missingExpectedHash"
              });
            }
            break;
        }
      }
    };
  }
};