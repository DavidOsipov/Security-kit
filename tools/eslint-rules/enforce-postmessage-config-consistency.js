/**
 * @fileoverview ESLint rule: enforce-postmessage-config-consistency  
 * Ensures postMessage configuration consistency, specifically preventing
 * incompatible sanitize=true + allowTypedArrays=true combinations.
 * 
 * OWASP ASVS V5.1.3: Input validation consistency
 * Security Constitution: postMessage configuration integrity
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Ensure postMessage configuration consistency - prevent incompatible option combinations",
      recommended: true,
    },
    schema: [],
    messages: {
      incompatibleSanitizeTypedArrays: "Incompatible postMessage options: sanitize=true (default) cannot be used with allowTypedArrays=true. Set sanitize=false when allowing typed arrays.",
      suggestFixSanitization: "Change to: sanitize: false, allowTypedArrays: true"
    },
  // fixable removed: convert to error-only reporting to avoid unsafe automated edits
  },

  create(context) {
    // Skip tests
    const filename = context.getFilename() || "";
    if (/\b(tests?|demo|benchmarks)\b/i.test(filename)) {
      return {};
    }

    /**
     * Extract boolean value from property node
     */
    function getBooleanValue(propNode, defaultValue = true) {
      if (!propNode) return defaultValue;
      if (propNode.value?.type === "Literal") {
        return Boolean(propNode.value.value);
      }
      return defaultValue;
    }

    /**
     * Extract string value from property node
     */
    function getStringValue(propNode, defaultValue = null) {
      if (!propNode) return defaultValue;
      if (propNode.value?.type === "Literal" && typeof propNode.value.value === "string") {
        return propNode.value.value;
      }
      return defaultValue;
    }

    /**
     * Check sendSecurePostMessage calls
     */
    function checkSendSecurePostMessage(node) {
      const optionsArg = node.arguments[0];
      if (!optionsArg || optionsArg.type !== "ObjectExpression") return;

      const props = optionsArg.properties;
      const wireFormatProp = props.find(p => p.key?.name === "wireFormat");
      const sanitizeProp = props.find(p => p.key?.name === "sanitize");  
      const allowTypedArraysProp = props.find(p => p.key?.name === "allowTypedArrays");

      const wireFormat = getStringValue(wireFormatProp, "json");
      const sanitize = getBooleanValue(sanitizeProp, true); // default true
      const allowTypedArrays = getBooleanValue(allowTypedArraysProp, false);

      // Check for incompatible combination
      if ((wireFormat === "structured" || wireFormat === "auto") && 
          sanitize && allowTypedArrays) {
        
        const targetNode = allowTypedArraysProp || sanitizeProp || optionsArg;
        
        context.report({
          node: targetNode,
          messageId: "incompatibleSanitizeTypedArrays"
        });
      }
    }

    return {
      CallExpression(node) {
        if (node.callee?.name === "sendSecurePostMessage") {
          checkSendSecurePostMessage(node);
        }
      }
    };
  }
};