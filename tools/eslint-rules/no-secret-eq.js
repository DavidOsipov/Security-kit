/**
 * @fileoverview ESLint rule: no-secret-eq
 * Flags `a === b` comparisons where operands are Identifiers whose names
 * look like secrets (configurable list). Enhanced to detect more security-sensitive patterns
 * and timing attack vulnerabilities. Suggests using secureCompareAsync for security-critical comparisons.
 *
 * OWASP ASVS V6.5.3: Timing attack prevention
 * Security Constitution §1.4: Fail Loudly, Fail Safely
 */

export default {
  meta: {
    type: "suggestion",
    docs: {
      description: "Warn when comparing secret-like identifiers with ===; prefer secureCompareAsync",
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
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      preferSecureCompare:
        "Comparison of secret-like identifier '{{identifier}}' detected. For security-critical comparisons prefer secureCompareAsync(a, b, { requireCrypto: true }) to prevent timing attacks and fail loudly when platform crypto is unavailable",
      preferSecureCompareBytes:
        "For byte array comparisons, use secureCompareBytes(a, b) or secureCompareBytesOrThrow(a, b)"
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const customPatterns = options.secretPatterns || [];
    const additionalSecretNames = options.additionalSecretNames || [];

    // Combine default and custom secret patterns
    const allSecretPatterns = [
      /token|secret|key|password|jwt|credential|bearer|hash|signature|mac|nonce|iv|salt/i,
      ...customPatterns.map(p => {
        // If it's already a regex, use it; otherwise create a simple regex
        if (p instanceof RegExp) return p;
        // For string patterns, create a case-insensitive regex
        return new RegExp(p, 'i');
      })
    ];

    const allSecretNames = new Set([
      'token', 'secret', 'key', 'password', 'jwt', 'credential', 'bearer', 'hash', 'signature', 'mac', 'nonce', 'iv', 'salt',
      ...additionalSecretNames
    ]);

    // Skip tests and scripts
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\/|\/demo\/|\/benchmarks\//i.test(filename)) {
      return {};
    }

    /**
     * Check if identifier name suggests sensitive data using combined patterns
     */
    function isSecretIdentifier(node) {
      if (!node || node.type !== "Identifier") return false;

      const name = node.name;
      
      // Exclude obvious non-sensitive patterns to reduce false positives
      const nonSensitivePatterns = [
        /result|output|response|data|value|item|element|property/i,
        /index|count|length|size|status|type|kind|id/i,
        /config|option|setting|param|arg|flag/i
      ];
      
      if (nonSensitivePatterns.some(pattern => pattern.test(name))) {
        return false;
      }
      
      return allSecretNames.has(name.toLowerCase()) ||
             allSecretPatterns.some(pattern => pattern.test(name));
    }

    /**
     * Check if a literal value looks like sensitive data
     */
    function isSecretLiteral(node) {
      if (!node || node.type !== "Literal") return false;
      if (typeof node.value !== "string") return false;

      const value = node.value;
      return allSecretNames.has(value.toLowerCase()) ||
             allSecretPatterns.some(pattern => pattern.test(value));
    }

    /**
     * Check if comparison involves typed arrays
     */
    function isTypedArrayComparison(left, right) {
      // Simple heuristic: if variable names suggest typed arrays
      const typedArrayPattern = /buffer|array|bytes|uint8|view/i;
      return (left?.type === "Identifier" && typedArrayPattern.test(left.name)) ||
             (right?.type === "Identifier" && typedArrayPattern.test(right.name));
    }

    return {
      BinaryExpression(node) {
        if (!["===", "!==", "==", "!="].includes(node.operator)) return;

        const left = node.left;
        const right = node.right;

        // Check Identifier === Identifier comparisons where either side is secret-like
        if (left?.type === "Identifier" && right?.type === "Identifier") {
          const leftIsSecret = isSecretIdentifier(left);
          const rightIsSecret = isSecretIdentifier(right);

          if (leftIsSecret || rightIsSecret) {
            const secretName = leftIsSecret ? left.name : right.name;
            const messageId = isTypedArrayComparison(left, right)
              ? "preferSecureCompareBytes"
              : "preferSecureCompare";

            context.report({
              node,
              messageId,
              data: { identifier: secretName }
            });
          }
        }

        // Check Identifier === Literal comparisons (e.g., token === 'hardcoded')
        if (left?.type === "Identifier" && right?.type === "Literal") {
          if (isSecretIdentifier(left) && isSecretLiteral(right)) {
            context.report({
              node,
              messageId: "preferSecureCompare",
              data: { identifier: left.name }
            });
          }
        }

        // Check Literal === Identifier comparisons (e.g., 'hardcoded' === token)
        if (left?.type === "Literal" && right?.type === "Identifier") {
          if (isSecretLiteral(left) && isSecretIdentifier(right)) {
            context.report({
              node,
              messageId: "preferSecureCompare",
              data: { identifier: right.name }
            });
          }
        }

        // Check MemberExpression comparisons (e.g., user.token === expectedToken)
        if (left?.type === "MemberExpression" && right?.type === "Identifier") {
          if (left.property?.type === "Identifier" && isSecretIdentifier(left.property)) {
            context.report({
              node,
              messageId: "preferSecureCompare",
              data: { identifier: left.property.name }
            });
          }
        }

        if (right?.type === "MemberExpression" && left?.type === "Identifier") {
          if (right.property?.type === "Identifier" && isSecretIdentifier(right.property)) {
            context.report({
              node,
              messageId: "preferSecureCompare",
              data: { identifier: right.property.name }
            });
          }
        }
      },
    };
  },
};
