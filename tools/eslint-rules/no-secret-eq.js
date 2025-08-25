/**
 * @fileoverview ESLint rule: no-secret-eq
 * Flags `a === b` comparisons where left side is an Identifier whose name
 * looks like a secret (token, secret, key, password, jwt, credential).
 * Suggests using secureCompareAsync(..., { requireCrypto: true }) for
 * security-critical comparisons.
 */

const SECRET_RE = /token|secret|key|password|jwt|credential|bearer/i;

export default {
  meta: {
    type: "suggestion",
    docs: {
      description:
        "Warn when comparing secret-like identifiers with ===; prefer secureCompareAsync",
      recommended: false,
    },
    schema: [],
    messages: {
      preferSecureCompare:
        "Comparison of a secret-like identifier detected. For security-critical comparisons prefer secureCompareAsync(a, b, { requireCrypto: true }) to fail loudly when platform crypto is unavailable",
    },
  },

  create(context) {
    // ignore tests and scripts by path
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\//i.test(filename)) {
      return {};
    }

    function isSecretIdentifier(n) {
      return n && n.type === "Identifier" && SECRET_RE.test(n.name);
    }

    return {
      BinaryExpression(node) {
        if (node.operator !== "===") return;

        const left = node.left;
        const right = node.right;

        // Narrow: only flag Identifier === Identifier comparisons where LHS is secret-like
        if (
          left &&
          left.type === "Identifier" &&
          right &&
          right.type === "Identifier"
        ) {
          if (isSecretIdentifier(left)) {
            context.report({ node, messageId: "preferSecureCompare" });
          }
        }
      },
    };
  },
};
