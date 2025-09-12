/**
 * @fileoverview ESLint rule: no-date-entropy-security-context
 * Flags usage of Date.now(), new Date(), or similar time-based entropy sources
 * in security-critical contexts. Time-based entropy is predictable and can be
 * manipulated by attackers, violating OWASP ASVS V6.5.1 (Cryptographic Randomness).
 *
 * Security Constitution §1.1: Zero Trust & Verifiable Security
 * OWASP ASVS V6.5.1: Cryptographic Randomness
 */

import { collectAliases } from './_shared/analysis.js';

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Prevent using Date.now() or new Date() for entropy in security contexts",
      recommended: false,
    },
    schema: [
      {
        type: "object",
        properties: {
          additionalEntropyFunctions: {
            type: "array",
            items: { type: "string" },
            description: "Additional function names to flag as insecure entropy sources"
          },
          securityFunctionPatterns: {
            type: "array",
            items: { type: "string" },
            description: "Regex patterns for function names that should not use time-based entropy"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      avoidDateEntropy:
        "Using '{{method}}' for entropy violates OWASP ASVS V6.5.1. Time-based entropy is predictable and can be manipulated. Use getSecureRandomBytesSync() or generateSecureIdSync() instead.",
      avoidDateInSecurityContext:
        "Date/time usage in '{{context}}' may introduce timing attack vulnerabilities. Consider if this could leak timing information.",
      avoidMathRandom:
        "Math.random() is not cryptographically secure. Use getSecureRandomInt() or getSecureRandomFloat() instead."
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const _additionalEntropyFunctions = options.additionalEntropyFunctions || [];
    const securityFunctionPatterns = options.securityFunctionPatterns || [];

    // Default patterns for security-critical functions
    const defaultSecurityPatterns = [
      /generate.*(?:token|id|key|secret|nonce|salt)/i,
      /create.*(?:token|id|key|secret|nonce|salt)/i,
      /random/i,
      /entropy/i,
      /crypto/i,
      /secure/i,
      /hash/i,
      /sign/i,
      /encrypt/i,
      /decrypt/i
    ];

    const allSecurityPatterns = [
      ...defaultSecurityPatterns,
      ...securityFunctionPatterns.map(p => new RegExp(p, 'i'))
    ];

    // Skip tests and scripts
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\/|\/demo\/|\/benchmarks\//i.test(filename)) {
      return {};
    }

    // Track aliases for Date and Math
    let dateAliases = new Set();
    let mathAliases = new Set();

    /**
     * Check if a function name matches security-critical patterns
     */
    function isSecurityCriticalFunction(name) {
      return allSecurityPatterns.some(pattern => pattern.test(name));
    }

    /**
     * Check if we're in a security-critical context
     */
    function isInSecurityContext(node) {
      // Check function name
      let current = node;
      while (current) {
        if (current.type === "FunctionDeclaration" || current.type === "FunctionExpression") {
          if (current.id && isSecurityCriticalFunction(current.id.name)) {
            // Be more conservative - only flag if the function name strongly suggests security/crypto usage
            const name = current.id.name.toLowerCase();
            if (name.includes('token') || name.includes('key') || name.includes('secret') || 
                name.includes('crypto') || name.includes('secure') || name.includes('encrypt') ||
                name.includes('decrypt') || name.includes('sign') || name.includes('hash') ||
                name.includes('nonce') || name.includes('salt')) {
              return current.id.name;
            }
          }
        }
        if (current.type === "VariableDeclarator" && current.id?.type === "Identifier") {
          if (isSecurityCriticalFunction(current.id.name)) {
            const name = current.id.name.toLowerCase();
            if (name.includes('token') || name.includes('key') || name.includes('secret') || 
                name.includes('crypto') || name.includes('secure') || name.includes('encrypt') ||
                name.includes('decrypt') || name.includes('sign') || name.includes('hash') ||
                name.includes('nonce') || name.includes('salt')) {
              return current.id.name;
            }
          }
        }
        if (current.type === "AssignmentExpression" && current.left?.type === "Identifier") {
          if (isSecurityCriticalFunction(current.left.name)) {
            const name = current.left.name.toLowerCase();
            if (name.includes('token') || name.includes('key') || name.includes('secret') || 
                name.includes('crypto') || name.includes('secure') || name.includes('encrypt') ||
                name.includes('decrypt') || name.includes('sign') || name.includes('hash') ||
                name.includes('nonce') || name.includes('salt')) {
              return current.left.name;
            }
          }
        }
        current = current.parent;
      }
      return null;
    }

    /**
     * Check if identifier is an alias for Date or Math
     */
    function isDateAlias(identifier) {
      return dateAliases.has(identifier.name);
    }

    function isMathAlias(identifier) {
      return mathAliases.has(identifier.name);
    }

    return {
      // Collect aliases at the top level
      Program() {
        const aliases = collectAliases(context, ['Date', 'Math']);
        dateAliases = new Set(aliases.get('Date') || []);
        mathAliases = new Set(aliases.get('Math') || []);
      },

      // Flag Date.now(), Math.random(), and Date() calls
      CallExpression(node) {
        const callee = node.callee;

        // Direct Date.now()
        if (callee.type === "MemberExpression" &&
            callee.object.type === "Identifier" &&
            (callee.object.name === "Date" || isDateAlias(callee.object)) &&
            callee.property.type === "Identifier" &&
            callee.property.name === "now") {
          const contextName = isInSecurityContext(node);
          if (contextName) {
            context.report({
              node,
              messageId: "avoidDateEntropy",
              data: { method: "Date.now()" }
            });
          }
          // Don't report for non-security contexts
        }

        // Direct Math.random()
        if (callee.type === "MemberExpression" &&
            callee.object.type === "Identifier" &&
            (callee.object.name === "Math" || isMathAlias(callee.object)) &&
            callee.property.type === "Identifier" &&
            callee.property.name === "random") {
          const contextName = isInSecurityContext(node);
          if (contextName) {
            context.report({
              node,
              messageId: "avoidMathRandom"
            });
          }
          // Don't report for non-security contexts
        }

        // Direct Date() calls
        if (callee.type === "Identifier" &&
            (callee.name === "Date" || isDateAlias(callee))) {
          const contextName = isInSecurityContext(node);
          if (contextName) {
            context.report({
              node,
              messageId: "avoidDateEntropy",
              data: { method: "Date()" }
            });
          }
          // Don't report for non-security contexts
        }

        // Direct performance.now()
        if (callee.type === "MemberExpression" &&
            callee.object.type === "Identifier" &&
            callee.object.name === "performance" &&
            callee.property.type === "Identifier" &&
            callee.property.name === "now") {
          const contextName = isInSecurityContext(node);
          if (contextName) {
            context.report({
              node,
              messageId: "avoidDateInSecurityContext",
              data: { context: contextName }
            });
          }
        }
      },

      // Flag new Date() calls
      NewExpression(node) {
        if (node.callee.type === "Identifier" &&
            (node.callee.name === "Date" || isDateAlias(node.callee))) {
          const contextName = isInSecurityContext(node);
          if (contextName) {
            context.report({
              node,
              messageId: "avoidDateEntropy",
              data: { method: "new Date()" }
            });
          }
          // Don't report for non-security contexts
        }
      }
    };
  },
};