/**
 * @fileoverview ESLint rule: enforce-secure-logging
 * Enforces use of secureDevLog/reportProdError over direct console methods.
 * Prevents accidental leakage of sensitive data (tokens, PII) in logs by
 * requiring sanitized logging functions that implement redaction and rate-limiting.
 * 
 * OWASP ASVS V7.1.1, V7.1.3: Log content sanitization and secure logging practices
 * Security Constitution §1.4 "Fail Loudly, Fail Safely" + §2.12 "Privacy-Preserving Telemetry"
 */

import { collectAliases, isLoggingCall } from './_shared/analysis.js';

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Enforce use of secureDevLog() or reportProdError() instead of direct console methods",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          allowInFiles: {
            type: "array",
            items: { type: "string" },
            description: "File patterns where direct console usage is permitted"
          },
          allowedMethods: {
            type: "array", 
            items: { type: "string" },
            description: "Console methods that are explicitly allowed"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      useSecureLogging: "Use secureDevLog() or reportProdError() instead of direct console.{{method}}(). Direct console methods bypass redaction and rate-limiting, risking sensitive data leakage.",
    },
  // fixable removed to prevent unsafe automated edits; rule is error-only
  },

  // fixable removed to prevent unsafe automated edits; rule is error-only

  create(context) {
    const options = context.options[0] || {};
    const allowInFiles = options.allowInFiles || [
      "utils.ts", 
      "dev-logger.ts", 
      "reporting.ts",
      "/tests/",
      "/test/",
      "/demo/",
      "/benchmarks/",
      "/scripts/"
    ];
    const allowedMethods = new Set(options.allowedMethods || ["log", "warn", "error", "info", "debug"]);
    
    const filename = context.getFilename() || "";
    
    // Skip rule if file is in allowed patterns
    if (allowInFiles.some(pattern => filename.includes(pattern))) {
      return {};
    }

    const aliases = collectAliases(context, ['console']);

    /**
     * Check if a logging call contains sensitive data
     */
    function containsSensitiveData(node) {
      if (!node.arguments || node.arguments.length === 0) return false;
      
      // Simple sensitive patterns
      const sensitivePatterns = /token|secret|key|password|jwt|credential|bearer|hash|signature|mac|nonce|iv|salt/i;
      const safeProperties = ['length', 'size', 'count', 'id', 'name', 'type', 'tostring', 'valueof'];
      
      function isSensitive(node) {
        if (!node) return false;
        
        // Direct identifier that matches sensitive pattern
        if (node.type === 'Identifier' && sensitivePatterns.test(node.name)) {
          return true;
        }
        
        // String literal containing sensitive content
        if (node.type === 'Literal' && typeof node.value === 'string' && sensitivePatterns.test(node.value)) {
          // Don't flag strings that look like messages (contain message indicators)
          if (node.value.includes(':') || node.value.includes('length') || node.value.includes('count') || node.value.includes('size') || node.value.includes(' ')) {
            return false;
          }
          return true;
        }
        
        // Member expression - check if it's safe property access
        if (node.type === 'MemberExpression') {
          // If the property is safe, don't flag it
          if (node.property && node.property.type === 'Identifier') {
            const propName = node.property.name.toLowerCase();
            if (safeProperties.includes(propName)) {
              return false; // Safe property access
            }
          }
          // If the object is sensitive and property is not safe, it's sensitive
          if (node.object && node.object.type === 'Identifier' && sensitivePatterns.test(node.object.name)) {
            return true;
          }
          return false; // Unknown member expression
        }
        
        // Template literal
        if (node.type === 'TemplateLiteral') {
          return node.expressions.some(expr => isSensitive(expr)) ||
                 node.quasis.some(quasi => quasi.value.raw && sensitivePatterns.test(quasi.value.raw));
        }
        
        // Object expression
        if (node.type === 'ObjectExpression') {
          return node.properties.some(prop => {
            if (prop.type === 'Property') {
              return isSensitive(prop.key) || isSensitive(prop.value);
            }
            return false;
          });
        }
        
        // Array expression
        if (node.type === 'ArrayExpression') {
          return node.elements.some(element => element && isSensitive(element));
        }
        
        // Binary expression
        if (node.type === 'BinaryExpression') {
          return isSensitive(node.left) || isSensitive(node.right);
        }
        
        // Call expression
        if (node.type === 'CallExpression') {
          if (node.callee && node.callee.type === 'Identifier' && sensitivePatterns.test(node.callee.name)) {
            return true;
          }
          return node.arguments.some(arg => isSensitive(arg));
        }
        
        return false;
      }
      
      // Check each argument
      for (const arg of node.arguments) {
        if (isSensitive(arg)) {
          return true;
        }
      }
      
      return false;
    }

    return {
      CallExpression(node) {
        if (isLoggingCall(node, context, [], aliases)) {
          const method = node.callee.property?.name || node.callee.name;
          
          // Allow if method is in allowedMethods and doesn't contain sensitive data
          if (allowedMethods.has(method) && !containsSensitiveData(node)) {
            return;
          }
          
          context.report({
            node,
            messageId: "useSecureLogging",
            data: { method }
          });
        }
      }
    };
  }
};
