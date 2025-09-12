/**
 * @fileoverview ESLint rule: enforce-json-size-guard
 * Flags JSON.parse() and JSON.stringify() calls without size guards to prevent
 * denial-of-service attacks from oversized payloads. Requires explicit size limits
 * or validation before parsing/stringifying.
 */

export default {
  meta: {
    type: 'problem',
    docs: {
      description: 'Require size guards for JSON.parse() and JSON.stringify() to prevent DoS attacks',
      recommended: false,
    },
    schema: [
      {
        type: 'object',
        properties: {
          maxSizeBytes: { type: 'number', default: 1048576 },
          requireValidation: { type: 'boolean', default: true },
          allowedValidationFunctions: { type: 'array', items: { type: 'string' } },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      missingSizeGuard:
        'JSON.{{method}}() without size guard detected. Add size validation to prevent DoS attacks from oversized payloads. Use validateJsonSize() or limit input size.',
      unsafeJsonParse:
        "JSON.parse() on external input '{{param}}' without size validation. This could enable DoS attacks. Validate size before parsing.",
      unsafeJsonStringify:
        "JSON.stringify() without size limits may cause memory exhaustion. Consider adding size constraints.",
      suggestValidation:
        'Consider using a validation function like validateJsonSize(input, {{maxSize}}) before JSON operations.',
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const maxSizeBytes = options.maxSizeBytes || 1048576;
    const requireValidation = options.requireValidation !== false;
    const allowedValidationFunctions = new Set([
      'validateJsonSize',
      'validateInputSize',
      'checkSizeLimit',
      'validatePayloadSize',
      ...(options.allowedValidationFunctions || []),
    ]);

    function hasSizeValidation(node) {
      let current = node;
      while (current && current.type !== 'FunctionDeclaration' && current.type !== 'FunctionExpression' && current.type !== 'ArrowFunctionExpression') {
        current = current.parent;
      }

      if (!current || !current.body) return false;
      const body = current.body.type === 'BlockStatement' ? current.body.body : [];

      for (const statement of body) {
        if (statement.type === 'ExpressionStatement' && statement.expression.type === 'CallExpression' &&
            statement.expression.callee.type === 'Identifier' && allowedValidationFunctions.has(statement.expression.callee.name)) {
          return true;
        }

        if (statement.type === 'VariableDeclaration') {
          for (const declarator of statement.declarations) {
            if (declarator.init && declarator.init.type === 'CallExpression' && declarator.init.callee.type === 'Identifier' &&
                allowedValidationFunctions.has(declarator.init.callee.name)) {
              return true;
            }
          }
        }
      }

      return false;
    }

    return {
      CallExpression(node) {
        const callee = node.callee;
        if (!callee || callee.type !== 'MemberExpression') return;

        const obj = callee.object;
        const prop = callee.property;
        if (!obj || !prop || obj.type !== 'Identifier' || prop.type !== 'Identifier') return;

        // JSON.parse
        if (obj.name === 'JSON' && prop.name === 'parse') {
          if (!hasSizeValidation(node) && requireValidation) {
            context.report({
              node,
              messageId: 'missingSizeGuard',
              data: { method: 'parse' },
            });
          }
        }

        // JSON.stringify
        if (obj.name === 'JSON' && prop.name === 'stringify') {
          if (!hasSizeValidation(node) && requireValidation) {
            context.report({
              node,
              messageId: 'missingSizeGuard',
              data: { method: 'stringify' },
            });
          }
        }
      },
    };
  },
};