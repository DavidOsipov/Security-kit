/**
 * @fileoverview ESLint rule: no-postmessage-constant-usage
 *
 * Goal (Pillar #1 & #2): Prevent drift where runtime logic reads the legacy
 * POSTMESSAGE_MAX_* constants directly instead of consulting the dynamic
 * configuration via getPostMessageConfig(). This enforces that all future
 * limit decisions are centrally governed and adjustable prior to sealing.
 *
 * Allowed usages (not reported):
 *  - Inside `src/config.ts` (definition / default wiring)
 *  - Inside tests (`/tests/` paths) for assertions / fixtures
 *  - Import specifiers (so files can re-export for backwards compatibility)
 *  - Type-only references (TS compile-time) – we heuristically ignore when
 *    parent.type === 'TSTypeReference'
 *
 * Everything else triggers a warning suggesting the config accessor.
 */

const TARGET_PREFIX = 'POSTMESSAGE_MAX_';

export default {
  meta: {
    type: 'problem',
    docs: {
      description: 'Disallow direct runtime usage of POSTMESSAGE_MAX_* constants outside config.ts and tests; require getPostMessageConfig()',
      recommended: false,
    },
    schema: [
      {
        type: 'object',
        additionalProperties: false,
        properties: {
          allowFiles: {
            type: 'array',
            items: { type: 'string' },
          },
        },
      },
    ],
    messages: {
      noDirectUsage:
        "Use getPostMessageConfig() for runtime limits; POSTMESSAGE_MAX_* constants are for defaults/backward compatibility only.",
      avoidHardcodedOrigin: "Avoid hardcoded postMessage origin; validate with validateOrigin() or use dynamic configuration",
      useConfigFactory: "Use createPostMessageConfig() factory for postMessage configuration objects",
    },
  },
  create(context) {
    const filename = String(context.getFilename() || '');

    // Allow tests outright
    if (/\btests?\b/.test(filename)) {
      return {};
    }

    // Allow the definitions file
    if (filename.endsWith('src/config.ts')) {
      return {};
    }

    // Allow consumers to opt-in to additional allowed files
    const option = (context.options && context.options[0]) || {};
    const allowFiles = Array.isArray(option.allowFiles)
      ? option.allowFiles
      : [];
    if (allowFiles.some((p) => filename.endsWith(p))) {
      return {};
    }

  function isIgnoredParent(parent) {
      if (!parent) return false;
      switch (parent.type) {
        case 'ImportSpecifier':
        case 'ImportDefaultSpecifier':
        case 'ImportNamespaceSpecifier':
        case 'ExportSpecifier':
          return true; // re-export / import is fine
        case 'TSTypeReference':
          return true; // type-only usage
        default:
          return false;
      }
    }

    return {
      Identifier(node) {
        if (!node || typeof node.name !== 'string') return;
        if (!node.name.startsWith(TARGET_PREFIX)) return;
        const parent = node.parent;
        if (isIgnoredParent(parent)) return;

        // Heuristic: if parent is VariableDeclarator and node is the id (definition), allow
        if (parent && parent.type === 'VariableDeclarator' && parent.id === node) {
          return; // definitions (should only appear in config.ts anyway)
        }
        // Allow property keys in object literals: { POSTMESSAGE_MAX_PAYLOAD_DEPTH: ... }
        if (
          parent &&
          parent.type === 'Property' &&
          parent.key === node &&
          !parent.computed
        ) {
          return;
        }
        // Report all other runtime reads
        // Map constant name to config property heuristic
        let replacementProp = '';
        if (node.name === 'POSTMESSAGE_MAX_PAYLOAD_DEPTH') replacementProp = 'maxPayloadDepth';
        else if (node.name === 'POSTMESSAGE_MAX_JSON_INPUT_BYTES') replacementProp = 'maxJsonTextBytes';
        else if (node.name === 'POSTMESSAGE_MAX_PAYLOAD_BYTES') replacementProp = 'maxPayloadBytes';

        context.report({
          node,
          messageId: 'noDirectUsage'
        });
      },
      CallExpression(node) {
        // detect postMessage(target, origin) style hardcoded origin strings
        if (node.callee?.name === 'postMessage' && node.arguments?.[1]) {
          const arg = node.arguments[1];
          if (arg.type === 'Literal' && typeof arg.value === 'string') {
            context.report({
              node: arg,
              messageId: 'avoidHardcodedOrigin'
            });
          }
        }
      },
      VariableDeclarator(node) {
        // detect plain postMessage config object literals and suggest factory
        if (node.init && node.init.type === 'ObjectExpression') {
          const props = node.init.properties || [];
          const hasAllowed = props.some(p => p.key && ((p.key.name === 'allowedOrigins') || (p.key.value === 'allowedOrigins')));
          const hasTargetOrigin = props.some(p => p.key && ((p.key.name === 'targetOrigin') || (p.key.value === 'targetOrigin')));
          if (hasAllowed || hasTargetOrigin) {
            context.report({
              node: node.init,
              messageId: 'useConfigFactory'
            });
          }
        }
      },
    };
  },
};
