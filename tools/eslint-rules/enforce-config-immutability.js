/**
 * @fileoverview ESLint rule: enforce-config-immutability
 * Enforces that configuration objects are properly frozen and prevents
 * mutations after sealing. Implements Principle of Least Privilege for
 * configuration management.
 * 
 * OWASP ASVS V14.2.1: Configuration integrity
 * Security Constitution §1.3 "Principle of Least Privilege"
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Enforce configuration immutability with Object.freeze and prevent mutations after sealing",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          configPatterns: {
            type: "array",
            items: { type: "string" },
            description: "Variable name patterns that should be treated as configuration"
          },
          requiredFreezeFor: {
            type: "array", 
            items: { type: "string" },
            description: "Object types that must be frozen"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      configNotFrozen: "Configuration object {{name}} must be frozen with Object.freeze() to prevent mutations",
      mutationAfterSealing: "Configuration mutation attempted after sealing. Check getCryptoState() === CryptoState.Sealed before modifying {{name}}",
      suggestFreeze: "Add: Object.freeze({{name}})",
      suggestSealCheck: "Add: if (getCryptoState() === CryptoState.Sealed) throw new InvalidConfigurationError('Configuration is sealed');"
    },
  // fixable removed to prevent unsafe automated edits; rule is error-only
  },

  create(context) {
    const options = context.options[0] || {};
    const configPatterns = options.configPatterns || [
      "config$",
      "settings$", 
      "options$",
      "defaults$",
      "constants$"
    ];
    
    // Convert string patterns to RegExp objects
    const configRegexes = configPatterns.map(pattern => 
      typeof pattern === 'string' ? new RegExp(pattern, 'i') : pattern
    );
    
    const requiredFreezeFor = new Set(options.requiredFreezeFor || [
      "ObjectExpression",
      "ArrayExpression"
    ]);

    // Skip tests
    const filename = context.getFilename() || "";
    if (/\b(tests?|demo|benchmarks)\b/i.test(filename)) {
      return {};
    }

    const configVariables = new Set();
    const frozenObjects = new Set();

    /**
     * Check if identifier name matches config patterns
     */
    function isConfigName(name) {
      return configRegexes.some(pattern => pattern.test(name));
    }

    /**
     * Check if assignment has seal check
     */
    function hasSealCheck(node) {
      // Look for getCryptoState() === CryptoState.Sealed checks
      // This is a simplified check - real implementation would be more sophisticated
      let parent = node.parent;
      while (parent && parent.type !== "Program") {
        if (parent.type === "IfStatement" && 
            parent.test?.type === "BinaryExpression") {
          const test = parent.test;
          if (test.left?.type === "CallExpression" &&
              test.left?.callee?.name === "getCryptoState" &&
              test.operator === "===" &&
              test.right?.type === "MemberExpression" &&
              test.right?.object?.name === "CryptoState" &&
              test.right?.property?.name === "Sealed") {
            return true;
          }
        }
        parent = parent.parent;
      }
      return false;
    }

    return {
      // Track variable declarations
      VariableDeclarator(node) {
        if (node.id?.type === "Identifier" && isConfigName(node.id.name)) {
          configVariables.add(node.id.name);
          
          // Check if the value should be frozen
          if (node.init && requiredFreezeFor.has(node.init.type)) {
            // Look for Object.freeze call
            const parent = node.parent?.parent; // VariableDeclarator -> VariableDeclaration -> parent
            let foundFreeze = false;
            
            // Check immediate next statement for Object.freeze
            if (parent?.type === "Program" || parent?.type === "BlockStatement") {
              const declarationIndex = parent.body?.findIndex(stmt => 
                stmt === node.parent
              );
              if (declarationIndex !== -1 && declarationIndex < parent.body.length - 1) {
                const nextStmt = parent.body[declarationIndex + 1];
                if (nextStmt?.type === "ExpressionStatement" &&
                    nextStmt.expression?.type === "CallExpression" &&
                    nextStmt.expression?.callee?.type === "MemberExpression" &&
                    nextStmt.expression?.callee?.object?.name === "Object" &&
                    nextStmt.expression?.callee?.property?.name === "freeze" &&
                    nextStmt.expression?.arguments?.[0]?.name === node.id.name) {
                  foundFreeze = true;
                  frozenObjects.add(node.id.name);
                }
              }
            }
            
            if (!foundFreeze) {
              context.report({
                node: node.id,
                messageId: "configNotFrozen", 
                data: { name: node.id.name }
              });
            }
          }
        }

        // ...existing code...
      },

      // Handle function returning an object literal directly: return { ... } -> return Object.freeze({ ... })
      ReturnStatement(node) {
        if (node.argument && node.argument.type === 'ObjectExpression') {
          context.report({
            node: node.argument,
            messageId: 'configNotFrozen',
            data: { name: 'returnedConfig' }
          });
        }
      },

      // Track Object.freeze calls
      CallExpression(node) {
        if (node.callee?.type === "MemberExpression" &&
            node.callee?.object?.name === "Object" &&
            node.callee?.property?.name === "freeze" &&
            node.arguments?.[0]?.type === "Identifier") {
          frozenObjects.add(node.arguments[0].name);
        }
      },

      // Check assignments to config variables
      AssignmentExpression(node) {
        if (node.left?.type === "Identifier" && 
            configVariables.has(node.left.name)) {
          
          if (!hasSealCheck(node)) {
            context.report({
              node,
              messageId: "mutationAfterSealing",
              data: { name: node.left.name }
            });
          }
        }

        // Check member assignments to config objects
        if (node.left?.type === "MemberExpression" &&
            node.left?.object?.type === "Identifier" &&
            configVariables.has(node.left.object.name)) {
          
          if (!hasSealCheck(node)) {
            context.report({
              node,
              messageId: "mutationAfterSealing",
              data: { name: node.left.object.name }
            });
          }
        }
      }
    };
  }
};