/**
 * @fileoverview ESLint rule: enforce-sealed-kit-startup
 * Ensures that sealSecurityKit() is called in main entry points to prevent
 * runtime configuration tampering. Enforces Security Constitution requirement
 * that the security kit must be sealed at startup.
 */

export default {
  meta: {
    type: "error",
    docs: {
      description:
        "Ensure sealSecurityKit() is called in main entry points to prevent runtime configuration tampering",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          entryPointPatterns: {
            type: "array",
            items: { type: "string" },
            description: "File patterns that should call sealSecurityKit()"
          },
          sealFunctionNames: {
            type: "array", 
            items: { type: "string" },
            description: "Function names that seal the security kit"
          }
        },
        additionalProperties: false,
      }
    ],
    messages: {
      missingSealCall:
        "Entry point file must call sealSecurityKit() to prevent runtime configuration tampering. " +
        "Add: import { sealSecurityKit } from './state.ts'; sealSecurityKit();",
      sealNotInTopLevel:
        "sealSecurityKit() must be called at the top level, not inside functions or conditional blocks, " +
        "to ensure it executes during module initialization.",
      multipleSealCalls:
        "sealSecurityKit() should only be called once per entry point to avoid redundant sealing attempts.",
    },
  },

  create(context) {
    const filename = String(context.getFilename() || "");
    const options = context.options[0] || {};
    
    // Default patterns for entry point files that should seal the kit
    const defaultEntryPatterns = [
      "index.ts",
      "main.ts", 
      "app.ts",
      "server.ts",
      "/src/index.ts",
      "/src/main.ts"
    ];
    
    const defaultSealFunctions = [
      "sealSecurityKit",
      "_sealSecurityKit"
    ];

    const entryPointPatterns = options.entryPointPatterns || defaultEntryPatterns;
    const sealFunctionNames = options.sealFunctionNames || defaultSealFunctions;

    /**
     * Checks if the current file should be calling sealSecurityKit
     */
    function isEntryPointFile() {
      return entryPointPatterns.some(pattern => 
        filename.includes(pattern) || filename.endsWith(pattern)
      );
    }

    if (!isEntryPointFile()) {
      return {};
    }

    let hasSealCall = false;
    let sealCallNodes = [];
    let hasTopLevelSealCall = false;

    /**
     * Checks if a call expression is a seal function call
     */
    function isSealCall(node) {
      if (node.type !== "CallExpression") return false;
      
      const callee = node.callee;
      
      // Direct function call: sealSecurityKit()
      if (callee?.type === "Identifier") {
        return sealFunctionNames.includes(callee.name);
      }
      
      // Property access: state.sealSecurityKit() or this.sealSecurityKit()
      if (callee?.type === "MemberExpression" && 
          callee.property?.type === "Identifier") {
        return sealFunctionNames.includes(callee.property.name);
      }
      
      return false;
    }

    /**
     * Determines if a node is at the top level of the module
     */
    function isTopLevelCall(node) {
      let parent = node.parent;
      
      // Walk up the AST to find the closest statement container
      while (parent && parent.type !== "Program") {
        // If we encounter a function, class, or conditional block, it's not top level
        if ([
          "FunctionDeclaration", 
          "FunctionExpression", 
          "ArrowFunctionExpression",
          "ClassDeclaration",
          "IfStatement", 
          "WhileStatement", 
          "ForStatement",
          "TryStatement"
        ].includes(parent.type)) {
          return false;
        }
        parent = parent.parent;
      }
      
      return true;
    }

    return {
      CallExpression(node) {
        if (isSealCall(node)) {
          hasSealCall = true;
          sealCallNodes.push(node);
          
          if (isTopLevelCall(node)) {
            hasTopLevelSealCall = true;
          } else {
            context.report({
              node,
              messageId: "sealNotInTopLevel",
            });
          }
        }
      },

      "Program:exit"(node) {
        // Check if we found any seal calls
        if (!hasSealCall) {
          context.report({
            node,
            messageId: "missingSealCall",
          });
          return;
        }

        // Warn about multiple seal calls (may indicate redundancy)
        if (sealCallNodes.length > 1) {
          sealCallNodes.slice(1).forEach(callNode => {
            context.report({
              node: callNode,
              messageId: "multipleSealCalls",
            });
          });
        }

        // Must have at least one top-level call
        if (!hasTopLevelSealCall) {
          context.report({
            node,
            messageId: "sealNotInTopLevel",
          });
        }
      }
    };
  },
};