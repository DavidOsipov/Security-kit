/**
 * @fileoverview ESLint rule: no-direct-process-env
 * Prevents direct access to process.env outside of approved configuration modules.
 * Enforces centralized configuration architecture and prevents configuration drift.
 * Aligns with Security Constitution §1.3 (Principle of Least Privilege) and 
 * §1.9 (Hardened Simplicity).
 */

export default {
  meta: {
    type: "error",
    docs: {
      description:
        "Prevent direct access to process.env outside approved configuration modules to enforce centralized configuration",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          allowedFiles: {
            type: "array",
            items: { type: "string" },
            description: "File patterns allowed to access process.env directly"
          },
          allowedPatterns: {
            type: "array", 
            items: { type: "string" },
            description: "Additional regex patterns for allowed files"
          }
        },
        additionalProperties: false,
      },
    ],
    messages: {
      useConfigModule:
        "Direct access to process.env is forbidden. Use centralized configuration from environment.ts or config.ts instead. " +
        "Suggestion: {{suggestion}}",
      useEnvironmentModule:
        "Access environment variables through the centralized environment module: import { environment } from './environment.ts'",
    },
  },

  create(context) {
    const filename = String(context.getFilename() || "");
    const options = context.options[0] || {};
    
    // Default allowed files - these are the approved configuration modules
    const defaultAllowedFiles = [
      "config.ts",
      "environment.ts", 
      "eslint.config.mjs",
      "eslint.config.js",
      "vitest.config.ts",
      "tsup.config.ts",
      "astro.config.mjs"
    ];
    
    const allowedFiles = options.allowedFiles || defaultAllowedFiles;
    const allowedPatterns = options.allowedPatterns || [];

    /**
     * Checks if the current file is allowed to access process.env
     */
    function isFileAllowed() {
      // Check direct file matches
      const isDirectlyAllowed = allowedFiles.some(pattern => 
        filename.includes(pattern) || filename.endsWith(pattern)
      );
      
      if (isDirectlyAllowed) return true;
      
      // Check regex patterns
      const isPatternAllowed = allowedPatterns.some(pattern => {
        try {
          const regex = new RegExp(pattern);
          return regex.test(filename);
        } catch {
          return false;
        }
      });
      
      return isPatternAllowed;
    }

    /**
     * Gets an appropriate suggestion based on the environment variable being accessed
     */
    function getSuggestion(propertyName) {
      if (!propertyName) {
        return "import { environment } from './environment.ts'";
      }

      // Common environment variable mappings to your centralized config
      const suggestions = {
        'NODE_ENV': "import { environment } from './environment.ts' and use environment.isDevelopment()",
        'SECURITY_STRICT': "import { environment } from './environment.ts'",
        'API_URL': "import { getApiConfig } from './config.ts'",
        'API_KEY': "Use Backend-for-Frontend pattern - secrets must not be in client code",
        'DATABASE_URL': "Access through server-side configuration only",
        'JWT_SECRET': "Use Backend-for-Frontend pattern - secrets must not be in client code"
      };

      return suggestions[propertyName] || "import { environment } from './environment.ts'";
    }

    if (isFileAllowed()) {
      return {};
    }

    return {
      MemberExpression(node) {
        // Check for process.env access
        if (
          node.object &&
          node.object.type === "Identifier" &&
          node.object.name === "process" &&
          node.property &&
          node.property.name === "env"
        ) {
          const suggestion = getSuggestion();
          
          context.report({
            node,
            messageId: "useConfigModule",
            data: { suggestion },
          });
        }

        // Check for process.env.VARIABLE access
        if (
          node.object &&
          node.object.type === "MemberExpression" &&
          node.object.object &&
          node.object.object.type === "Identifier" &&
          node.object.object.name === "process" &&
          node.object.property &&
          node.object.property.name === "env"
        ) {
          const envVar = node.property && node.property.type === "Identifier" 
            ? node.property.name 
            : null;
          const suggestion = getSuggestion(envVar);
          
          context.report({
            node,
            messageId: "useConfigModule", 
            data: { suggestion },
          });
        }
      },

      // Also catch bracket notation: process.env['VARIABLE']
      CallExpression(node) {
        // This won't be a call expression, but we should handle bracket access
      },
      
      // Handle bracket notation separately
      "MemberExpression[computed=true]"(node) {
        if (
          node.object &&
          node.object.type === "MemberExpression" &&
          node.object.object &&
          node.object.object.type === "Identifier" &&
          node.object.object.name === "process" &&
          node.object.property &&
          node.object.property.name === "env"
        ) {
          let envVar = null;
          if (node.property && node.property.type === "Literal" && 
              typeof node.property.value === "string") {
            envVar = node.property.value;
          }
          
          const suggestion = getSuggestion(envVar);
          
          context.report({
            node,
            messageId: "useConfigModule",
            data: { suggestion },
          });
        }
      }
    };
  },
};