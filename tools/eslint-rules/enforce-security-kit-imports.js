/**
 * @fileoverview ESLint rule: enforce-security-kit-imports
 * Enforces use of centralized security-kit utilities instead of direct Web Crypto API access.
 * Merged with no-direct-subtle-crypto rule for unified crypto API enforcement.
 * Ensures all cryptographic operations go through the hardened, tested security-kit interface.
 */

import { collectAliases, resolveFullMemberName, isGlobalReference } from './_shared/analysis.js';

export default {
  meta: {
    type: "error",
    docs: {
      description:
        "Enforce use of centralized security-kit utilities instead of direct Web Crypto API access",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          allowedFiles: {
            type: "array",
            items: { type: "string" },
            description: "File patterns allowed to access crypto APIs directly"
          },
          securityKitModule: {
            type: "string",
            description: "Path to the security kit module"
          },
          allowedMethods: {
            type: "array",
            items: { type: "string" },
            description: "Array of crypto.subtle methods that are allowed (for gradual migration)"
          }
        },
        additionalProperties: false,
      }
    ],
    messages: {
      useSecurityKit:
        "Direct access to {{api}} is forbidden. Use {{suggestion}} from security-kit instead. " +
        "The security-kit provides hardened, tested wrappers with DoS protection and error handling.",
      useSecurityKitGeneric:
        "Direct crypto API access detected. Use the centralized security-kit utilities instead of {{api}}.",
      importSecurityKit:
        "Import the required utilities: import { {{functions}} } from '{{module}}';",
      noSubtle:
        "Direct use of 'crypto.subtle.{{method}}' is forbidden. Use a high-level abstraction from the security-kit instead " +
        "(e.g., 'sha256Base64' for digest, 'createAesGcmKey256' for key generation) to ensure proper validation and error handling.",
      noSubtleGeneric:
        "Direct access to 'crypto.subtle' is forbidden. Use high-level abstractions from the security-kit to ensure " +
        "proper validation, hardening, and consistent error handling per our Security Constitution.",
      suggestAlternative:
        "Consider using these security-kit alternatives: {{alternatives}}",
    },
  },

  create(context) {
    const filename = String(context.getFilename() || "");
    const options = context.options[0] || {};
    
    // Files allowed to access crypto APIs directly (typically just the security-kit itself)
    const defaultAllowedFiles = [
      "crypto.ts",
      "state.ts", 
      "/src/crypto.ts",
      "/src/state.ts",
      "security-kit.ts",
      "/tests/",  // Tests may need direct access for mocking
    ];
    
    const allowedFiles = options.allowedFiles || defaultAllowedFiles;
    const securityKitModule = options.securityKitModule || "./crypto.ts";
    const allowedMethods = new Set(options.allowedMethods || []);

    /**
     * Checks if the current file is allowed direct crypto access
     */
    function isAllowedFile() {
      return allowedFiles.some(pattern => 
        filename.includes(pattern) || filename.endsWith(pattern)
      );
    }

    /**
     * Maps crypto API calls to security-kit equivalents
     */
    function getSecurityKitSuggestion(apiCall) {
      const suggestions = {
        // Web Crypto API -> Security Kit mappings
        "crypto.getRandomValues": "getSecureRandomBytesSync",
        "crypto.randomUUID": "generateSecureUUID", 
        "crypto.subtle.generateKey": "createOneTimeCryptoKey",
        "crypto.subtle.importKey": "createOneTimeCryptoKey",
        "crypto.subtle.encrypt": "Use AES-GCM utilities from security-kit",
        "crypto.subtle.decrypt": "Use AES-GCM utilities from security-kit", 
        "crypto.subtle.sign": "Use signing utilities from security-kit",
        "crypto.subtle.verify": "Use verification utilities from security-kit",
        "crypto.subtle.digest": "Use hashing utilities from security-kit",
        "crypto.subtle.deriveBits": "Use key derivation utilities from security-kit",
        "crypto.subtle.deriveKey": "Use key derivation utilities from security-kit",
        
        // Node.js crypto -> Security Kit mappings  
        "require('crypto')": "Use security-kit instead of Node.js crypto module",
        "require('node:crypto')": "Use security-kit instead of Node.js crypto module",
        "import crypto": "Use security-kit instead of direct crypto imports",
        
        // Other crypto libraries
        "CryptoJS": "Use Web Crypto API through security-kit instead of CryptoJS",
        "bcrypt": "Use security-kit utilities or approved server-side alternatives",
        "uuid": "Use generateSecureUUID from security-kit",
      };
      
      return suggestions[apiCall] || "appropriate security-kit utility";
    }

    /**
     * Gets recommended import statement
     */
    function getImportSuggestion(apiCalls) {
      const functionMappings = {
        "getRandomValues": "getSecureRandomBytesSync, getSecureRandom",
        "randomUUID": "generateSecureUUID",
        "generateKey": "createOneTimeCryptoKey", 
        "encrypt": "encryption utilities",
        "decrypt": "decryption utilities",
        "sign": "signing utilities",
        "verify": "verification utilities"
      };
      
      const functions = apiCalls.map(call => {
        const parts = call.split('.');
        const methodName = parts[parts.length - 1];
        return functionMappings[methodName] || methodName;
      }).join(", ");
      
      return functions;
    }

    /**
     * Get suggested alternatives for common crypto.subtle methods
     */
    function getSuggestedAlternatives(method) {
      const alternatives = {
        digest: "sha256Base64() from encoding-utils.ts",
        generateKey: "createAesGcmKey256(), createHmacKey() from crypto.ts",
        sign: "createSecureSignature() from postMessage.ts",
        verify: "verifySecureSignature() from postMessage.ts",
        encrypt: "secure encryption utilities from crypto.ts",
        decrypt: "secure decryption utilities from crypto.ts",
        deriveBits: "secure key derivation utilities from crypto.ts",
        deriveKey: "secure key derivation utilities from crypto.ts",
        importKey: "key import utilities from crypto.ts",
        exportKey: "key export utilities from crypto.ts",
        wrapKey: "secure key wrapping utilities from crypto.ts",
        unwrapKey: "secure key unwrapping utilities from crypto.ts"
      };
      
      return alternatives[method] || "appropriate security-kit abstraction";
    }

    /**
     * Checks if a generateKey call looks safe (has proper parameters)
     */
    function isLikelySafeGenerateKeyCall(node, context) {
      // Find the CallExpression that contains this generateKey
      let callNode = node;
      
      // If node is the property (generateKey), find its parent CallExpression
      if (node.type === 'Identifier' && node.name === 'generateKey') {
        let current = node;
        while (current && current.type !== 'CallExpression') {
          current = current.parent;
        }
        callNode = current;
      } else if (node.type === 'MemberExpression') {
        let current = node;
        while (current && current.type !== 'CallExpression') {
          current = current.parent;
        }
        callNode = current;
      }
      
      if (!callNode || callNode.type !== 'CallExpression') {
        return false;
      }
      
      // Must have at least 3 arguments
      if (!callNode.arguments || callNode.arguments.length < 3) {
        return false;
      }
      
      const [algorithm, extractable, keyUsages] = callNode.arguments;
      
      // Check if keyUsages includes both encrypt and decrypt (suggesting proper key usage)
      if (keyUsages && keyUsages.type === 'ArrayExpression') {
        const usageElements = keyUsages.elements || [];
        const usages = usageElements
          .filter(el => el && el.type === 'Literal' && typeof el.value === 'string')
          .map(el => el.value);
        
        // Allow if it includes both encrypt and decrypt (proper encryption key)
        return usages.includes('encrypt') && usages.includes('decrypt');
      }
      return false;
    }

    if (isAllowedFile()) {
      return {};
    }

    // Skip for encoding-utils.ts and other internal crypto modules that may legitimately use crypto.subtle
    if (filename.includes("encoding-utils.ts") || filename.includes("capabilities.ts")) {
      return {};
    }

    const detectedApiCalls = new Set();
    const reportedNodes = new Set(); // Track nodes we've already reported on
    const aliases = collectAliases(context, ['crypto', 'crypto.subtle']);

    return {
      // Direct crypto object access
      MemberExpression(node) {
        // Skip if we've already reported on this node
        if (reportedNodes.has(node)) return;
        
        // Prioritize detection of crypto.subtle.* access before generic crypto.* checks
        // so that method-specific messages (e.g., 'noSubtle') are reported first
        const object = node.object;
        const property = node.property;

        // crypto.subtle.* access - be more selective
        if (object?.type === "MemberExpression" &&
            object.object?.type === "Identifier" &&
            object.object.name === "crypto" &&
            object.property?.type === "Identifier" &&
            object.property.name === "subtle") {

          if (property?.type === "Identifier") {
            const method = property.name;

            // Skip if method is explicitly allowed
            if (allowedMethods.has(method)) {
              return;
            }

            const apiCall = `crypto.subtle.${method}`;
            detectedApiCalls.add(apiCall);

            // For generateKey, only flag if it doesn't look safe
            let shouldFlag = true;
            if (method === 'generateKey') {
              shouldFlag = !isLikelySafeGenerateKeyCall(node, context);
            }

            if (shouldFlag) {
              reportedNodes.add(node);
              const alternatives = getSuggestedAlternatives(method);

              context.report({
                node,
                messageId: "noSubtle",
                data: {
                  method,
                  alternatives
                }
              });
            }
          }
        }

        // crypto.getRandomValues, crypto.randomUUID, etc.
        if (object?.type === "Identifier" && object.name === "crypto") {
          if (property?.type === "Identifier") {
            const apiCall = `crypto.${property.name}`;
            detectedApiCalls.add(apiCall);

            // Only flag problematic methods, allow getRandomValues and randomUUID
            if (property.name !== 'getRandomValues' && property.name !== 'randomUUID') {
              // For subtle, check if it's followed by allowed method
              if (property.name === 'subtle') {
                // Check if parent is generateKey with proper parameters
                if (node.parent?.type === 'MemberExpression' && node.parent.property?.name === 'generateKey') {
                  const generateKeyNode = node.parent;
                  if (isLikelySafeGenerateKeyCall(generateKeyNode, context)) {
                    // Don't report
                  } else {
                    reportedNodes.add(node);
                    context.report({
                      node,
                      messageId: "useSecurityKit",
                      data: {
                        api: apiCall,
                        suggestion: getSecurityKitSuggestion(apiCall)
                      }
                    });
                  }
                } else {
                  reportedNodes.add(node);
                  context.report({
                    node,
                    messageId: "useSecurityKit",
                    data: {
                      api: apiCall,
                      suggestion: getSecurityKitSuggestion(apiCall)
                    }
                  });
                }
              } else {
                reportedNodes.add(node);
                context.report({
                  node,
                  messageId: "useSecurityKit",
                  data: {
                    api: apiCall,
                    suggestion: getSecurityKitSuggestion(apiCall)
                  }
                });
              }
            }
          }
        }

        // window.crypto, globalThis.crypto, self.crypto access - these should be flagged
        if (object?.type === "MemberExpression" &&
            object.object?.type === "Identifier" &&
            ["window", "self"].includes(object.object.name) &&
            object.property?.type === "Identifier" &&
            object.property.name === "crypto") {

          // Check if this is followed by .subtle access
          if (node.parent?.type === "MemberExpression" &&
              node.parent.property?.type === "Identifier" &&
              node.parent.property.name === "subtle") {
            // This is window.crypto.subtle - flag it
            const parentNode = node.parent;
            if (!reportedNodes.has(parentNode)) {
              reportedNodes.add(parentNode);
              context.report({
                node: parentNode,
                messageId: "useSecurityKit",
                data: {
                  api: "window.crypto.subtle",
                  suggestion: getSecurityKitSuggestion("crypto.subtle")
                }
              });
            }
          }
        }

        // Check for window.crypto.subtle.* access
        if (object?.type === "MemberExpression" &&
            object.object?.type === "MemberExpression" &&
            object.object.object?.type === "Identifier" &&
            ["window", "self"].includes(object.object.object.name) &&
            object.object.property?.type === "Identifier" &&
            object.object.property.name === "crypto" &&
            object.property?.type === "Identifier" &&
            object.property.name === "subtle") {

          // This is window.crypto.subtle - flag it
          if (!reportedNodes.has(node)) {
            reportedNodes.add(node);
            context.report({
              node,
              messageId: "noSubtleGeneric"
            });
          }
        }

        // Alias usage: alias.subtle.method
        const fullName = resolveFullMemberName(node);
        if (fullName && fullName.startsWith('crypto.subtle.')) {
          const method = fullName.split('.')[2];
          if (method && !allowedMethods.has(method)) {
            let shouldFlag = true;
            if (method === 'generateKey') {
              shouldFlag = !isLikelySafeGenerateKeyCall(node, context);
            }

            if (shouldFlag && !reportedNodes.has(node)) {
              reportedNodes.add(node);
              const alternatives = getSuggestedAlternatives(method);
              context.report({
                node,
                messageId: "noSubtle",
                data: {
                  method,
                  alternatives
                }
              });
            }
          }
        }

        // Check for alias.subtle.method
        if (object?.type === "MemberExpression" &&
            object.object?.type === "Identifier" && aliases.get('crypto')?.includes(object.object.name) &&
            object.property?.type === "Identifier" && object.property.name === "subtle" &&
            property?.type === "Identifier") {
          const method = property.name;
          if (!allowedMethods.has(method)) {
            let shouldFlag = true;
            if (method === 'generateKey') {
              shouldFlag = !isLikelySafeGenerateKeyCall(node, context);
            }

            if (shouldFlag && !reportedNodes.has(node)) {
              reportedNodes.add(node);
              const alternatives = getSuggestedAlternatives(method);
              context.report({
                node,
                messageId: "noSubtle",
                data: {
                  method,
                  alternatives
                }
              });
            }
          }
        }

        // Check for alias usage
        if (object?.type === "Identifier" && aliases.get('crypto')?.includes(object.name)) {
          if (property?.type === "Identifier") {
            const apiCall = `crypto.${property.name}`;
            detectedApiCalls.add(apiCall);

            if (property.name !== 'getRandomValues' && property.name !== 'randomUUID') {
              if (property.name === 'subtle') {
                // Check if parent is generateKey with proper parameters
                if (node.parent?.type === 'MemberExpression' && node.parent.property?.name === 'generateKey') {
                  const generateKeyNode = node.parent;
                  if (!isLikelySafeGenerateKeyCall(generateKeyNode, context)) {
                    reportedNodes.add(node);
                    context.report({
                      node,
                      messageId: "useSecurityKit",
                      data: {
                        api: apiCall,
                        suggestion: getSecurityKitSuggestion(apiCall)
                      }
                    });
                  }
                } else {
                  reportedNodes.add(node);
                  context.report({
                    node,
                    messageId: "useSecurityKit",
                    data: {
                      api: apiCall,
                      suggestion: getSecurityKitSuggestion(apiCall)
                    }
                  });
                }
              } else {
                reportedNodes.add(node);
                context.report({
                  node,
                  messageId: "useSecurityKit",
                  data: {
                    api: apiCall,
                    suggestion: getSecurityKitSuggestion(apiCall)
                  }
                });
              }
            }
          }
        }

        // Check for alias.subtle.method
        if (object?.type === "MemberExpression" &&
            object.object?.type === "Identifier" && aliases.get('crypto')?.includes(object.object.name) &&
            object.property?.type === "Identifier" && object.property.name === "subtle" &&
            property?.type === "Identifier") {
          const method = property.name;
          if (!allowedMethods.has(method)) {
            let shouldFlag = true;
            if (method === 'generateKey') {
              shouldFlag = !isLikelySafeGenerateKeyCall(node, context);
            }

            if (shouldFlag && !reportedNodes.has(node)) {
              reportedNodes.add(node);
              const alternatives = getSuggestedAlternatives(method);
              context.report({
                node,
                messageId: "noSubtle",
                data: {
                  method,
                  alternatives
                }
              });
            }
          }
        }
      },

      // Import statements for crypto modules
      ImportDeclaration(node) {
        const source = node.source.value;

        if (typeof source === "string") {
          const cryptoModules = [
            "crypto",
            "node:crypto",
            "crypto-js",
            "bcryptjs",
            "bcrypt",
            "uuid"
          ];

          if (cryptoModules.includes(source)) {
            detectedApiCalls.add(`import ${source}`);

            context.report({
              node,
              messageId: "useSecurityKit",
              data: {
                api: `import from '${source}'`,
                suggestion: getSecurityKitSuggestion(source)
              }
            });
          }
        }
      },

      // Require calls for crypto modules
      CallExpression(node) {
        const callee = node.callee;

        if (callee?.type === "Identifier" && callee.name === "require") {
          const arg = node.arguments[0];
          if (arg?.type === "Literal" && typeof arg.value === "string") {
            const moduleName = arg.value;
            const cryptoModules = ["crypto", "node:crypto", "crypto-js", "bcryptjs", "uuid"];

            if (cryptoModules.includes(moduleName)) {
              detectedApiCalls.add(`require('${moduleName}')`);

              context.report({
                node,
                messageId: "useSecurityKit",
                data: {
                  api: `require('${moduleName}')`,
                  suggestion: getSecurityKitSuggestion(`require('${moduleName}')`)
                }
              });
            }
          }
        }
      },

      // Also catch cases where crypto.subtle is destructured or assigned to variables
      VariableDeclarator(node) {
        // Skip if we've already reported on this node
        if (reportedNodes.has(node)) return;
        
        if (
          node.init &&
          node.init.type === "MemberExpression" &&
          node.init.object.type === "Identifier" &&
          node.init.object.name === "crypto" &&
          node.init.property.type === "Identifier" &&
          node.init.property.name === "subtle"
        ) {
          reportedNodes.add(node);
          context.report({
            node,
            messageId: "noSubtleGeneric",
          });
        }

        // Check for destructuring: const { subtle } = crypto
        if (
          node.id &&
          node.id.type === "ObjectPattern" &&
          node.init &&
          node.init.type === "Identifier" &&
          node.init.name === "crypto"
        ) {
          for (const prop of node.id.properties) {
            if (prop.type === "Property" &&
                prop.key.type === "Identifier") {
              const propName = prop.key.name;
              if (propName !== 'randomUUID') {
                if (!reportedNodes.has(prop)) {
                  reportedNodes.add(prop);
                  const messageId = propName === 'subtle' ? 'noSubtleGeneric' : 'useSecurityKit';
                  context.report({
                    node: prop,
                    messageId,
                    data: {
                      api: `crypto.${propName}`,
                      suggestion: getSecurityKitSuggestion(`crypto.${propName}`)
                    }
                  });
                }
              }
            }
          }
        }

        // Track aliases for crypto
        if (node.id?.type === "Identifier" &&
            node.init?.type === "Identifier" &&
            node.init.name === "crypto") {
          // This is an alias: const alias = crypto
          // Already handled by collectAliases
        }
      },

      // Provide import suggestion at the end if any violations were found
      "Program:exit"(node) {
        // Only report import suggestion if we have violations and haven't reported it yet
        const hasViolations = reportedNodes.size > 0;
        if (hasViolations && detectedApiCalls.size > 0 && !reportedNodes.has(node)) {
          const functions = getImportSuggestion(Array.from(detectedApiCalls));
          
          reportedNodes.add(node);
          context.report({
            node,
            messageId: "importSecurityKit",
            data: {
              functions,
              module: securityKitModule
            }
          });
        }
      }
    };
  },
};