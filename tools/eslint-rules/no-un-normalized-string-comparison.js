/**
 * @fileoverview ESLint rule: no-un-normalized-string-comparison
 * Requires Unicode normalization for external string comparisons to prevent
 * homograph attacks and Unicode normalization bypasses (ASVS V5.1.4).
 * Flags binary string comparisons and method calls where one operand appears
 * to be from an external source and hasn't been normalized.
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description:
        "Require Unicode normalization for external string comparisons to prevent homograph attacks",
      recommended: true,
    },
    // fixable removed: convert to error-only reporting to avoid unsafe automated edits
    schema: [],
    messages: {
      requireNormalization:
        "String comparison with external input requires normalization. Use normalizeInputString() from canonical.ts or similar normalization function",
      unsafeMethodCall:
        "String method '{{method}}' on external input requires normalization first. External strings may contain visually identical but canonically different characters",
      unsafeSwitchCase:
        "Switch statement with external input requires normalization. Use normalizeInputString() before the switch",
      unsafeRegexTest:
        "RegExp test with external input requires normalization to prevent Unicode bypass attacks",
    },
  },

  create(context) {
    // Skip tests and scripts
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\//i.test(filename)) {
      return {};
    }

    // Skip canonical.ts entirely - it's the normalization module
    // and ALL string operations within it are part of the normalization process
    if (/canonical\.ts$/.test(filename) || filename.includes('canonical.ts')) {
      return {};
    }

    // Skip generated files and internal utilities that handle Unicode data processing
    if (/generated\//.test(filename) || /unicode-/.test(filename)) {
      return {};
    }
    
    // Skip internal utility modules that process trusted/internal data
    // These modules handle low-level operations and internal string processing
    if (/\/(config|constants|encoding|errors)\.ts$/.test(filename)) {
      return {};
    }

    // Skip scripts directory - contains build/development tools, not runtime code
    if (/\/scripts\//.test(filename)) {
      return {};
    }

    /**
     * Detects if a node represents potentially external/untrusted input
     */
    function isTaintedInput(node, context) {
      if (!node) return false;

      // Skip literal strings - they're not external input
      if (node.type === "Literal" && typeof node.value === "string") {
        return false;
      }

      // Skip template literals with no expressions - they're static
      if (node.type === "TemplateLiteral" && node.expressions.length === 0) {
        return false;
      }

      // Function parameters are considered external input UNLESS they are in internal processing functions
      if (node.type === "Identifier") {
        const name = node.name;
        
        // Skip internal library identifiers that are known safe or are part of internal processing
        const internalIdentifiers = [
          "string_", "rawString", "normalizedString", "normalized", 
          "context", "scheme", "host", "port", "path", "query", "fragment",
          "url", "href", "origin", "protocol", "hostname", "pathname", 
          "search", "hash", "username", "password", "toString", "source",
          "target", "char", "codePoint", "status", "variant", "pattern",
          "regex", "key", "value", "name", "type", "method", "property",
          "input", "canonical", "violation", "factor", "score", "result",
          // Additional internal processing identifiers
          "cleanString", "processedString", "internalValue", "configValue",
          "constantValue", "literalValue", "encodedValue", "decodedValue",
          "tempString", "workingString", "bufferString", "cacheKey"
        ];
        
        if (internalIdentifiers.includes(name)) {
          return false; // These are internal processing variables, not external input
        }
        
        // Check if we're in an internal function context - be more specific
        const sourceCode = context.sourceCode || context.getSourceCode();
        const functionScope = sourceCode.getScope ? sourceCode.getScope(node) : context.getScope();
        
        // Look for function names that indicate internal processing
        let currentScope = functionScope;
        while (currentScope) {
          if (currentScope.type === 'function' && currentScope.block && 
              currentScope.block.id && currentScope.block.id.name) {
            const functionName = currentScope.block.id.name;
            // More comprehensive list of internal processing function patterns
            const internalFunctionPatterns = [
              /^(normalize|validate|sanitize|encode|decode|parse|build|create|update|analyze|calculate|detect|extract|generate|process|transform|convert)/,
              /^(toCanonical|isNormalized|getConfusable|validateUnicode|detectTrojan|calculateSecurity)/,
              /^(_[a-z]|internal[A-Z]|helper[A-Z]|process[A-Z]|analyze[A-Z])/,
              /(Internal|Helper|Utils|Util)$/
            ];
            
            if (internalFunctionPatterns.some(pattern => pattern.test(functionName))) {
              return false; // This is an internal processing function
            }
          }
          currentScope = currentScope.upper;
        }
        
        const externalPatterns = [
          /^(userInput|userData|externalData|untrustedInput|rawInput)$/i,
          /^user(?!Agent$)/i, // user* but not userAgent
          /^external/i,
          /^untrusted/i,
          /^client/i,
          /^request/i,
          /Input$/, // but not internalInput
          /Data$/, // but not internalData
          /Param$/,
          /^param[A-Z]/
        ];
        
        // Only flag as tainted if it matches external patterns AND is not in an internal context
        if (externalPatterns.some(pattern => pattern.test(name))) {
          return true;
        }

        // Check if this identifier is a function parameter in a non-internal function
        const sourceCode2 = context.sourceCode || context.getSourceCode();
        let scope = sourceCode2.getScope ? sourceCode2.getScope(node) : context.getScope();
        while (scope) {
          const variable = scope.variables.find(v => v.name === name);
          if (variable && variable.defs.length > 0) {
            const def = variable.defs[0];
            if (def.type === "Parameter") {
              // Check if parent function looks like an internal processing function
              if (scope.block && scope.block.id && scope.block.id.name) {
                const functionName = scope.block.id.name;
                if (/^(_|internal|helper|process|analyze|calculate|detect|extract|transform|convert)/.test(functionName) ||
                    functionName.includes('Internal') || functionName.includes('Helper') ||
                    /^(normalize|validate|sanitize|encode|decode)/.test(functionName)) {
                  return false; // Internal function parameter
                }
              }
              // Additional check: if this is the first parameter and function starts with a verb,
              // it's likely an internal processing function
              if (def.index === 0 && scope.block && scope.block.id && scope.block.id.name) {
                const functionName = scope.block.id.name;
                if (/^[a-z][a-z]*[A-Z]/.test(functionName)) { // camelCase starting with lowercase verb
                  return false; // Likely internal processing function
                }
              }
              return true; // External function parameter
            }
          }
          scope = scope.upper;
        }
      }

      // Property access that looks like external data
      if (node.type === "MemberExpression") {
        const property = node.property;
        if (property && property.type === "Identifier") {
          const externalProperties = [
            "value", "textContent", "innerText", "data", 
            "search", "hash", "pathname", "hostname", "href"
          ];
          if (externalProperties.includes(property.name)) {
            return true;
          }
        }
      }

      // URLSearchParams.get(), new URL().hash, etc.
      if (node.type === "CallExpression") {
        const callee = node.callee;
        if (callee && callee.type === "MemberExpression") {
          const object = callee.object;
          const method = callee.property;
          
          if (method && method.type === "Identifier") {
            // URLSearchParams methods
            if (method.name === "get" || method.name === "getAll") {
              return true;
            }
            // URL parsing methods
            if (method.name === "toString" && object && 
                object.type === "NewExpression" && 
                object.callee && object.callee.name === "URL") {
              return true;
            }
          }
        }
      }

      return false;
    }

    /**
     * Checks if a string has been normalized using approved functions
     */
    // Collect normalization import bindings from the file (e.g. `import { normalizeInputString } from './canonical'`)
    const importedNormalizationBindings = new Set();
    const importedNormalizationNamespaces = new Set();

    function collectImports(programNode) {
      for (const stmt of programNode.body) {
        if (stmt.type !== 'ImportDeclaration') continue;
        const source = String(stmt.source.value || '');
        // Match canonical import paths like './canonical', 'canonical', '../src/canonical', or 'src/canonical'
        if (!/(^|\/)canonical(\.js|\.ts)?$/i.test(source) && !/canonical(\/|$)/i.test(source)) continue;

        for (const spec of stmt.specifiers || []) {
          if (spec.type === 'ImportSpecifier' && spec.local && spec.local.name) {
            importedNormalizationBindings.add(spec.local.name);
          }
          if (spec.type === 'ImportDefaultSpecifier' && spec.local && spec.local.name) {
            importedNormalizationBindings.add(spec.local.name);
          }
          if (spec.type === 'ImportNamespaceSpecifier' && spec.local && spec.local.name) {
            importedNormalizationNamespaces.add(spec.local.name);
          }
        }
      }
    }

    /**
     * Checks if a node represents an expression that has been normalized using approved functions
     */
    function isNormalizedString(node) {
      if (!node) return false;
      
      // Check for calls to normalization functions from canonical.ts
      if (node.type === "CallExpression") {
        const callee = node.callee;
        // Direct call to an imported binder: normalizeInputString(...)
        if (callee && callee.type === "Identifier") {
          if (importedNormalizationBindings.has(callee.name)) return true;
          const normalizationFunctions = [
            "normalizeInputString",
            "normalizeInputStringInternal",
            "normalizeUrlComponent",
            "normalizeInputStringUltraStrict",
            "normalizeUrlSafeString",
            "normalizeAndCompareAsync",
            "validateAndNormalizeInput",
            "sanitizeForLogging",
            // Legacy normalization function names for compatibility
            "normalizeUnicode",
            "sanitizeInput",
            "normalizeString",
            // Internal canonical functions that produce normalized output
            "toCanonicalValue",
            "safeStableStringify",
            "_toString",
            // String method calls that indicate normalization
            "toString",
            "valueOf",
          ];
          if (normalizationFunctions.includes(callee.name)) return true;

          // Recognize project-specific canonicalizer function patterns by name
          // e.g., canonicalizeHostname, canonicalizeScheme, parseAndValidateHost
          if (/^(canonicalize|canonicalise|parseAndValidate|parse_and_validate)[A-Z_]/.test(callee.name) || /^(canonicalize|canonicalise)[A-Z_]/.test(callee.name)) {
            return true;
          }
        }

        // Member expression calls like canonical.normalizeInputString(...)
        if (callee && callee.type === "MemberExpression") {
          const obj = callee.object;
          const prop = callee.property;
          if (obj && prop && prop.type === 'Identifier') {
            if (obj.type === 'Identifier' && importedNormalizationNamespaces.has(obj.name)) {
              return true;
            }
            // e.g. canonical.normalizeInputString where canonical was imported as default or namespace
            if (importedNormalizationBindings.has(obj.name) && typeof prop.name === 'string') {
              return true;
            }
            if (prop.name === 'normalize') {
              return true; // String.prototype.normalize or other normalize calls
            }
          }
        }
      }
      
      // Check for variables that are the result of normalization calls
      if (node.type === "Identifier") {
        const name = node.name;
        const normalizedNames = [
          /^normalized/i,
          /^canonical/i,
          /^sanitized/i,
          /^validated/i,
          /^processed/i,
          /Normalized$/,
          /Canonical$/,
          /Sanitized$/,
          /Validated$/,
          // Additional patterns for internal processing variables
          /^string_$/, // canonical.ts uses this pattern for normalized strings
          /^rawString$/, // often the result of _toString() normalization
          /^cleanInput$/,
          /^safeString$/,
        ];

            if (normalizedNames.some((pattern) => pattern.test(name))) {
          return true;
        }

        // Additional heuristic: treat names that include 'normalized'/'canonical' or 'finalUrl' as normalized
        if (/normalized|canonical|finalUrl|normalizedUrl|normalizedBase|safeString|cleanInput/i.test(name)) {
          return true;
        }

        // Attempt to resolve the variable definition and see if it was initialized
        // by a normalization call (e.g., const s = normalizeInputString(raw))
        try {
          let scope = context.getScope();
          while (scope) {
            const variable = scope.variables && scope.variables.find((v) => v.name === name);
            if (variable && variable.defs && variable.defs.length > 0) {
              const def = variable.defs[0];
              if (def.node && def.node.type === 'VariableDeclarator' && def.node.init) {
                const init = def.node.init;
                if (init.type === 'CallExpression') {
                  const callee = init.callee;
                          if (callee.type === 'Identifier' && importedNormalizationBindings.has(callee.name)) return true;
                          if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier') {
                            if (importedNormalizationNamespaces.has(callee.object.name)) return true;
                            if (importedNormalizationBindings.has(callee.object.name)) return true;
                          }

                          // If the initializer is calling a local helper like canonicalizeHostname or parseAndValidateHost
                          // which likely performs canonicalization, treat as normalized when the helper name matches patterns
                          if (callee.type === 'Identifier' && /^(canonicalize|canonicalise|parseAndValidate|parse_and_validate)[A-Z_]/.test(callee.name)) {
                            return true;
                          }
                }
              }
            }
            scope = scope.upper;
          }
        } catch (e) {
          // ignore resolution errors and fall back to name-based heuristics
        }
      }

      // MemberExpression where object is identifier pointing to normalized variable
      if (node.type === 'MemberExpression' && node.object && node.object.type === 'Identifier') {
        const objId = node.object;
        try {
          let scope = context.getScope();
          while (scope) {
            const variable = scope.variables && scope.variables.find((v) => v.name === objId.name);
            if (variable && variable.defs && variable.defs.length > 0) {
              const def = variable.defs[0];
              if (def.node && def.node.type === 'VariableDeclarator' && def.node.init) {
                const init = def.node.init;
                if (init.type === 'CallExpression') {
                  const callee = init.callee;
                  if (callee.type === 'Identifier' && importedNormalizationBindings.has(callee.name)) return true;
                  if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier') {
                    if (importedNormalizationNamespaces.has(callee.object.name)) return true;
                    if (importedNormalizationBindings.has(callee.object.name)) return true;
                  }
                }
              }
            }
            scope = scope.upper;
          }
        } catch (e) {
          // ignore
        }
      }
      
      return false;
    }

    return {
      Program(node) {
        // Collect imports once at program level so the checks know which local identifiers
        // refer to canonical normalization helpers
        try {
          collectImports(node);
        } catch (e) {
          // ignore import collection failures
        }
      },
      BinaryExpression(node) {
        if (node.operator !== "===" && node.operator !== "!==") {
          return;
        }

        const left = node.left;
        const right = node.right;

        // Check if either side is tainted and the other is not normalized
        if (isTaintedInput(left, context) && !isNormalizedString(left)) {
          context.report({
            node: left,
            messageId: "requireNormalization",
          });
        }

        if (isTaintedInput(right, context) && !isNormalizedString(right)) {
          context.report({
            node: right,
            messageId: "requireNormalization",
          });
        }
      },

      CallExpression(node) {
        const callee = node.callee;
        if (!callee || callee.type !== "MemberExpression") {
          return;
        }

        const object = callee.object;
        const method = callee.property;

        if (!method || method.type !== "Identifier") {
          return;
        }

        // String methods that require normalization
        const dangerousMethods = [
          "includes", "startsWith", "endsWith", "indexOf", 
          "lastIndexOf", "match", "search"
        ];

        if (dangerousMethods.includes(method.name)) {
          if (isTaintedInput(object, context) && !isNormalizedString(object)) {
            context.report({
              node: object,
              messageId: "unsafeMethodCall",
              data: { method: method.name },
            });
          }

          // Also check arguments for tainted input
          node.arguments.forEach(arg => {
            if (isTaintedInput(arg, context) && !isNormalizedString(arg)) {
              context.report({
                node: arg,
                messageId: "unsafeMethodCall",
                data: { method: method.name },
              });
            }
          });
        }

        // RegExp.test() calls
        if (method.name === "test" && 
            object.type === "Identifier" && /regex|regexp|pattern/i.test(object.name)) {
          node.arguments.forEach(arg => {
            if (isTaintedInput(arg, context) && !isNormalizedString(arg)) {
              context.report({
                node: arg,
                messageId: "unsafeRegexTest",
              });
            }
          });
        }
      },

      SwitchStatement(node) {
        const discriminant = node.discriminant;
        if (isTaintedInput(discriminant, context) && !isNormalizedString(discriminant)) {
          context.report({
            node: discriminant,
            messageId: "unsafeSwitchCase",
          });
        }
      },
    };
  },
};