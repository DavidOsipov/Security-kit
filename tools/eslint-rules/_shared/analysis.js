/**
 * @fileoverview Shared utility functions for ESLint rules in the security-kit.
 * Provides common analysis helpers for alias detection, secret name matching,
 * global reference checking, and basic taint analysis.
 *
 * These utilities reduce code duplication across rules and enable consistent
 * behavior for evasion detection (aliasing, scoping).
 */

const SECRET_RE = /token|secret|key|password|jwt|credential|bearer|hash|signature|mac|nonce|iv|salt/i;

/**
 * Checks if a variable name suggests it contains sensitive data.
 * @param {string} name - The variable name to check.
 * @returns {boolean} True if the name matches secret patterns.
 */
export function isSecretName(name) {
  return SECRET_RE.test(name);
}

/**
 * Resolves the full member expression name (e.g., 'crypto.subtle.digest').
 * @param {Object} node - The AST node (MemberExpression).
 * @returns {string|null} The full dotted name or null if not resolvable.
 */
export function resolveFullMemberName(node) {
  if (!node || node.type !== 'MemberExpression') return null;

  const parts = [];
  let current = node;

  while (current && current.type === 'MemberExpression') {
    if (current.property && current.property.type === 'Identifier') {
      parts.unshift(current.property.name);
    }
    current = current.object;
  }

  if (current && current.type === 'Identifier') {
    parts.unshift(current.name);
  }

  return parts.length > 1 ? parts.join('.') : null;
}

/**
 * Checks if an identifier refers to a global object (not shadowed by local scope).
 * @param {Object} context - ESLint context.
 * @param {Object} identifierNode - The Identifier AST node.
 * @param {string} expectedName - The expected global name (e.g., 'console').
 * @returns {boolean} True if it's a global reference.
 */
export function isGlobalReference(context, identifierNode, expectedName) {
  if (!identifierNode || identifierNode.type !== 'Identifier') return false;
  if (identifierNode.name !== expectedName) return false;

  // Check if it's declared in the current scope or upper scopes
  let scope = context.getScope(identifierNode);
  while (scope) {
    const variable = scope.variables.find(v => v.name === expectedName);
    if (variable) {
      // If declared in this scope, it's not global
      return false;
    }
    scope = scope.upper;
  }

  // Not found in any scope, so it's global
  return true;
}

/**
 * Collects aliases for global objects (e.g., const c = console).
 * @param {Object} context - ESLint context.
 * @param {string[]} rootNames - Array of global names to track (e.g., ['console', 'crypto']).
 * @returns {Map<string, string[]>} Map of root name to array of alias names.
 */
export function collectAliases(context, rootNames = ['console', 'crypto', 'process']) {
  const aliases = new Map();

  // Initialize map
  rootNames.forEach(name => aliases.set(name, []));

  // Walk the AST to find assignments
  const sourceCode = context.sourceCode || context.getSourceCode();
  const program = sourceCode.ast;

  function traverse(node) {
    if (!node) return;

    // Check for variable declarations: const alias = globalName
    if (node.type === 'VariableDeclarator' &&
        node.id && node.id.type === 'Identifier' &&
        node.init && node.init.type === 'Identifier') {
      const aliasName = node.id.name;
      const initName = node.init.name;
      if (rootNames.includes(initName)) {
        aliases.get(initName).push(aliasName);
      }
    }

    // Recursively traverse children
    for (const key in node) {
      if (key === 'type' || key === 'parent') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(traverse);
      } else if (child && typeof child === 'object') {
        traverse(child);
      }
    }
  }

  traverse(program);
  return aliases;
}

/**
 * Checks if an identifier is likely from external input (simple heuristic).
 * @param {Object} identifier - The Identifier AST node.
 * @param {Object} context - ESLint context.
 * @returns {boolean} True if likely external.
 */
export function isLikelyExternalParam(identifier, context) {
  if (!identifier || identifier.type !== 'Identifier') return false;

  // Check if it's a function parameter (only if getScope is available)
  if (typeof context.getScope === 'function') {
    try {
      let scope = context.getScope(identifier);
      while (scope) {
        const variable = scope.variables.find(v => v.name === identifier.name);
        if (variable && variable.defs.length > 0) {
          const def = variable.defs[0];
          if (def.type === 'Parameter') {
            return true;
          }
        }
        scope = scope.upper;
      }
    } catch (e) {
      // getScope not available in test environment, continue with heuristics
    }
  }

  // Additional heuristics: naming patterns
  const externalPatterns = [
    /^(input|data|value|param|arg|query|search|filter|term)$/i,
    /^user/i,
    /^external/i,
    /^raw/i,
    /Input$/,
    /Data$/,
    /Param$/,
    /^(req|request)$/i,
    /^body$/i,
    /^payload$/i,
  ];

  return externalPatterns.some(pattern => pattern.test(identifier.name));
}

/**
 * Checks if a node represents a logging function call (handles aliases).
 * @param {Object} node - The CallExpression AST node.
 * @param {Object} context - ESLint context.
 * @param {string[]} allowedMethods - Array of allowed console methods.
 * @param {Map<string, string[]>} aliases - Map of aliases from collectAliases.
 * @returns {boolean} True if it's a logging call.
 */
export function isLoggingCall(node, context, allowedMethods, aliases) {
  if (!node || node.type !== 'CallExpression') return false;

  // Direct console.method
  if (node.callee?.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' &&
      node.callee.object.name === 'console' &&
      node.callee.property?.type === 'Identifier') {
    const method = node.callee.property.name;
    return true; // Always return true for console methods
  }

  // Alias usage: alias.method
  if (node.callee?.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' &&
      node.callee.property?.type === 'Identifier') {
    const aliasName = node.callee.object.name;
    const method = node.callee.property.name;
    // Check if aliasName is an alias for console
    const consoleAliases = aliases.get('console') || [];
    if (consoleAliases.includes(aliasName)) {
      return true;
    }
  }

  // Direct identifier call (destructured console methods)
  if (node.callee?.type === 'Identifier') {
    const methodName = node.callee.name;
    // Check if this identifier was destructured from console
    const sourceCode = context.sourceCode || context.getSourceCode();
    const program = sourceCode.ast;
    
    function findDestructuredConsole(identifier) {
      function traverse(n) {
        if (!n) return false;
        
        // Check for destructuring: const { log } = console
        if (n.type === 'VariableDeclarator' &&
            n.id && n.id.type === 'ObjectPattern' &&
            n.init && n.init.type === 'Identifier' && n.init.name === 'console') {
          // Check if our method is in the destructured properties
          for (const property of n.id.properties) {
            if (property.type === 'Property' &&
                property.key.type === 'Identifier' &&
                property.key.name === methodName) {
              return true;
            }
          }
        }
        
        // Recursively traverse
        for (const key in n) {
          if (key === 'type' || key === 'parent') continue;
          const child = n[key];
          if (Array.isArray(child)) {
            if (child.some(traverse)) return true;
          } else if (child && typeof child === 'object') {
            if (traverse(child)) return true;
          }
        }
        return false;
      }
      
      return traverse(program);
    }
    
    if (findDestructuredConsole(node.callee)) {
      return true;
    }
  }

  return false;
}
