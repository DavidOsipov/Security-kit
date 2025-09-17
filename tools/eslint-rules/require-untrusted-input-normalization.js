/**
 * @fileoverview ESLint rule: require-untrusted-input-normalization
 * Ensures that all untrusted UTF-8 (string) input is explicitly normalized via
 * canonical.ts helpers (normalizeInputString / validateAndNormalizeInput / normalizeInputStringUltraStrict)
 * before being used in sensitive sinks (assignment to exported constants, object properties
 * passed across trust boundaries, function returns, or parameter propagation to other modules).
 *
 * Rationale:
 *  - Prevents Unicode normalization attacks, homoglyph spoofing, bidi/invisible control injection.
 *  - Codifies mandatory normalization boundary (Security Constitution § Unicode Hardening, ASVS V5.1.4).
 *
 * Heuristics (conservative to minimize false negatives; may produce some FPs initially):
 *  - Treat function parameters as untrusted unless function name matches internal processing patterns
 *    (similar to no-un-normalized-string-comparison rule) OR the parameter is immediately normalized.
 *  - Track identifiers that become normalized (result of call to approved normalization helpers or
 *    have naming pattern /^normalized|canonical|sanitized/).
 *  - Flag when an untrusted identifier (tainted) is:
 *      a) Returned directly from a function.
 *      b) Passed as an argument to another call (propagation) without being normalized first.
 *      c) Assigned to an exported variable/property (module boundary exposure).
 *      d) Used as a template literal expression or concatenated (binary +) with other strings
 *         (indicates preparation for output/logging/serialization) without normalization.
 *
 * Approved normalization helpers (customizable in future):
 *  - normalizeInputString
 *  - validateAndNormalizeInput
 *  - normalizeInputStringUltraStrict
 *  - sanitizeForLogging (treated as producing normalized output for sinks, though not a strict validator)
 *
 * Limitations:
 *  - This rule is heuristic; deep inter-procedural flow is not modeled.
 *  - Focuses on direct usage in same file. Cross-file propagation relies on boundary export checks.
 *
 * Future Enhancements (documented for maintainers):
 *  - Option to configure extra approved helper names.
 *  - Taint spreading through simple assignments and destructuring.
 */
export default {
  meta: {
    type: 'problem',
    docs: {
      description: 'Require canonical normalization of untrusted UTF-8 input using canonical.ts helpers',
      recommended: true,
    },
    schema: [
      {
        type: 'object',
        additionalProperties: false,
        properties: {
          ignoreFiles: { type: 'array', items: { type: 'string' } },
          approvedFunctions: { type: 'array', items: { type: 'string' } },
          taintNamePattern: { type: 'string' },
          internalFunctionPattern: { type: 'string' },
          maxReportsPerFile: { type: 'number', minimum: 1 },
          nestedObjectArrayDepth: { type: 'number', minimum: 0 },
          strictDirectories: { type: 'array', items: { type: 'string' } },
          strictApprovedFunctions: { type: 'array', items: { type: 'string' } },
        },
      },
    ],
    messages: {
      unnormalizedReturn: 'Function returns untrusted string without normalization. Wrap with normalizeInputString() or validateAndNormalizeInput().',
      unnormalizedArg: 'Passing untrusted string to function without prior normalization.',
      unnormalizedExport: 'Exported value derived from untrusted input must be normalized via canonical.ts.',
      unnormalizedConcat: 'Untrusted string used in concatenation/template without normalization.',
    },
  },
  create(context) {
    const filename = String(context.getFilename() || '');
  const options = context.options && context.options[0] ? context.options[0] : {};
    const ignoreFiles = Array.isArray(options.ignoreFiles) ? options.ignoreFiles : [];
    const maxReports = typeof options.maxReportsPerFile === 'number' ? options.maxReportsPerFile : 80; // cap noise
    let reportCount = 0;

    // Canonical ignore defaults + user configured patterns
    const defaultIgnore = [ 'canonical.ts' ];
    const ignorePatterns = [...defaultIgnore, ...ignoreFiles];
    if (ignorePatterns.some((p) => filename.includes(p)) || /(tests|demo|benchmarks|scripts|tools)\//.test(filename)) {
      return {};
    }

    // -------- Helper predicates --------
    // Base approved functions (standard mode)
    const BASE_APPROVED = [
      'normalizeInputString',
      'validateAndNormalizeInput',
      'normalizeInputStringUltraStrict',
      'sanitizeForLogging',
      'normalizeAndCompareAsync',
    ];
    // Strict mode: only allow ultra-strict canonicalization helpers unless extended by config
    const STRICT_DEFAULT = [ 'normalizeInputStringUltraStrict' ];
    const strictDirs = Array.isArray(options.strictDirectories) ? options.strictDirectories : [];
    const inStrictDir = strictDirs.some((d) => filename.includes(d));
    const APPROVED_FUNCTIONS = new Set(inStrictDir ? STRICT_DEFAULT : BASE_APPROVED);
    if (Array.isArray(options.approvedFunctions) && !inStrictDir) {
      for (const fn of options.approvedFunctions) if (typeof fn === 'string') APPROVED_FUNCTIONS.add(fn);
    }
    if (Array.isArray(options.strictApprovedFunctions) && inStrictDir) {
      for (const fn of options.strictApprovedFunctions) if (typeof fn === 'string') APPROVED_FUNCTIONS.add(fn);
    }
    if (Array.isArray(options.approvedFunctions)) {
      for (const fn of options.approvedFunctions) {
        if (typeof fn === 'string') APPROVED_FUNCTIONS.add(fn);
      }
    }

    const internalFnRegex = new RegExp(
      options.internalFunctionPattern || '^(normalize|validate|sanitize|encode|decode|parse|build|create|update|analyze|calculate|detect|extract|generate|process|transform|convert|canonicalize|assert|is[A-Z]|toCanonical)'
    );
    function isInternalFunctionName(name) {
      return internalFnRegex.test(name);
    }

    // Collect imported canonical helpers (import {...} from './canonical')
    const importedNormalizationBindings = new Set();
    function collectImports(programNode) {
      for (const stmt of programNode.body) {
        if (stmt.type !== 'ImportDeclaration') continue;
        const source = String(stmt.source.value || '');
        if (!/(^|\/)canonical(\.js|\.ts)?$/i.test(source) && !/canonical(\/|$)/i.test(source)) continue;
        for (const spec of stmt.specifiers || []) {
          if (spec.type === 'ImportSpecifier' && spec.local && spec.local.name) {
            importedNormalizationBindings.add(spec.local.name);
          }
          if (spec.type === 'ImportNamespaceSpecifier' && spec.local && spec.local.name) {
            importedNormalizationBindings.add(spec.local.name);
          }
          if (spec.type === 'ImportDefaultSpecifier' && spec.local && spec.local.name) {
            importedNormalizationBindings.add(spec.local.name);
          }
        }
      }
    }

    // Track identifiers considered normalized
  const normalizedIds = new Set();
  const resultObjectIds = new Set(); // e.g., result from validateAndNormalizeInput

    function markNormalized(idName) {
      if (idName) normalizedIds.add(idName);
    }

    function isNormalizationCall(node) {
      if (!node || node.type !== 'CallExpression') return false;
      const callee = node.callee;
      if (callee.type === 'Identifier') {
        // Only treat as normalization if explicitly approved (import alone is insufficient in strict mode)
        if (APPROVED_FUNCTIONS.has(callee.name)) return true;
      }
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
        if (APPROVED_FUNCTIONS.has(callee.property.name)) return true;
        // treat .normalize() string method as normalization
        if (callee.property.name === 'normalize') return true;
      }
      return false;
    }


    const taintNameRegex = new RegExp(options.taintNamePattern || '^(raw|user|external|untrusted|input|param|arg|data|payload|body|value|text)');
    function isTaintedIdentifierName(name) {
      if (!name) return false;
      if (normalizedIds.has(name)) return false;
      if (taintNameRegex.test(name)) return true;
      return false;
    }

    // Map from identifier name -> isTainted (updated as we see params & assignments)
    const tainted = new Map();

    function markTainted(name) {
      if (!name || normalizedIds.has(name)) return;
      tainted.set(name, true);
    }

    function isTaintedIdentifier(node) {
      if (!node || node.type !== 'Identifier') return false;
      if (normalizedIds.has(node.name)) return false;
      return tainted.get(node.name) === true || isTaintedIdentifierName(node.name);
    }

    // Record variable declarators that are initialized with normalization calls
    function handleVariableDeclarator(node) {
      if (!node.id || node.id.type !== 'Identifier') return;
      const name = node.id.name;
      const init = node.init;
      if (init) {
        if (isNormalizationCall(init)) {
          markNormalized(name);
          tainted.delete(name);
          if (init.callee && init.callee.type === 'Identifier' && init.callee.name === 'validateAndNormalizeInput') {
            // track result object for member access (.value) normalization
            resultObjectIds.add(name);
          }
        } else if (init.type === 'ArrayExpression') {
          // Propagate taint if any element (or spread element) is tainted
          for (const el of init.elements) {
            if (!el) continue;
            if (el.type === 'Identifier' && isTaintedIdentifier(el)) { markTainted(name); break; }
            if (el.type === 'SpreadElement' && el.argument.type === 'Identifier' && isTaintedIdentifier(el.argument)) { markTainted(name); break; }
          }
        } else if (init.type === 'ObjectExpression') {
          for (const prop of init.properties) {
            if (prop.type !== 'Property') continue;
            const v = prop.value;
            if (v.type === 'Identifier' && isTaintedIdentifier(v)) { markTainted(name); break; }
            if (v.type === 'TemplateLiteral') {
              for (const expr of v.expressions) {
                if (expr.type === 'Identifier' && isTaintedIdentifier(expr)) { markTainted(name); break; }
              }
            }
          }
        } else if (init.type === 'Identifier' && isTaintedIdentifier(init)) {
          // Propagate taint
          markTainted(name);
        } else if (init.type === 'CallExpression') {
          // If argument is tainted and not normalized, propagate taint
            for (const arg of init.arguments) {
              if (arg.type === 'Identifier' && isTaintedIdentifier(arg) && !isNormalizationCall(init)) {
                markTainted(name);
              }
            }
        } else if (isTaintedIdentifier(init)) {
          markTainted(name);
        }
      }
      // Name-based normalization heuristics
      if (/^(normalized|canonical|sanitized)/i.test(name)) {
        markNormalized(name);
        tainted.delete(name);
      }
    }

    function safeReport(descriptor) {
      if (reportCount >= maxReports) return; // cap to reduce noise
      context.report(descriptor);
      reportCount += 1;
    }


    const maxNestedDepth = typeof options.nestedObjectArrayDepth === 'number' ? options.nestedObjectArrayDepth : 2;

    function scanNested(node, depth, reportMessageId) {
      if (!node || depth < 0) return;
      switch (node.type) {
        case 'Identifier':
          if (isTaintedIdentifier(node)) {
            safeReport({ node, messageId: reportMessageId });
          }
          break;
        case 'TemplateLiteral':
          for (const expr of node.expressions) scanNested(expr, depth, reportMessageId);
          break;
        case 'ArrayExpression':
          if (depth === 0) return;
            for (const el of node.elements) {
              if (!el) continue;
              if (el.type === 'SpreadElement') {
                scanNested(el.argument, depth - 1, reportMessageId);
              } else {
                scanNested(el, depth - 1, reportMessageId);
              }
            }
          break;
        case 'ObjectExpression':
          if (depth === 0) return;
          for (const prop of node.properties) {
            if (prop.type !== 'Property') continue;
            scanNested(prop.value, depth - 1, reportMessageId);
          }
          break;
        case 'CallExpression':
          // treat deeper call arguments as potential propagation sinks
          if (!isNormalizationCall(node)) {
            for (const arg of node.arguments) scanNested(arg, depth - 1, 'unnormalizedArg');
          }
          break;
        default:
          break;
      }
    }

    function handleReturnStatement(node) {
      const arg = node.argument;
      if (!arg) return;
      scanNested(arg, maxNestedDepth, 'unnormalizedReturn');
    }

    function handleBinaryExpression(node) {
      if (node.operator !== '+') return;
      const left = node.left;
      const right = node.right;
      const parts = [left, right];
      for (const p of parts) {
        if (p.type === 'Identifier' && isTaintedIdentifier(p)) {
          safeReport({ node: p, messageId: 'unnormalizedConcat' });
        }
        if (p.type === 'TemplateLiteral') {
          for (const expr of p.expressions) {
            if (expr.type === 'Identifier' && isTaintedIdentifier(expr)) {
              safeReport({ node: expr, messageId: 'unnormalizedConcat' });
            }
          }
        }
      }
    }

    function handleTemplateLiteral(node) {
      for (const expr of node.expressions) {
        if (expr.type === 'Identifier' && isTaintedIdentifier(expr)) {
          safeReport({ node: expr, messageId: 'unnormalizedConcat' });
        }
      }
    }

    function handleAssignmentExpression(node) {
      // If assigning tainted to export or module-level property
      if (node.right && node.right.type === 'Identifier' && isTaintedIdentifier(node.right)) {
        // Detect export (module.exports / exports.* or ES export const)
        const left = node.left;
        if (left.type === 'MemberExpression') {
          const obj = left.object;
          if (obj.type === 'Identifier' && (obj.name === 'exports' || obj.name === 'module')) {
            safeReport({ node: node.right, messageId: 'unnormalizedExport' });
          }
        }
      }
    }

    function handleExportNamedDeclaration(node) {
      if (!node.declaration) return;
      if (node.declaration.type === 'VariableDeclaration') {
        for (const decl of node.declaration.declarations) {
          if (decl.init && decl.init.type === 'Identifier' && isTaintedIdentifier(decl.init)) {
            safeReport({ node: decl.init, messageId: 'unnormalizedExport' });
          }
        }
      } else if (node.declaration.type === 'FunctionDeclaration') {
        // If function directly returns tainted input (detected in ReturnStatement)
      }
    }

    return {
      Program(node) {
  try { collectImports(node); } catch (_e) { /* ignore import parse issues; non-fatal */ }
        // Initialize taint from function parameters (done later per function) but can mark top-level const assignments after normalization
      },
      FunctionDeclaration(node) {
        const name = node.id && node.id.name ? node.id.name : '';
        const internal = isInternalFunctionName(name);
        if (node.params) {
          for (const p of node.params) {
            if (p.type === 'Identifier' && !internal) {
              markTainted(p.name);
            }
          }
        }
      },
      ArrowFunctionExpression(node) {
        // Attempt to derive name from parent variable declarator
        let name = '';
        if (node.parent && node.parent.type === 'VariableDeclarator' && node.parent.id.type === 'Identifier') {
          name = node.parent.id.name;
        }
        const internal = isInternalFunctionName(name);
        for (const p of node.params || []) {
          if (p.type === 'Identifier' && !internal) markTainted(p.name);
        }
      },
      VariableDeclarator: handleVariableDeclarator,
      CallExpression(node) {
        // Mark variable on left side of assignment when normalization call is used inside initializer handled by VariableDeclarator already.
        // For calls, check arguments for taint propagation.
        for (const arg of node.arguments) {
          if (arg.type === 'Identifier' && isTaintedIdentifier(arg)) {
            // If the callee itself is not a normalization function, flag usage
            if (!isNormalizationCall(node)) {
              safeReport({ node: arg, messageId: 'unnormalizedArg' });
            }
          }
          if (arg.type === 'TemplateLiteral') {
            for (const expr of arg.expressions) {
              if (expr.type === 'Identifier' && isTaintedIdentifier(expr) && !isNormalizationCall(node)) {
                safeReport({ node: expr, messageId: 'unnormalizedArg' });
              }
            }
          }
        }
      },
      MemberExpression(node) {
        // Treat obj.value where obj is result of validateAndNormalizeInput as normalized sink usage
        if (node.object && node.object.type === 'Identifier' && node.property && node.property.type === 'Identifier' && node.property.name === 'value') {
          if (resultObjectIds.has(node.object.name)) {
            markNormalized(node.object.name + '.value'); // pseudo marker
          }
        }
      },
      ReturnStatement: handleReturnStatement,
      BinaryExpression: handleBinaryExpression,
      TemplateLiteral: handleTemplateLiteral,
      AssignmentExpression: handleAssignmentExpression,
      ExportNamedDeclaration: handleExportNamedDeclaration,
    };
  },
};
