/**
 * @fileoverview ESLint rule: no-unsafe-object-merge
 * Prevents unsafe object merging/spreading that could lead to prototype pollution attacks.
 * Requires use of safe merging utilities like toNullProto or explicit sanitization.
 *
 * OWASP ASVS V5.1.3: Input validation consistency, prototype pollution prevention
 * Security Constitution: Hardened input validation
 */

import { isLikelyExternalParam } from './_shared/analysis.js';

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Prevent unsafe object merging that could lead to prototype pollution",
      recommended: true,
    },
    schema: [
      {
        type: "object",
        properties: {
          allowedFiles: {
            type: "array",
            items: { type: "string" },
            description: "File patterns where unsafe merges are allowed"
          },
          safeMergeFunctions: {
            type: "array",
            items: { type: "string" },
            description: "Functions that safely merge objects"
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      unsafeObjectSpread: "Unsafe object spread from external input {{source}}. Use toNullProto() or safe merge utility to prevent prototype pollution.",
      unsafeObjectAssign: "Unsafe Object.assign with external input {{source}}. Use safe merge utility instead.",
      suggestSafeMerge: "Use: Object.assign(toNullProto({}), {{source}}) or safe merge utility",
      suggestSpreadFix: "Use: { ...toNullProto({{source}}) }"
    },
  // fixable removed to prevent unsafe automated edits; rule is error-only
  },

  create(context) {
    const options = context.options[0] || {};
    const allowedFiles = options.allowedFiles || [
      "/tests/",
      "/test/",
      "/demo/",
      "/benchmarks/"
    ];
    const safeMergeFunctions = new Set(options.safeMergeFunctions || [
      "toNullProto",
      "sanitizePlainObject",
      "safeMerge",
      "mergeObjects"
    ]);

    const filename = context.getFilename() || "";

    // Skip if file is in allowed patterns
    if (allowedFiles.some(pattern => filename.includes(pattern))) {
      return {};
    }

    // Track reported nodes to prevent duplicate errors
    const reportedNodes = new Set();

    /**
     * Check if a node is already wrapped in a safe function
     */
    function isSafe(node) {
      if (!node) return false;

      // Check for call expressions wrapping the node
      if (node.type === "CallExpression" && node.callee?.name) {
        return safeMergeFunctions.has(node.callee.name);
      }

      // Check for spread in safe context
      if (node.type === "SpreadElement" && node.argument) {
        return isSafe(node.argument);
      }

      return false;
    }

    /**
     * Check if identifier represents external input
     */
    function isExternalInput(node) {
      if (node.type === "Identifier") {
        const name = node.name || '';
        const lower = name.toLowerCase();

        // If it looks explicitly like user-supplied or external, treat as external
        if (/^user/i.test(name) || /^external/i.test(name) || /^raw/i.test(name)) return true;

        // Exact common external names
        const externalNames = ['userinput', 'req', 'request', 'input', 'payload', 'body', 'params', 'query', 'userdata', 'data', 'externaldata'];
        if (externalNames.includes(lower)) return true;

  // If identifier contains 'local' it's very likely a local/internal variable -> treat as not external
  if (/local/i.test(name)) return false;

  // Function parameter heuristics
  if (isLikelyExternalParam(node, context)) return true;

        // If it ends with Input/Param/Data it is likely external, but exclude common local patterns
        if ((/Input$|Param$|Data$/i).test(name)) {
          // If it's clearly local (contains 'local' or starts with 'local'), treat as local
          if (/\blocal\b/i.test(name) || /^local/i.test(name) || /local/i.test(name)) return false;
          return true;
        }

        // Otherwise, treat as not external by default
      }
      return false;
    }

    return {
      // Object spread: { ...externalInput }
      SpreadElement(node) {
        if (isExternalInput(node.argument) && !isSafe(node.argument) && !reportedNodes.has(node)) {
          reportedNodes.add(node);
          context.report({
            node,
            messageId: "unsafeObjectSpread",
            data: { source: node.argument.name }
          });
        }
      },

      // Object.assign(target, ...sources)
      CallExpression(node) {
        if (node.callee?.type === "MemberExpression" &&
            node.callee.object?.name === "Object" &&
            node.callee.property?.name === "assign") {

          // Check each argument after the first (target)
          node.arguments.slice(1).forEach(arg => {
            if (isExternalInput(arg) && !isSafe(arg) && !reportedNodes.has(arg)) {
              reportedNodes.add(arg);
              context.report({
                node: arg,
                messageId: "unsafeObjectAssign",
                data: { source: arg.name }
              });
            }
          });
        }
      },

      // Variable assignment with spread: const obj = { ...externalInput }
      VariableDeclarator(node) {
        if (node.init?.type === "ObjectExpression") {
          node.init.properties.forEach(prop => {
            if (prop.type === "SpreadElement" &&
                isExternalInput(prop.argument) &&
                !isSafe(prop.argument) &&
                !reportedNodes.has(prop)) {
              reportedNodes.add(prop);
              context.report({
                node: prop,
                messageId: "unsafeObjectSpread",
                data: { source: prop.argument.name }
              });
            }
          });
        }
      }
    };
  }
};