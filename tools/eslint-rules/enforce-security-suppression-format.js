/**
 * @fileoverview ESLint rule: enforce-security-suppression-format
 * Enforces proper format for suppressing security-related ESLint rules.
 * Requires justification comments and proper formatting for security rule suppressions.
 *
 * Security Constitution §1.4: Fail Loudly, Fail Safely
 */

export default {
  meta: {
    type: "problem",
    docs: {
      description: "Enforce proper format for suppressing security-related ESLint rules",
      recommended: false,
    },
    schema: [
      {
        type: "object",
        properties: {
          securityRulePrefixes: {
            type: "array",
            items: { type: "string" },
            description: "Prefixes for security-related rule names",
            default: ["no-secret", "enforce-security", "no-plaintext", "no-unsafe"]
          },
          requireJustification: {
            type: "boolean",
            description: "Whether to require justification comments",
            default: true
          },
          justificationKeywords: {
            type: "array",
            items: { type: "string" },
            description: "Required keywords in justification comments",
            default: ["SECURITY", "REVIEWED", "SAFE", "ENCRYPTED", "VALIDATED"]
          }
        },
        additionalProperties: false
      }
    ],
    messages: {
      invalidSuppressionFormat:
        "Security rule suppression '{{ruleName}}' must include justification comment with required keywords.",
      missingSuppressionComment:
        "Security rule '{{ruleName}}' suppression requires explanatory comment on the same line or previous line.",
      insecureSuppression:
        "Suppression of security rule '{{ruleName}}' should include security review justification.",
      suggestProperSuppression:
        "Use: /* SECURITY: [justification] */ eslint-disable-next-line {{ruleName}}"
    },
  },

  create(context) {
    const options = context.options[0] || {};
    // If rule prefixes provided in options, use them; otherwise use a conservative default set
    const securityRulePrefixes = Array.isArray(options.securityRulePrefixes)
      ? options.securityRulePrefixes
      : ["no-secret", "enforce-security", "no-plaintext", "no-unsafe", "no-date-entropy", "no-undef"];
    const requireJustification = options.requireJustification !== false;
    const justificationKeywords = options.justificationKeywords || [
      "SECURITY", "REVIEWED", "SAFE", "ENCRYPTED", "VALIDATED", "AUDITED"
    ];

    // Skip tests and scripts
    const filename = String(context.getFilename() || "");
    if (/\btests?\b|\/scripts\/|\/demo\/|\/benchmarks\//i.test(filename)) {
      return {};
    }

    /**
     * Check if a rule name is security-related
     */
    function isSecurityRule(ruleName) {
      return securityRulePrefixes.some(prefix => ruleName.startsWith(prefix));
    }

    /**
     * Check if a comment contains required justification keywords
     */
    function hasJustification(comment, allComments) {
      // Only accept justification if it's an explicit justification comment
      // immediately preceding the suppression comment (previous line). We do
      // NOT accept inline code after the disable directive as justification.
      const commentLine = comment.loc.start.line;

      // Check previous-line comments only
      for (const otherComment of allComments) {
        if (otherComment === comment) continue;
        const otherLine = otherComment.loc.start.line;
        if (otherLine === commentLine - 1) {
          const otherText = String(otherComment.value || '').toUpperCase();
          if (hasSecurityKeyword(otherText)) return true;
        }
      }

      return false;
    }

    /**
     * Check if text contains security justification keywords as meaningful words
     */
    function hasSecurityKeyword(text) {
      // Check for keyword followed by colon (indicating justification) or standalone keyword
      // but not preceded by negative words like "without", "no", "not"
      return justificationKeywords.some(keyword => {
        // Pattern for keyword with colon (justification format)
        const colonRegex = new RegExp(`\\b${keyword}\\s*:\\s*`, 'i');
        if (colonRegex.test(text)) return true;
        
        // Pattern for standalone keyword, but avoid negative contexts
        const wordRegex = new RegExp(`\\b(?:without|no|not)\\s+\\w*\\s*\\b${keyword}\\b`, 'i');
        if (wordRegex.test(text)) return false; // Negative context
        
        // Check for positive standalone keyword
        const positiveWordRegex = new RegExp(`\\b${keyword}\\b`, 'i');
        return positiveWordRegex.test(text);
      });
    }

    /**
     * Extract security rules from eslint-disable comment
     */
    function extractSecurityRules(commentValue) {
      // First, find the directive and capture the rest of the comment after it
      const directiveMatch = commentValue.match(/eslint-disable(?:-next-line)?(.*)/i);
      if (!directiveMatch) return [];

      // Remove any trailing human-readable description introduced with '--'
      let afterDirective = String(directiveMatch[1] || '').trim();
      const descIndex = afterDirective.indexOf('--');
      if (descIndex !== -1) afterDirective = afterDirective.slice(0, descIndex).trim();

      // If the remaining text contains code-like tokens (e.g., 'const', '=', ';'),
      // treat it as a comment that embeds code and do not attempt to parse it as
      // an eslint disable directive. This prevents amplifying ESLint's own
      // diagnostics for malformed directives that include code.
      // Detect obvious code-like tokens (keywords or punctuation) after the directive
      const codeLikePattern = /\b(?:const|let|var)\b|[;={}()]/i;
      if (codeLikePattern.test(afterDirective)) {
        return [];
      }

      // Now extract the comma-separated rule list from the cleaned text
      const ruleListMatch = afterDirective.match(/([a-zA-Z0-9-]+(?:\s*,\s*[a-zA-Z0-9-]+)*)/);
      if (!ruleListMatch) return [];
      const ruleList = ruleListMatch[1];
      return ruleList.split(',')
        .map(rule => rule.trim())
        .filter(rule => rule && isSecurityRule(rule));
    }

    return {
      Program(_node) {
        const sourceCode = context.getSourceCode();
        const comments = sourceCode.getAllComments();

        // Track processed suppressions to avoid duplicates
        const processedSuppressions = new Set();

        // Process all comments for suppressions
        for (const comment of comments) {
          const rules = extractSecurityRules(comment.value);
          if (rules.length > 0) {
            // Create a unique key for this suppression to avoid duplicates
            const suppressionKey = `${comment.loc.start.line}:${comment.loc.start.column}`;

            if (!processedSuppressions.has(suppressionKey)) {
              processedSuppressions.add(suppressionKey);

              if (requireJustification && !hasJustification(comment, comments)) {
                // Report each rule separately but only once per suppression
                for (const rule of rules) {
                  // DEBUG disabled
                  context.report({
                    node: comment,
                    messageId: "invalidSuppressionFormat",
                    data: { ruleName: rule }
                  });
                }
              }
            }
          }
        }
      }
    };
  },
};