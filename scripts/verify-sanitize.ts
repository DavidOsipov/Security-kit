#!/usr/bin/env node
/*
  Developer-only verifier: uses the ESLint Node API and AST parsing
  for precise, non-runtime checks. This script is not part of
  production code.
*/
/*
  TypeScript replacement for the dev-only verify-sanitize script.
  Uses the ESLint Node API to analyze repository source files without
  performing non-literal fs reads or dynamic object injection patterns.

  This file intentionally runs as a developer utility; it is not part
  of production code.
*/
import path from "path";
import { ESLint } from "eslint";
import { parse } from "@typescript-eslint/parser";

const CHILD_KEYS = [
  "test",
  "expression",
  "body",
  "arguments",
  "callee",
  "declarations",
  "init",
  "left",
  "right",
  "consequent",
  "alternate",
  "params",
  "property",
  "object",
  "value",
  "key",
  "elements",
  "properties",
];

function isDevIdentifierNode(n: any) {
  return n && n.type === "Identifier" && n.name === "isDevelopment";
}

function isEnvironmentIsProductionNode(n: any) {
  return n && n.type === "MemberExpression" && isMemberAccess(n, "environment", "isProduction");
}

function isIdentifier(node: any, name: string) {
  return node && node.type === "Identifier" && node.name === name;
}

function isMemberAccess(node: any, objectName: string, propertyName: string) {
  if (!node || node.type !== "MemberExpression") return false;
  const obj = node.object;
  const prop = node.property;
  if (obj && obj.type === "Identifier" && obj.name === objectName) {
    if (prop && prop.type === "Identifier" && prop.name === propertyName) return true;
    if (prop && prop.type === "Literal" && prop.value === propertyName) return true;
  }
  return false;
}

function nodeContainsDevGuard(node: any) {
  if (!node || typeof node !== "object") return false;
  const seen = new Set<any>();
  const stack = [node];
  while (stack.length) {
    const n = stack.pop();
    if (!n || typeof n !== "object" || seen.has(n)) continue;
    seen.add(n);
    if (isDevIdentifierNode(n)) return true;
    if (isEnvironmentIsProductionNode(n)) return true;
    iterateChildNodes(n, (c) => {
      stack.push(c);
    });
  }
  return false;
}

// pushChildren removed; traversal uses recursive visit and traverseChildren helper

function traverseChildren(node: any, fn: (n: any) => void) {
  if (!node || typeof node !== "object") return;
  iterateChildNodes(node, (c) => fn(c));
}

function iterateChildNodes(node: any, cb: (child: any) => void) {
  if (!node || typeof node !== "object") return;
  // Explicitly check known AST child properties to avoid dynamic property access
  // which can trigger security/detect-object-injection. Extract small helpers
  // to keep the function under the cognitive complexity threshold.
  const n = node as any;
  const callIfObject = (prop: any) => {
    if (prop && typeof prop === "object") cb(prop);
  };
  const callIfArray = (arr: any) => {
    if (!Array.isArray(arr)) return;
    for (const el of arr) if (el && typeof el === "object") cb(el);
  };

  callIfObject(n.test);
  callIfObject(n.expression);
  callIfObject(n.body);
  callIfArray(n.arguments);
  callIfObject(n.callee);
  callIfArray(n.declarations);
  callIfObject(n.init);
  callIfObject(n.left);
  callIfObject(n.right);
  callIfObject(n.consequent);
  callIfObject(n.alternate);
  callIfArray(n.params);
  callIfObject(n.property);
  callIfObject(n.object);
  callIfObject(n.value);
  callIfObject(n.key);
  callIfArray(n.elements);
  callIfArray(n.properties);
}
 


function processFallback(res: any, src: string, violations: string[]) {
  const lines = src.split("\n");
  const hasDevHelper = /(?:function|const)\s+(?:_devConsole|secureDevLog)\b/.test(src);
  for (const msg of res.messages || []) {
    if (msg.ruleId !== "no-console") continue;
    if (!isConsoleAllowed(msg.line, lines, hasDevHelper)) {
      violations.push(`${path.relative(process.cwd(), res.filePath)}:${msg.line}: ${msg.message}`);
    }
  }
  // If ESLint messages are not present, also scan for console.* occurrences as a best-effort fallback
  const consoleRegex = /console\s*\.\s*([A-Za-z_$]\w*)/g;
  for (const [i, line] of lines.entries()) {
    const lineNum = i + 1;
    consoleRegex.lastIndex = 0;
    while (consoleRegex.exec(line)) {
      if (!isConsoleAllowed(lineNum, lines, hasDevHelper)) {
        violations.push(`${path.relative(process.cwd(), res.filePath)}:${lineNum}: console.* usage detected (fallback)`);
      }
    }
  }
}

// Top-level small helpers extracted from findConsoleViolations to reduce nesting
function isNamedDevHelperNode(a: any) {
  return a && a.type === "FunctionDeclaration" && a.id && (isIdentifier(a.id, "_devConsole") || isIdentifier(a.id, "secureDevLog"));
}

function hasIfGuardInFunctionNode(a: any) {
  if (!a || !a.body || !Array.isArray(a.body.body)) return false;
  const first = a.body.body[0];
  return !!(first && first.type === "IfStatement" && nodeContainsDevGuard(first.test));
}

function isAncestorAllowedNode(a: any) {
  const allowed = !!(a && typeof a.type === "string" && (isNamedDevHelperNode(a) || (a.type === "IfStatement" && a.test && nodeContainsDevGuard(a.test)) || ((a.type === "FunctionDeclaration" || a.type === "FunctionExpression" || a.type === "ArrowFunctionExpression") && hasIfGuardInFunctionNode(a))));
  return allowed;
}

function handleCallExpressionNode(node: any, ancestors: any[], violations: string[], filePath: string) {
  const callee = node.callee;
  if (callee && callee.type === "MemberExpression" && callee.object && isIdentifier(callee.object, "console")) {
    const allowed = ancestors.some(isAncestorAllowedNode);
    if (!allowed) violations.push(`${path.relative(process.cwd(), filePath)}:${node.loc.start.line}: console.* usage detected`);
  }
}

function walkNode(node: any, ancestors: any[], violations: string[], filePath: string) {
  if (!node || typeof node.type !== "string") return;
  if (node.type === "CallExpression") handleCallExpressionNode(node, ancestors, violations, filePath);

  ancestors.push(node);
  traverseChildren(node, (n) => walkNode(n, ancestors, violations, filePath));
  ancestors.pop();
}

// Break the large function into smaller helpers so each has low cognitive complexity
async function getLintResults(eslint: ESLint, files: string[]) {
  return eslint.lintFiles(files);
}

function buildResultMap(results: ESLint.LintResult[]) {
  const m = new Map<string, ESLint.LintResult>();
  for (const r of results) m.set(path.resolve(r.filePath), r);
  return m;
}

function findConsoleViolations(results: ESLint.LintResult[]) {
  const violations: string[] = [];
  for (const res of results) {
    const src = res.source ?? "";
    if (!src) continue;

    // parse and walk helper
  let ast: any = null;
    try {
      ast = parse(src, { sourceType: "module", ecmaVersion: 2024, loc: true });
    } catch (err) {
      // Log parsing error and fall back to text heuristics
      console.error(`verify-sanitize: parse error in ${path.relative(process.cwd(), res.filePath)}: ${String(err)}`);
    }

    if (!ast) {
      processFallback(res, src, violations);
      continue;
    }

    // use top-level traversal helpers
    const beforeCount = violations.length;
    walkNode(ast as any, [], violations, res.filePath);
    // If AST traversal didn't find anything, run the text-based fallback for this file as a safety net
    if (violations.length === beforeCount) processFallback(res, src, violations);
  }
  return violations;
}

function isConsoleAllowed(lineNumber: number, lines: string[], hasDevHelper: boolean) {
  const lineIdx = Math.max(0, lineNumber - 1);
  const start = Math.max(0, lineIdx - 12);
  const context = lines.slice(start, Math.min(lines.length, lineIdx + 4)).join("\n");
  let allowed = false;
  const hasInlineGuard = context.includes("isDevelopment(") || context.includes("environment.isProduction");
  if (hasInlineGuard) allowed = true;
  if (!allowed && hasDevHelper) {
    const searchStart = Math.max(0, lineIdx - 30);
    const up = lines.slice(searchStart, lineIdx + 1).join("\n");
    if (/(?:function|const)\s+(?:_devConsole|secureDevLog)\b/.test(up)) allowed = true;
  }
  return allowed;
}

function checkPrototypeProtections(resultMap: Map<string, ESLint.LintResult>) {
  const pmPath = path.resolve("src/postMessage.ts");
  const pmRes = resultMap.get(pmPath);
  const errors: string[] = [];
  if (!pmRes) {
    errors.push("postMessage.ts not found in lint results");
    return errors;
  }
  const content = pmRes.source ?? "";
  if (!content.includes("toNullProto"))
    errors.push(
      "Prototype pollution protection (toNullProto) not found in src/postMessage.ts",
    );
  if (!content.includes("POSTMESSAGE_FORBIDDEN_KEYS"))
    errors.push("Forbidden keys protection not found in src/postMessage.ts");
  return errors;
}

function checkCryptoGuards(resultMap: Map<string, ESLint.LintResult>) {
  const cryptoPath = path.resolve("src/crypto.ts");
  const cryptoRes = resultMap.get(cryptoPath);
  const errors: string[] = [];
  if (!cryptoRes) {
    errors.push("crypto.ts not found in lint results");
    return errors;
  }
  const content = cryptoRes.source ?? "";
  if (!content.includes("assertCryptoAvailableSync"))
    errors.push("Sync crypto guard function not found in src/crypto.ts");
  if (!content.includes("CRYPTO_UNAVAILABLE_SYNC"))
    errors.push("Sync crypto error code not found in src/crypto.ts");
  return errors;
}

function checkErrorCodes(resultMap: Map<string, ESLint.LintResult>) {
  const errors: string[] = [];
  const errorsPath = path.resolve("src/errors.ts");
  const errorsRes = resultMap.get(errorsPath);
  if (!errorsRes) {
    errors.push("errors.ts not found in lint results");
    return errors;
  }
  const content = errorsRes.source ?? "";
  const expectedCodes = [
    "ERR_CRYPTO_UNAVAILABLE",
    "ERR_INVALID_PARAMETER",
    "ERR_RANDOM_GENERATION",
    "ERR_INVALID_CONFIGURATION",
  ];
  for (const code of expectedCodes)
    if (!content.includes(code))
      errors.push(`Error code ${code} not found in src/errors.ts`);
  return errors;
}

async function run() {
  // Use a typed options object; ESLint reads .eslintrc by default so we omit useEslintrc
  const eslintOptions: ConstructorParameters<typeof ESLint>[0] = {
    overrideConfig: { rules: { "no-console": "error" } },
  };
  const eslint = new ESLint(eslintOptions);
  const files = [
    "src/**/*.ts",
    "src/errors.ts",
    "src/postMessage.ts",
    "src/crypto.ts",
  ];
  console.log("🔍 Running TypeScript-based security sanitization checks...");

  const results = await getLintResults(eslint, files);
  const resultMap = buildResultMap(results);

  const checks: Array<{ name: string; fn: () => string[] }> = [
    { name: "console", fn: () => findConsoleViolations(results) },
    { name: "prototype", fn: () => checkPrototypeProtections(resultMap) },
    { name: "crypto", fn: () => checkCryptoGuards(resultMap) },
    { name: "errors", fn: () => checkErrorCodes(resultMap) },
  ];

  let allPassed = true;
  for (const c of checks) {
    const errs = c.fn();
    if (errs.length === 0) {
      // Friendly success messages
      switch (c.name) {
        case "console":
          console.log("✅ No unguarded console statements found");
          break;
        case "prototype":
          console.log("✅ Prototype pollution protections verified");
          break;
        case "crypto":
          console.log("✅ Sync crypto guards verified");
          break;
        case "errors":
          console.log("✅ Error code stability verified");
          break;
      }
      continue;
    }
    allPassed = false;
    for (const e of errs) console.error("❌", e);
  }

  console.log("");
  if (allPassed) {
    console.log("🎉 All security sanitization checks passed!");
    process.exit(0);
  }
  console.log("💥 Security sanitization checks failed!");
  process.exit(1);
}
if (process.argv[1] && process.argv[1].endsWith("verify-sanitize.ts")) {
  run().catch((err) => {
    console.error("Unhandled error running verify-sanitize:", err);
    process.exit(2);
  });
}

export { findConsoleViolations, nodeContainsDevGuard, isConsoleAllowed, processFallback };
