import { describe, expect, it } from "vitest";
import path from "path";
import { __test_helpers } from "../../scripts/verify-sanitize";

const {
  isMemberAccess,
  nodeContainsDevGuard,
  isConsoleAllowed,
  checkPrototypeProtections,
  checkCryptoGuards,
  checkErrorCodes,
  findConsoleViolations,
} = __test_helpers as any;

describe("scripts/verify-sanitize helpers", () => {
  it("isMemberAccess detects identifier and literal properties", () => {
    const ident = {
      type: "MemberExpression",
      object: { type: "Identifier", name: "env" },
      property: { type: "Identifier", name: "isProd" },
    };
    expect(isMemberAccess(ident, "env", "isProd")).toBe(true);

    const lit = {
      type: "MemberExpression",
      object: { type: "Identifier", name: "env" },
      property: { type: "Literal", value: "isProd" },
    };
    expect(isMemberAccess(lit, "env", "isProd")).toBe(true);

    const not = {
      type: "MemberExpression",
      object: { type: "Identifier", name: "other" },
      property: { type: "Identifier", name: "isProd" },
    };
    expect(isMemberAccess(not, "env", "isProd")).toBe(false);
  });

  it("nodeContainsDevGuard finds isDevelopment and environment.isProduction", () => {
    const node1 = { type: "Identifier", name: "isDevelopment" };
    expect(nodeContainsDevGuard(node1)).toBe(true);

    const node2 = {
      type: "MemberExpression",
      object: { type: "Identifier", name: "environment" },
      property: { type: "Identifier", name: "isProduction" },
    };
    expect(nodeContainsDevGuard(node2)).toBe(true);

    const node3 = { type: "Literal", value: 42 };
    expect(nodeContainsDevGuard(node3)).toBe(false);
  });

  it("isConsoleAllowed returns true when guard present in context", () => {
    const src = [
      "function foo() {",
      "  if (isDevelopment()) {",
      "    console.log('ok');",
      "  }",
      "}",
    ];
    // line number of console.log is 3
    expect(isConsoleAllowed(3, src, false)).toBe(true);

    const src2 = ["// no guard here", "console.error('oops')"];
    expect(isConsoleAllowed(2, src2, false)).toBe(false);
  });

  it("findConsoleViolations fallback detects console usage", () => {
    const fakeRes: any = {
      filePath: path.resolve("src/foo.ts"),
      source: "const x = 1; console.log(x);",
      messages: [],
    };
    const res = findConsoleViolations([fakeRes]);
    expect(res.length).toBeGreaterThan(0);
  });

  it("checkPrototypeProtections and checkCryptoGuards report missing files when map empty", () => {
    const m = new Map();
    const prot = checkPrototypeProtections(m);
    expect(prot.length).toBeGreaterThan(0);
    const crypto = checkCryptoGuards(m);
    expect(crypto.length).toBeGreaterThan(0);
  });

  it("checkErrorCodes reports missing errors when file not present", () => {
    const m = new Map();
    const errs = checkErrorCodes(m);
    expect(errs.length).toBeGreaterThan(0);
  });
});
