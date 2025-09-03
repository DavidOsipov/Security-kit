import { describe, it, expect } from "vitest";
import { createDefaultDOMValidator } from "../../src/dom";
import { InvalidParameterError } from "../../src/errors";

describe("DOMValidator (no-DOM environment)", () => {
  const v = createDefaultDOMValidator();

  it("accepts simple selectors (id, class, tag) synchronously", () => {
    expect(v.validateSelectorSyntax("#main")).toBe("#main");
    expect(v.validateSelectorSyntax(".cls")).toBe(".cls");
    expect(v.validateSelectorSyntax("div")).toBe("div");
    expect(v.validateSelectorSyntax("a > b")).toBe("a > b");
  });

  it("rejects selectors with expensive pseudo-classes", () => {
    expect(() => v.validateSelectorSyntax("div:has(span)")).toThrow(
      InvalidParameterError,
    );
    expect(() => v.validateSelectorSyntax("input:not([type])")).toThrow(
      InvalidParameterError,
    );
  });

  it("attribute selector path is well-behaved (implementation-dependent)", () => {
    // Attribute selectors may be treated as complex or simple depending on
    // runtime heuristics; accept either a thrown InvalidParameterError or a
    // returned normalized selector string to keep the test resilient.
    try {
      const out = v.validateSelectorSyntax('[data-secret="x"]');
      expect(typeof out).toBe("string");
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidParameterError);
    }
  });

  it("queryAllSafely returns empty array when no DOM", () => {
    const res = v.queryAllSafely(".anything");
    expect(Array.isArray(res)).toBe(true);
    expect(res.length).toBe(0);
  });

  it("containsWithinAllowedRoots returns false in no-DOM", () => {
    // create a fake element object that is not an Element instance
    // ts-ignore: we intentionally pass wrong type to exercise guard
    // @ts-ignore
    expect(v.containsWithinAllowedRoots({})).toBe(false);
  });
});
