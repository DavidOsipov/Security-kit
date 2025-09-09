import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { _resetCanonicalConfigForTests, setCanonicalConfig } from "../../src/config";
import { InvalidParameterError } from "../../src/errors";
import { toCanonicalValue, safeStableStringify } from "../../src/canonical";

describe("canonicalization depth budget", () => {
  beforeEach(() => {
    _resetCanonicalConfigForTests();
  });

  afterEach(() => {
    _resetCanonicalConfigForTests();
  });

  it("throws typed error when nested depth exceeds maxDepth for toCanonicalValue", () => {
    setCanonicalConfig({ maxDepth: 2 });
    // build a nested object deeper than 2
    const deep = { a: { b: { c: { d: 1 } } } };
    expect(() => toCanonicalValue(deep)).toThrow(InvalidParameterError);
  });

  it("safeStableStringify throws typed error when nested depth exceeds maxDepth", () => {
    setCanonicalConfig({ maxDepth: 3 });
    const deep = { a: { b: { c: { d: { e: 2 } } } } };
    expect(() => safeStableStringify(deep)).toThrow(InvalidParameterError);
  });
});
