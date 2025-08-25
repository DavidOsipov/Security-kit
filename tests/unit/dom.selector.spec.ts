import { describe, it, expect } from "vitest";
import { DOMValidator } from "../../src/dom";
import { InvalidParameterError } from "../../src/errors";

describe("DOMValidator.validateSelectorSyntax hardening", () => {
  const v = new DOMValidator();

  it("accepts simple selectors", () => {
    expect(v.validateSelectorSyntax(".foo > .bar")).toBe(".foo > .bar");
  });

  it("rejects overly long selectors", () => {
    const long = "a".repeat(2000);
    expect(() => v.validateSelectorSyntax(long)).toThrow(InvalidParameterError);
  });

  it("rejects :has pseudo-class", () => {
    expect(() => v.validateSelectorSyntax("div:has(span)")).toThrow(
      InvalidParameterError,
    );
  });

  it("rejects :nth-child heavy selectors", () => {
    expect(() => v.validateSelectorSyntax(".list li:nth-child(2n)")).toThrow(
      InvalidParameterError,
    );
  });
});
