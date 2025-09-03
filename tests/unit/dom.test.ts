import { beforeEach, describe, expect, it } from "vitest";
import { DOMValidator, createDefaultDOMValidator } from "../../src/dom";
import {
  InvalidParameterError,
  InvalidConfigurationError,
} from "../../src/errors";

describe("DOMValidator", () => {
  beforeEach(() => {
    // Setup a minimal DOM required by queries
    document.body.innerHTML = `
      <div id="main-content">
        <div id="allowed-child"><span id="inner">ok</span></div>
      </div>
      <div id="outside">outside</div>
    `;
  });

  it("validateSelectorSyntax rejects empty or evil selectors", () => {
    const v = new DOMValidator();
    expect(() => v.validateSelectorSyntax("")).toThrow(InvalidParameterError);
    expect(() => v.validateSelectorSyntax(" :has(div) ")).toThrow(
      InvalidParameterError,
    );
    // overly long selector
    const long = "a".repeat(2000);
    expect(() => v.validateSelectorSyntax(long)).toThrow(InvalidParameterError);
  });

  it("validateElement rejects non-elements and forbidden tags", () => {
    const v = new DOMValidator();
    expect(() => v.validateElement(null as any)).toThrow(InvalidParameterError);
    const script = document.createElement("script");
    expect(() => v.validateElement(script)).toThrow(InvalidParameterError);
  });

  it("queryElementSafely returns element when inside allowed roots and null otherwise", () => {
    const v = new DOMValidator();
    // allowed element
    const inside = v.queryElementSafely("#inner");
    expect(inside).not.toBeNull();
    expect(inside!.id).toBe("inner");

    // outside element should be undefined (and not throw)
    const outside = v.queryElementSafely("#outside");
    expect(outside).toBeUndefined();
  });

  it("constructor clones config and rejects forbidden roots", () => {
    const cfg = {
      // Use overlapping token so constructor validation triggers
      allowedRootSelectors: new Set(["#main-content"]),
      forbiddenRoots: new Set(["#main-content"]),
    } as any;
    expect(() => new DOMValidator(cfg)).toThrow(InvalidConfigurationError);

    // If we provide a safe config, mutating original should not affect instance
    const cfg2 = {
      allowedRootSelectors: new Set(["#main-content"]),
      forbiddenRoots: new Set(),
    } as any;
    const inst = new DOMValidator(cfg2);
    // mutate source config
    cfg2.allowedRootSelectors.add("#outside");
    // instance should still only find elements in original allowed root
    const found = inst.queryElementSafely("#inner");
    expect(found).not.toBeNull();
    const outside = inst.queryElementSafely("#outside");
    expect(outside).toBeUndefined();
  });
});
