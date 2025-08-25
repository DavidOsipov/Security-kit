import { describe, it, expect } from "vitest";
import { parseURLParams } from "../../src/url";

describe("parseURLParams descriptors and freezing", () => {
  it("returns a frozen object with read-only properties for safe keys", () => {
    const params = parseURLParams("https://example.com/?a=1&b=2");
    expect(Object.isFrozen(params)).toBe(true);
    const descA = Object.getOwnPropertyDescriptor(params, "a");
    expect(descA).toBeDefined();
    expect(descA?.writable).toBe(false);
    expect(descA?.enumerable).toBe(true);
  });
});
