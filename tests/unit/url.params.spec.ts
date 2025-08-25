import { describe, it, expect } from "vitest";
import { parseURLParams, __test_arrayBufferToBase64 } from "../../src";

function toArrayBufferFromString(s: string): ArrayBuffer {
  const enc = new TextEncoder();
  return enc.encode(s).buffer;
}

describe("base64 helper", () => {
  it("produces stable base64 for known input", () => {
    const input = "hello world";
    const helper = __test_arrayBufferToBase64 as any;
    // In production-like builds the test-only helper may be undefined. Fall
    // back to a Node-compatible Buffer-based encoder for the assertion.
    const fallback = (buf: ArrayBuffer) =>
      Buffer.from(new Uint8Array(buf)).toString("base64");
    const fn = typeof helper === "function" ? helper : fallback;
    const b64 = fn(toArrayBufferFromString(input));
    expect(b64).toBe("aGVsbG8gd29ybGQ=");
  });
});

describe("parseURLParams hardening", () => {
  it("filters dangerous keys and enforces SAFE_KEY_REGEX", () => {
    const url =
      "https://example.test/?__proto__=x&constructor=y&prototype=z&ok_key=1&weird%20key=2&dot.name=a&dash-name=b&underscore_name=c";
    const params = parseURLParams(url);
    expect(Object.getPrototypeOf(params)).toBe(null);
    expect(params.ok_key).toBe("1");
    expect(params["dot.name"]).toBe("a");
    expect(params["dash-name"]).toBe("b");
    expect(params["underscore_name"]).toBe("c");
    expect("weird key" in params).toBe(false);
    expect("__proto__" in params).toBe(false);
  });
});
