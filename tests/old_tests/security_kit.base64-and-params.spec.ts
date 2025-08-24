import { describe, it, expect } from "vitest";
import { parseURLParams } from "@utils/security_kit";

// _arrayBufferToBase64 is internal; validate via public generateSRI which uses it
import { __test_arrayBufferToBase64 } from "@utils/security_kit";

function toArrayBufferFromString(s: string): ArrayBuffer {
  const enc = new TextEncoder();
  return enc.encode(s).buffer;
}

describe("security_kit: base64 encoding internal", () => {
  it("produces stable base64 for known input", async () => {
    const input = "hello world";
    const helper = __test_arrayBufferToBase64!;
    expect(typeof helper).toBe("function");
    const b64 = helper(toArrayBufferFromString(input));
    // btoa of 'hello world' is 'aGVsbG8gd29ybGQ='
    expect(b64).toBe("aGVsbG8gd29ybGQ=");
  });
});

describe("parseURLParams hardening", () => {
  it("filters dangerous keys and enforces SAFE_KEY_REGEX", () => {
    const url =
      "https://example.test/?__proto__=x&constructor=y&prototype=z&ok_key=1&weird%20key=2&dot.name=a&dash-name=b&underscore_name=c";
    const params = parseURLParams(url);
    expect(Object.prototype.toString.call(params)).toBe("[object Object]");
    expect(Object.getPrototypeOf(params)).toBe(null);
    // Allowed keys
    expect(params.ok_key).toBe("1");
    expect(params["dot.name"]).toBe("a");
    expect(params["dash-name"]).toBe("b");
    expect(params["underscore_name"]).toBe("c");
    // Rejected keys are absent
    expect("weird key" in params).toBe(false);
    expect("__proto__" in params).toBe(false);
    expect("constructor" in params).toBe(false);
    expect("prototype" in params).toBe(false);

    // Frozen (immutable) result
    expect(() => {
      (params as any).ok_key = "2";
    }).toThrowError();
  });

  it("emits warnings for schema mismatches but does not throw", () => {
    const url = "https://example.test/?page=one&count=ten&flag=maybe";
    const params = parseURLParams(url, {
      page: "number",
      count: "number",
      flag: "boolean",
    });
    expect(params.page).toBe("one");
    expect(params.count).toBe("ten");
    expect(params.flag).toBe("maybe");
  });
});
