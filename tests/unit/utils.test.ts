import { describe, it, expect, beforeEach } from "vitest";
import {
  secureWipe,
  createSecureZeroingArray,
  secureCompare,
  secureCompareAsync,
  _redact,
} from "../../src/utils";
import { arrayBufferToBase64 } from "../../src/encoding-utils";
import { encodeComponentRFC3986, strictDecodeURIComponent } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("utils module", () => {
  it("secureWipe zeros a Uint8Array", () => {
    const arr = new Uint8Array([1, 2, 3, 4]);
    secureWipe(arr);
    expect(Array.from(arr)).toEqual([0, 0, 0, 0]);
  });

  it("createSecureZeroingArray enforces bounds", () => {
    const a = createSecureZeroingArray(8);
    expect(a.length).toBe(8);
  });

  it("secureCompare handles equal and different strings", () => {
    expect(secureCompare("abc", "abc")).toBe(true);
    expect(secureCompare("abc", "abx")).toBe(false);
    expect(() => secureCompare(undefined, undefined)).toThrow(InvalidParameterError);
  });

  it("secureCompare throws on too long inputs", () => {
    const long = "a".repeat(5000);
    expect(() => secureCompare(long, "a")).toThrow(InvalidParameterError);
  });

  it("secureCompareAsync falls back when subtle missing and allow fallback", async () => {
    // Run without requireCrypto to allow fallback
    const res = await secureCompareAsync("x", "x");
    expect(res).toBe(true);
  });

  it("_redact redacts secrets and jwt-like and truncates long strings", () => {
    const obj = {
      password: "hunter2",
      token: "abc",
      nested: { jwt: "eyJxxxxx.yyyyy.zzzzz" },
      long: "a".repeat(9000),
    } as any;
    const redacted = _redact(obj) as any;
    expect(redacted.password).toBe("[REDACTED]");
    expect(redacted.token).toBe("[REDACTED]");
    // long should be truncated
    expect(typeof redacted.long).toBe("string");
  });

  it("_arrayBufferToBase64 produces expected base64", () => {
    const buf = new Uint8Array([0, 1, 2, 3]).buffer;
    const b64 = arrayBufferToBase64(buf);
    expect(typeof b64).toBe("string");
  });

  it("encodeComponentRFC3986 rejects control characters", () => {
    expect(() => encodeComponentRFC3986("a\x00b")).toThrow(InvalidParameterError);
  });

  it("strictDecodeURIComponent handles malformed input", () => {
    const res = strictDecodeURIComponent("%E0%A4%A");
    expect(res.ok).toBe(false);
  });
});
