import { describe, it, expect } from "vitest";
import { encodeHostLabel } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("encodeHostLabel - IDNA edge cases and error semantics", () => {
  it("throws InvalidParameterError when idnaLibrary is undefined", () => {
    expect(() => encodeHostLabel("example", undefined as any)).toThrow(
      InvalidParameterError,
    );
  });

  it("throws InvalidParameterError when idnaLibrary is null", () => {
    expect(() => encodeHostLabel("example", null as any)).toThrow(
      InvalidParameterError,
    );
  });

  it("throws InvalidParameterError when toASCII is not a function (missing)", () => {
    const provider = {} as any;
    expect(() => encodeHostLabel("example", provider)).toThrow(
      InvalidParameterError,
    );
  });

  it("throws InvalidParameterError when toASCII is not a function (non-callable)", () => {
    const provider = { toASCII: 123 } as any;
    expect(() => encodeHostLabel("example", provider)).toThrow(
      InvalidParameterError,
    );
  });

  it("wraps provider exception and surfaces InvalidParameterError with safe message fragment", () => {
    const provider = { toASCII: (_: string) => { throw new Error("boom-idna"); } } as any;
    try {
      encodeHostLabel("exämple", provider);
      throw new Error("expected to throw");
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(InvalidParameterError);
      const msg = (e as Error).message;
      // Message should include a safe fragment indicating IDNA encoding failed
      expect(msg).toContain("IDNA encoding failed");
      // Should not leak the original provider error name verbatim in production; ensure the detail is present in non-prod (test env)
      expect(msg).toContain("boom-idna");
    }
  });

  it("rejects provider returning non-ASCII characters (runtime validation in url.ts happens elsewhere but encodeHostLabel should return provider output)", () => {
    // encodeHostLabel simply returns provider.toASCII output after runtime checks.
    // To exercise rejection paths that would exist in preValidateAuthority, we simulate
    // a provider returning non-ASCII and assert encodeHostLabel returns it (higher-level
    // checks are performed by preValidateAuthority). This ensures encodeHostLabel is
    // deterministic and does not silently mutate provider output.
    const provider = { toASCII: (s: string) => "пример" } as any; // non-ascii
    const out = encodeHostLabel("пример", provider);
    expect(out).toBe("пример");
  });

  it("accepts valid provider and returns normalized A-label-like output", () => {
    // Deterministic mock that simulates punycode conversion
    const provider = { toASCII: (s: string) => `xn--${s.toLowerCase().replace(/[^a-z0-9]+/g, "")}` } as any;
    const out = encodeHostLabel("Exämple", provider);
    expect(out.startsWith("xn--")).toBe(true);
  });

  it("throws InvalidParameterError when label is not a string", () => {
    const provider = { toASCII: (s: string) => s } as any;
    expect(() => encodeHostLabel((123 as unknown) as string, provider)).toThrow(
      InvalidParameterError,
    );
  });
});
