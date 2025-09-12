import { describe, it, expect } from "vitest";
import { generateSRI, generateSecureBytesAsync } from "../../src/crypto.ts";

describe("crypto: minimal edge tests", () => {
  it("throws InvalidParameterError for unsupported SRI algorithm", async () => {
    await expect(generateSRI("data", "md5" as any)).rejects.toThrow();
  });

  it("throws InvalidParameterError when input is null/undefined", async () => {
    // @ts-expect-error deliberate runtime misuse
    await expect(generateSRI(undefined)).rejects.toThrow();
    // @ts-expect-error deliberate runtime misuse
    await expect(generateSRI(null)).rejects.toThrow();
  });

  it("rejects immediately when provided an already-aborted signal", async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(
      generateSecureBytesAsync(8, { signal: ac.signal }),
    ).rejects.toThrow();
  });
});
