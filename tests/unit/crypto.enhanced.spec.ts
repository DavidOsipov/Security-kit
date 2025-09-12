import { describe, it, expect } from "vitest";
import { generateSecureBytesAsync } from "../../src/crypto";

describe("crypto: visibility & abort guards for generateSecureBytesAsync", () => {
  it("throws when document.hidden is true and enforceVisibility is true", async () => {
    const originalDoc = (globalThis as any).document;
    try {
      // Simulate a hidden document (jsdom provides document by default in jsdom env)
      (globalThis as any).document = { hidden: true } as any;
      await expect(
        generateSecureBytesAsync(16, { enforceVisibility: true }),
      ).rejects.toThrow();
    } finally {
      (globalThis as any).document = originalDoc;
    }
  });

  it("succeeds when document.hidden is true but enforceVisibility is false", async () => {
    const originalDoc = (globalThis as any).document;
    try {
      (globalThis as any).document = { hidden: true } as any;
      const bytes = await generateSecureBytesAsync(8, { enforceVisibility: false });
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(8);
    } finally {
      (globalThis as any).document = originalDoc;
    }
  });

  it("rejects immediately when provided AbortSignal is already aborted", async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(
      generateSecureBytesAsync(8, { signal: ac.signal }),
    ).rejects.toThrow();
  });
});
