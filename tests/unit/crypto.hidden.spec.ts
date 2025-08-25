import { describe, it, expect } from "vitest";
import { generateSecureStringAsync } from "../../src/crypto";

describe("crypto async visibility abort", () => {
  it("aborts when document.hidden is true", async () => {
    const origDoc = globalThis.document;
    // Create a proxy that delegates to the real document but overrides `hidden`
    const proxy = new Proxy(origDoc, {
      get(target, prop, receiver) {
        if (prop === "hidden") return true;
        // forward all other properties
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const v = Reflect.get(target as any, prop, receiver as any);
        return typeof v === "function" ? v.bind(target) : v;
      },
    });
    try {
      // Replace global document with the proxy for the duration of the test
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore - test-only replacement
      globalThis.document = proxy as unknown as Document;
      await expect(
        generateSecureStringAsync("abcdef0123456789", 8),
      ).rejects.toBeTruthy();
    } finally {
      // Restore original document
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      globalThis.document = origDoc;
    }
  });
});
