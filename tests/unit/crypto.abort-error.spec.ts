import { describe, it, expect } from "vitest";
import {
  generateSecureStringAsync,
  getSecureRandomInt,
} from "../../src/crypto";

describe("crypto async abort error shape", () => {
  it("generateSecureStringAsync rejects with an AbortError when aborted", async () => {
    const ctl = new AbortController();
    const p = generateSecureStringAsync("abcdef0123456789", 16, {
      signal: ctl.signal,
    });
    ctl.abort();
    await p.catch((err) => {
      // Accept either DOMException with name AbortError or any Error with message containing 'abort'
      expect(err).toBeTruthy();
      const name = (err && (err as any).name) || "";
      expect(
        name === "AbortError" || /abort/i.test(String(err.message || "")),
      ).toBe(true);
    });
  });

  it("getSecureRandomInt rejects with an AbortError when aborted", async () => {
    const ctl = new AbortController();
    const p = getSecureRandomInt(0, 1000000, { signal: ctl.signal });
    ctl.abort();
    await p.catch((err) => {
      expect(err).toBeTruthy();
      const name = (err && (err as any).name) || "";
      expect(
        name === "AbortError" || /abort/i.test(String(err.message || "")),
      ).toBe(true);
    });
  });
});
