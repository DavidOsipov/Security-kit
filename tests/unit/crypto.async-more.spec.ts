import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  generateSecureStringAsync,
  getSecureRandomInt,
} from "../../src/crypto";

describe("crypto async extra tests", () => {
  it("generateSecureStringAsync returns a string of requested length", async () => {
    const s = await generateSecureStringAsync("abcdef0123456789", 16);
    expect(typeof s).toBe("string");
    expect(s.length).toBe(16);
  });

  it("generateSecureStringAsync rejects with AbortError when aborted before work", async () => {
    const ctl = new AbortController();
    ctl.abort();
    await expect(
      generateSecureStringAsync("abcdef0123456789", 16, { signal: ctl.signal }),
    ).rejects.toBeTruthy();
  });

  it("getSecureRandomInt returns a number in range", async () => {
    const v = await getSecureRandomInt(1, 10);
    expect(typeof v).toBe("number");
    expect(v).toBeGreaterThanOrEqual(1);
    expect(v).toBeLessThanOrEqual(10);
  });

  it("getSecureRandomInt aborts with AbortSignal and rejects", async () => {
    const ctl = new AbortController();
    const p = getSecureRandomInt(0, 1000000, { signal: ctl.signal });
    ctl.abort();
    await expect(p).rejects.toBeTruthy();
  });
});
