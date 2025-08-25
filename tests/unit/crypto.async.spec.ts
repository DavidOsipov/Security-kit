import { describe, it, expect } from "vitest";
import {
  generateSecureStringAsync,
  getSecureRandomInt,
} from "../../src/crypto";

describe("crypto async abort behavior", () => {
  it("should abort when AbortSignal is aborted", async () => {
    const controller = new AbortController();
    const p = generateSecureStringAsync("abcde01234", 32, {
      signal: controller.signal,
    });
    controller.abort();
    await expect(p).rejects.toBeTruthy();
  });

  it("getSecureRandomInt respects AbortSignal", async () => {
    const controller = new AbortController();
    const p = getSecureRandomInt(0, 1000000, { signal: controller.signal });
    controller.abort();
    await expect(p).rejects.toBeTruthy();
  });
});
