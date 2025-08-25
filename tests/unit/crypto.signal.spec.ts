import { describe, it, expect } from "vitest";
import {
  getSecureRandomAsync,
  generateSecureStringSync,
} from "../../src/crypto";
import { RandomGenerationError } from "../../src/errors";

describe("crypto signal handling", () => {
  it("getSecureRandomAsync should throw when signal is aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      getSecureRandomAsync({ signal: controller.signal }),
    ).rejects.toThrow(/Abort|aborted|Operation aborted/);
  });

  it("generateSecureStringSync should throw when signal is aborted", () => {
    const controller = new AbortController();
    controller.abort();
    expect(() =>
      generateSecureStringSync("abc", 8, { signal: controller.signal }),
    ).toThrow(/Abort|aborted|Operation aborted|RandomGenerationError/);
  });
});
