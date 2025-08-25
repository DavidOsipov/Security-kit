import { describe, it, expect, vi } from "vitest";
import { getSecureRandomAsync } from "../../src/crypto";
import { RandomGenerationError } from "../../src/errors";

describe("getSecureRandomAsync abort/hidden behavior", () => {
  it("rejects when signal is aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      getSecureRandomAsync({ signal: controller.signal }),
    ).rejects.toThrow(/Operation aborted|AbortError/);
  });

  it("rejects when document.hidden is true", async () => {
    if (typeof document === "undefined") return;
    const spy = vi
      .spyOn(document as any, "hidden", "get")
      .mockReturnValue(true);
    try {
      await expect(getSecureRandomAsync()).rejects.toThrow(
        RandomGenerationError,
      );
    } finally {
      spy.mockRestore();
    }
  });
});
