import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { generateSecureStringSync } from "../../src/crypto";
import { RandomGenerationError } from "../../src/errors";

// Helper to temporarily stub document.hidden
let hiddenSpy: ReturnType<typeof vi.spyOn> | undefined;

beforeEach(() => {
  hiddenSpy = undefined;
});

afterEach(() => {
  if (hiddenSpy) hiddenSpy.mockRestore();
});

describe("generateSecureStringSync document.hidden behavior", () => {
  it("throws when document.hidden is true", () => {
    if (typeof document === "undefined") {
      // Node environment: skip this test
      return;
    }
    // Use vi.spyOn to mock the `hidden` getter which may be non-writable.
    hiddenSpy = vi
      .spyOn(document as any, "hidden", "get")
      .mockReturnValue(true);
    expect(() => generateSecureStringSync("abcd", 8)).toThrow(
      RandomGenerationError,
    );
  });
});
