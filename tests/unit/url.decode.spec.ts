import { describe, it, expect } from "vitest";
import { strictDecodeURIComponent } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("strictDecodeURIComponent", () => {
  it("decodes a valid percent-encoded component", () => {
    const res = strictDecodeURIComponent("hello%20world");
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.value).toBe("hello world");
  });

  it("returns error for malformed percent-encoding", () => {
    const res = strictDecodeURIComponent("bad%2");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBeInstanceOf(InvalidParameterError);
  });

  it("rejects decoded control characters", () => {
    // %01 is a control character when decoded
    const res = strictDecodeURIComponent("x%01y");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBeInstanceOf(InvalidParameterError);
  });

  it("rejects overly long input", () => {
    const long = "%41".repeat(5000);
    const res = strictDecodeURIComponent(long);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBeInstanceOf(InvalidParameterError);
  });
});
