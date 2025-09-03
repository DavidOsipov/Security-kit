import { describe, it, expect, vi } from "vitest";

describe("postMessage serialization tests", () => {
  it("sendSecurePostMessage should throw for circular payloads (JSON.stringify throws)", async () => {
    const postMessage = await import("../../src/postMessage");
    const errors = await import("../../src/errors");
    const a: any = { x: 1 };
    a.self = a;
    try {
      (postMessage as any).sendSecurePostMessage({
        targetWindow: window,
        payload: a,
        targetOrigin: "http://localhost",
      } as any);
      // if it didn't throw, fail
      throw new Error(
        "Expected sendSecurePostMessage to throw on circular payload",
      );
    } catch (err: any) {
      // exact error class
      expect(err).toBeInstanceOf(errors.InvalidParameterError);
      // exact code
      expect((err as any).code).toBe("ERR_INVALID_PARAMETER");
      // message content
      expect(String(err.message)).toMatch(/JSON-serializ|serializ/i);
    }
  });

  it("sendSecurePostMessage serializes and calls targetWindow.postMessage for valid payloads", async () => {
    const postMessage = await import("../../src/postMessage");
    const fakeWin = { postMessage: vi.fn() } as any;
    const payload = { a: 1 };
    (postMessage as any).sendSecurePostMessage({
      targetWindow: fakeWin,
      payload,
      targetOrigin: "http://localhost",
    } as any);
    expect(fakeWin.postMessage).toHaveBeenCalled();
    const args = fakeWin.postMessage.mock.calls[0];
    expect(typeof args[0]).toBe("string");
    expect(args[1]).toBe("http://localhost");
  });
});
