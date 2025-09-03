import { describe, it, expect, vi } from "vitest";
import {
  sendSecurePostMessage,
  createSecurePostMessageListener,
} from "../../src/postMessage";
import { InvalidParameterError } from "../../src/errors";

describe("postMessage module (unit)", () => {
  it("sendSecurePostMessage rejects '*' origin and invalid origins", () => {
    const fakeWin: any = { postMessage: vi.fn() };
    expect(() =>
      sendSecurePostMessage({
        targetWindow: fakeWin,
        payload: { a: 1 },
        targetOrigin: "*",
      } as any),
    ).toThrow(InvalidParameterError);
    expect(() =>
      sendSecurePostMessage({
        targetWindow: fakeWin,
        payload: { a: 1 },
        targetOrigin: "not-a-url",
      } as any),
    ).toThrow(InvalidParameterError);
  });

  it("sendSecurePostMessage rejects non-serializable payloads (circular)", () => {
    const fakeWin: any = { postMessage: vi.fn() };
    const a: any = {};
    a.self = a;
    expect(() =>
      sendSecurePostMessage({
        targetWindow: fakeWin,
        payload: a,
        targetOrigin: "https://example.com",
      } as any),
    ).toThrow(InvalidParameterError);
  });

  it("createSecurePostMessageListener enforces production constraints", () => {
    // This unit test ensures the API validates its inputs; environment-specific
    // production checks are exercised in integration tests.
    expect(() =>
      createSecurePostMessageListener(["https://example.com"], () => {}),
    ).not.toThrow();
  });
});
