// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { sendSecurePostMessage } from "../../src/postMessage";

// JSDOM doesn't fully implement postMessage structured clone across windows.
// We simulate by creating a fake targetWindow with a stubbed postMessage and
// assert that oversized or overly complex payloads are rejected before calling it.

describe("postMessage payload caps", () => {
  const targetOrigin = "https://example.com";
  const targetWindow = {
    postMessage: (_data: unknown, _origin: string) => {
      /* no-op */
    },
  } as unknown as Window;

  it("rejects very large nested arrays when sanitize=false", () => {
    const HUGE = 40 * 1024; // clearly over byte limit after estimation
    const payload = new Array(HUGE).fill("x");
    expect(() =>
      sendSecurePostMessage({
        targetWindow,
        payload,
        targetOrigin,
        wireFormat: "structured",
        sanitize: false,
      }),
    ).toThrowError(/Payload exceeds maximum size|Array has too many items/i);
  });

  it("rejects overly deep objects when sanitize=false", () => {
    // Build > depth cap object
    let o: any = { a: 1 };
    for (let i = 0; i < 32; i++) o = { o };
    const deep = o;
    expect(() =>
      sendSecurePostMessage({
        targetWindow,
        payload: deep,
        targetOrigin,
        wireFormat: "structured",
        sanitize: false,
      }),
    ).toThrow();
  });
});
