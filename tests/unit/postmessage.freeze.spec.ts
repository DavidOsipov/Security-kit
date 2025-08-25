import { createSecurePostMessageListener } from "../../src/postMessage";
import { expect, it, describe } from "vitest";

// Minimal DOM-like environment mock for message events
class MockWindow {
  listeners: Map<string, Function[]> = new Map();
  addEventListener(name: string, cb: Function) {
    const arr = this.listeners.get(name) || [];
    arr.push(cb);
    this.listeners.set(name, arr);
  }
  postMessage(data: string, origin: string) {
    const e: any = { data, origin, source: null };
    const arr = this.listeners.get("message") || [];
    for (const cb of arr) cb(e);
  }
}

declare const window: any;

describe("postMessage freezePayload option", () => {
  it("freezes payload by default", () => {
    const mockWin = new MockWindow() as any;
    (globalThis as any).window = mockWin;
    let received: any = null;
    const listener = createSecurePostMessageListener(
      { allowedOrigins: ["https://trusted.example.com"], onMessage: (d: unknown) => (received = d), validate: () => true },
    );
    mockWin.postMessage(JSON.stringify({ a: 1 }), "https://trusted.example.com");
    expect(received).not.toBeNull();
    expect(Object.isFrozen(received)).toBe(true);
  });

  it("does not freeze when freezePayload=false", () => {
    const mockWin = new MockWindow() as any;
    (globalThis as any).window = mockWin;
    let received: any = null;
    const listener = createSecurePostMessageListener(
      { allowedOrigins: ["https://trusted.example.com"], onMessage: (d: unknown) => (received = d), validate: () => true, freezePayload: false },
    );
    mockWin.postMessage(JSON.stringify({ a: 1 }), "https://trusted.example.com");
    expect(received).not.toBeNull();
    // Should allow mutation
    (received as any).b = 2;
    expect((received as any).b).toBe(2);
  });
});
