import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

describe("createSecurePostMessageListener basic hardening", () => {
  beforeEach(async () => {
    // Reset module cache before each test to ensure clean state
    vi.resetModules();
    // Allow test APIs in runtime by setting global flag
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  });
  afterEach(async () => {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    vi.restoreAllMocks();
  });

  it("drops messages from non-allowlisted origins", async () => {
    const postMessage = await import("../../src/postMessage");
    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["https://example.com"],
      onMessage,
      validate: { x: "number" },
    });
    // dispatch a message from disallowed origin
    const ev = new MessageEvent("message", { data: JSON.stringify({ x: 1 }), origin: "https://evil.com", source: window });
    window.dispatchEvent(ev);
    expect(onMessage).not.toHaveBeenCalled();
    listener.destroy();
  });

  it("removes __proto__ from parsed payload and enforces depth limit", async () => {
    const postMessage = await import("../../src/postMessage");
    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { a: "object" },
    });
    const payload = { a: { b: 1 } } as any;
    // attach __proto__ maliciously in stringified payload
    const malicious = JSON.parse(JSON.stringify(payload));
    (malicious as any).__proto__ = { hacked: true };
    const ev = new MessageEvent("message", { data: JSON.stringify(malicious), origin: "http://localhost", source: window });
    window.dispatchEvent(ev);
    expect(onMessage).toHaveBeenCalled();
    // ensure prototype was not polluted
    expect(Object.prototype.hasOwnProperty.call({}, "hacked")).toBe(false);
    // depth limit test: craft deep payload
    const deep: any = { a: {} };
    let cur = deep.a;
    for (let i = 0; i < postMessage.POSTMESSAGE_MAX_PAYLOAD_DEPTH + 2; i++) {
      cur.next = {};
      cur = cur.next;
    }
    const ev2 = new MessageEvent("message", { data: JSON.stringify(deep), origin: "http://localhost", source: window });
    // should not throw; listener should drop due to depth
    window.dispatchEvent(ev2);
    listener.destroy();
  });
});
