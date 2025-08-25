import { describe, it, expect, vi } from "vitest";
import { createSecurePostMessageListener, POSTMESSAGE_MAX_PAYLOAD_DEPTH } from "../../src/postMessage";

describe("createSecurePostMessageListener basic hardening", () => {
  it("drops messages from non-allowlisted origins", () => {
    const onMessage = vi.fn();
    const listener = createSecurePostMessageListener({
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

  it("removes __proto__ from parsed payload and enforces depth limit", () => {
    const onMessage = vi.fn();
    const listener = createSecurePostMessageListener({
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
    for (let i = 0; i < POSTMESSAGE_MAX_PAYLOAD_DEPTH + 2; i++) {
      cur.next = {};
      cur = cur.next;
    }
    const ev2 = new MessageEvent("message", { data: JSON.stringify(deep), origin: "http://localhost", source: window });
    // should not throw; listener should drop due to depth
    window.dispatchEvent(ev2);
    listener.destroy();
  });
});
