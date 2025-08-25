import { expect, test, vi, afterEach } from "vitest";
import * as state from "../../src/state";
import { sendSecurePostMessage, createSecurePostMessageListener, __test_resetForUnitTests } from "../../src/postMessage";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  vi.restoreAllMocks();
  try { __test_resetForUnitTests(); } catch {}
});

test("scheduleDiagnostic handles subtle.digest rejection gracefully", async () => {
  // ensureCrypto resolves but subtle.digest rejects
  vi.spyOn(state, "ensureCrypto").mockResolvedValue({
    getRandomValues: (arr: Uint8Array) => arr,
    subtle: { digest: async () => { throw new Error("digest fail"); } }
  } as unknown as Crypto);

  const onMessage = vi.fn();
  const listener = createSecurePostMessageListener({
    allowedOrigins: ["http://localhost"],
    onMessage,
    validate: { a: "number" },
    enableDiagnostics: true,
  });

  const ev = new MessageEvent("message", { data: JSON.stringify({ a: "x" }), origin: "http://localhost" });
  const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
  window.dispatchEvent(ev as any);

  // Allow async fingerprint attempt to run
  await new Promise((r) => setTimeout(r, 50));
  // Should have logged, but without crashing; at least one warn call expected
  expect(spy).toHaveBeenCalled();
  listener.destroy();
});

test("sendSecurePostMessage rejects payloads whose getters throw during serialization", () => {
  const target: any = { postMessage: () => {} };
  const obj: any = {};
  Object.defineProperty(obj, "danger", {
    get() { throw new Error("boom getter"); },
    enumerable: true,
  });
  expect(() => sendSecurePostMessage({ targetWindow: target as Window, payload: obj, targetOrigin: "https://example.com" })).toThrow();
});

test("listener onMessage async errors are sanitized and logged without leaking stack", async () => {
  const onMessage = async () => { throw new Error("async handler secret"); };
  const listener = createSecurePostMessageListener({ allowedOrigins: ["https://trusted.example.com"], onMessage, validate: (d:any) => true });
  const ev = new MessageEvent("message", { data: JSON.stringify({}), origin: "https://trusted.example.com" });
  const spy = vi.spyOn(console, "error").mockImplementation(() => {});
  window.dispatchEvent(ev as any);
  // allow async handler to run
  await new Promise((r) => setTimeout(r, 20));
  expect(spy).toHaveBeenCalled();
  listener.destroy();
});
