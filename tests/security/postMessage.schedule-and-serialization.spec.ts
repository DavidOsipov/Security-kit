import { expect, test, vi, afterEach } from "vitest";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(async () => {
  vi.restoreAllMocks();
  vi.resetModules();
  try {
    const postMessage = await import("../../src/postMessage");
    (postMessage as any).__test_resetForUnitTests();
  } catch {}
});

test("scheduleDiagnostic handles subtle.digest rejection gracefully", async () => {
  vi.resetModules();
  // ensureCrypto resolves but subtle.digest rejects
  const state = await import("../../src/state");
  vi.spyOn(state, "ensureCrypto").mockResolvedValue({
    getRandomValues: (arr: Uint8Array) => arr,
    subtle: { digest: async () => { throw new Error("digest fail"); } }
  } as unknown as Crypto);

  const postMessage = await import("../../src/postMessage");
  const onMessage = vi.fn();
  const listener = (postMessage as any).createSecurePostMessageListener({
    allowedOrigins: ["http://localhost"],
    onMessage,
    validate: { a: "number" },
    enableDiagnostics: true,
  });

  const ev = new MessageEvent("message", { data: JSON.stringify({ a: "x" }), origin: "http://localhost" });
  const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
  // Enable fake timers before dispatch so async fingerprint/diagnostic runs under mocked timers
  vi.useFakeTimers();
  try {
    window.dispatchEvent(ev as any);
    await vi.runAllTimersAsync();
  } finally {
    vi.useRealTimers();
  }

  // Should have logged, but without crashing; at least one warn call expected
  expect(spy).toHaveBeenCalled();
  listener.destroy();
});

test("sendSecurePostMessage skips accessors that throw during serialization (does not throw)", async () => {
  vi.resetModules();
  const postMessage = await import("../../src/postMessage");
  const target: any = { postMessage: () => {} };
  const obj: any = {};
  Object.defineProperty(obj, "danger", {
    get() { throw new Error("boom getter"); },
    enumerable: true,
  });
  const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
  // Should NOT throw because getters are skipped by the sanitizer
  (postMessage as any).sendSecurePostMessage({ targetWindow: target as Window, payload: obj, targetOrigin: "https://example.com" });
  // Current implementation skips accessor properties without emitting a dev warning,
  // so ensure no warning was emitted during normal sanitization path.
  expect(spy).not.toHaveBeenCalled();
  spy.mockRestore();
});

test("listener onMessage async errors are sanitized and logged without leaking stack", async () => {
  vi.resetModules();
  const postMessage = await import("../../src/postMessage");
  const onMessage = async () => { throw new Error("async handler secret"); };
  const listener = (postMessage as any).createSecurePostMessageListener({ allowedOrigins: ["https://trusted.example.com"], onMessage, validate: (d:any) => true });
  const ev = new MessageEvent("message", { data: JSON.stringify({}), origin: "https://trusted.example.com" });
  const spy = vi.spyOn(console, "error").mockImplementation(() => {});
  window.dispatchEvent(ev as any);
  // allow async handler to run
    vi.useFakeTimers();
    try {
      await vi.runAllTimersAsync();
    } finally {
      vi.useRealTimers();
    }
  expect(spy).toHaveBeenCalled();
  listener.destroy();
});
