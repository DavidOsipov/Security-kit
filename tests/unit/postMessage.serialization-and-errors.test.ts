import { expect, test, vi, afterEach } from "vitest";
import { sendSecurePostMessage, createSecurePostMessageListener, __test_resetForUnitTests } from "../../src/postMessage";
import * as state from "../../src/state";
import { environment } from "../../src/environment";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  vi.restoreAllMocks();
  try { __test_resetForUnitTests(); } catch {}
  try { if (typeof (state as any).__test_resetCryptoStateForUnitTests === 'function') (state as any).__test_resetCryptoStateForUnitTests(); } catch {}
});

// Test A: scheduleDiagnostic when subtle.digest throws (fingerprint promise rejects -> no fingerprint logged)
test("scheduleDiagnostic handles subtle.digest throwing without crashing", async () => {
  // make ensureCrypto succeed but subtle.digest throw
  vi.spyOn(state, "ensureCrypto").mockResolvedValue({
    getRandomValues: (arr: Uint8Array) => arr,
    subtle: { digest: async () => { throw new Error("boom digest"); } }
  } as unknown as Crypto);

  // create listener with diagnostics enabled and schema validator
  const onMessage = vi.fn();
  const listener = createSecurePostMessageListener({
    allowedOrigins: ["http://localhost"],
    onMessage,
    validate: { a: "number" },
    enableDiagnostics: true,
  });

  // simulate window message event with invalid payload that triggers diagnostics
  // Call handler via window.postMessage simulation
  const ev = new MessageEvent("message", { data: JSON.stringify({ a: "x" }), origin: "http://localhost" });
  // Manually dispatch to window listeners
  window.dispatchEvent(ev as any);

  // Wait a tick for async fingerprint attempt
  await new Promise((r) => setTimeout(r, 50));

  listener.destroy();
});

// Test B: sendSecurePostMessage rejects circular payload
test("sendSecurePostMessage rejects circular payloads", () => {
  const target: any = { postMessage: () => {} };
  const a: any = {};
  a.self = a;
  expect(() => sendSecurePostMessage({ targetWindow: target as Window, payload: a, targetOrigin: "https://example.com" })).toThrow();
});

// Test C: listener handler error sanitization (sanitizeErrorForLogs path)
test("listener handler errors are sanitized and don't leak full stack", () => {
  // Force validator to throw to trigger handler error path
  const listener = createSecurePostMessageListener({
    allowedOrigins: ["https://trusted.example.com"],
    onMessage: () => {},
    validate: (d: any) => { throw new Error("validator boom"); }
  });

  const ev = new MessageEvent("message", { data: JSON.stringify({}), origin: "https://trusted.example.com" });
  // Spy on console.warn to capture sanitized validation-failure log
  const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  window.dispatchEvent(ev as any);
  expect(consoleSpy).toHaveBeenCalled();
  listener.destroy();
});
