import { expect, test, vi, afterEach } from "vitest";
import * as state from "../../src/state";
import { createSecurePostMessageListener, __test_resetForUnitTests } from "../../src/postMessage";
import { environment } from "../../src/environment";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  vi.restoreAllMocks();
  try { __test_resetForUnitTests(); } catch {}
  try { environment.setExplicitEnv("development"); } catch {}
});

test("production disables diagnostics when crypto unavailable", async () => {
  // Simulate production environment
  environment.setExplicitEnv("production");

  // Make ensureCrypto reject to simulate no crypto available
  vi.spyOn(state, "ensureCrypto").mockRejectedValue(new Error("no crypto"));

  const listener = createSecurePostMessageListener({
    allowedOrigins: ["http://localhost"],
    onMessage: () => {},
    validate: { a: "number" },
    enableDiagnostics: true,
  });

  const ev = new MessageEvent("message", { data: JSON.stringify({ a: "x" }), origin: "http://localhost" });
  const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
  window.dispatchEvent(ev as any);

  // Wait to allow async computeAndLog to attempt ensureCrypto
  vi.useFakeTimers();
  try {
    await vi.runAllTimersAsync();
  } finally {
    vi.useRealTimers();
  }

  // In production with no crypto, fingerprint should not be present in logs
  const called = spy.mock.calls.some(call => JSON.stringify(call[1] || call[0]).includes("fingerprint"));
  expect(called).toBe(false);
  listener.destroy();
});
