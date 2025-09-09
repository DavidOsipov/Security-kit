import { expect, test, vi, afterEach } from "vitest";
import { CryptoUnavailableError } from "../../src/errors";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(async () => {
  vi.restoreAllMocks();
  vi.resetModules();
  try {
    const postMessage = await import("../../src/postMessage");
    (postMessage as any).__test_resetForUnitTests();
  } catch {}
  try {
    const env = await import("../../src/environment");
    env.environment.setExplicitEnv("development");
  } catch {}
});

test("production disables diagnostics when crypto unavailable", async () => {
  vi.resetModules();
  // Simulate production environment
  const env = await import("../../src/environment");
  env.environment.setExplicitEnv("production");

  // Make ensureCrypto reject to simulate no crypto available
  const state = await import("../../src/state");
  vi.spyOn(state, "ensureCrypto").mockRejectedValue(
    new CryptoUnavailableError(),
  );

  const postMessage = await import("../../src/postMessage");
  const listener = (postMessage as any).createSecurePostMessageListener({
    allowedOrigins: ["http://localhost"],
    onMessage: () => {},
    validate: { a: "number" },
    enableDiagnostics: true,
  });

  const ev = new MessageEvent("message", {
    data: JSON.stringify({ a: "x" }),
    origin: "http://localhost",
  });
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
  const called = spy.mock.calls.some((call) =>
    JSON.stringify(call[1] || call[0]).includes("fingerprint"),
  );
  expect(called).toBe(false);
  listener.destroy();
});
