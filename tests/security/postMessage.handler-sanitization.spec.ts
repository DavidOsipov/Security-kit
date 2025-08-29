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

test("handler sanitizes thrown validator errors and logs a warn", async () => {
  const postMessage = await import("../../src/postMessage");
  const listener = (postMessage as any).createSecurePostMessageListener({
    allowedOrigins: ["https://example.com"],
    onMessage: () => {},
    validate: () => { throw new Error("secret-stack"); }
  });
  const ev = new MessageEvent("message", { data: JSON.stringify({}), origin: "https://example.com" });
  const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
  window.dispatchEvent(ev as any);
  expect(spy).toHaveBeenCalled();
  listener.destroy();
});
