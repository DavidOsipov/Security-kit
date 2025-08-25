import { expect, test, vi, afterEach } from "vitest";
import { createSecurePostMessageListener, __test_resetForUnitTests } from "../../src/postMessage";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  vi.restoreAllMocks();
  try { __test_resetForUnitTests(); } catch {}
});

test("handler sanitizes thrown validator errors and logs a warn", () => {
  const listener = createSecurePostMessageListener({
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
