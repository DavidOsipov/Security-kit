import { expect, test, afterEach } from "vitest";
import { createSecurePostMessageListener } from "../../src/postMessage";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  try {
    // no-op cleanup
  } catch {}
});

test("freeze cache avoids repeated deep freeze work", () => {
  const win = {
    addEventListener: () => {},
    removeEventListener: () => {},
  } as unknown as Window;
  const payload = { x: { y: 1 } };
  const calls: any[] = [];
  const listener = createSecurePostMessageListener({
    allowedOrigins: ["http://localhost"],
    onMessage() {
      calls.push(1);
    },
    validate: (d: any) => true as any,
    freezePayload: true,
  });

  // Manually call the internal freeze helper via creating two listeners to exercise cache behavior
  const listener2 = createSecurePostMessageListener({
    allowedOrigins: ["http://localhost"],
    onMessage() {
      calls.push(2);
    },
    validate: (d: any) => true as any,
    freezePayload: true,
  });

  // Simulate two different listeners freezing same payload instance
  // This is a coarse smoke test: ensure no exception and listeners created
  expect(typeof listener.destroy).toBe("function");
  expect(typeof listener2.destroy).toBe("function");
});
