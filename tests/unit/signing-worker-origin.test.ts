import { test, expect } from "vitest";

// Enable test API guard for this module
process.env.SECURITY_KIT_ALLOW_TEST_APIS = "true";

test("signing-worker-origin: test API available and works", async () => {
  const worker = await import("../../src/worker/signing-worker");
  expect(typeof worker.__test_validateHandshakeNonce === "function").toBe(true);
  const ok = worker.__test_validateHandshakeNonce?.("example-nonce");
  // Should be a boolean (true/false) depending on config; at minimum it should not throw
  expect(typeof ok === "boolean").toBe(true);
});
