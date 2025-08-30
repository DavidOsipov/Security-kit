import { test, expect } from "vitest";

// Enable test API guard for this module
process.env.SECURITY_KIT_ALLOW_TEST_APIS = "true";

test("signing-worker: __test_validateHandshakeNonce accepts reasonable nonces", async () => {
  const worker = await import("../../src/worker/signing-worker");
  const ok = worker.__test_validateHandshakeNonce("short-nonce");
  expect(ok).toBe(true);
});

test("signing-worker: __test_validateHandshakeNonce rejects overly long nonces", async () => {
  const worker = await import("../../src/worker/signing-worker");
  const long = "a".repeat(2000);
  const ok = worker.__test_validateHandshakeNonce(long);
  expect(ok).toBe(false);
});
