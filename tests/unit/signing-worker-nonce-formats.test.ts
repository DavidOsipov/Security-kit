import { test, expect } from "vitest";

// Enable test API guard for this module
process.env.SECURITY_KIT_ALLOW_TEST_APIS = "true";

test("signing-worker: accepts base64url nonces when allowed", async () => {
  const worker = await import("../../src/worker/signing-worker");
  // a short base64url nonce (unpadded)
  const nonce = "abcd-ef_";
  const ok = worker.__test_validateHandshakeNonce(nonce);
  expect(ok).toBe(true);
});

test("signing-worker: rejects invalid base64url nonces", async () => {
  const worker = await import("../../src/worker/signing-worker");
  const nonce = "!*notvalid*";
  const ok = worker.__test_validateHandshakeNonce(nonce);
  expect(ok).toBe(false);
});
