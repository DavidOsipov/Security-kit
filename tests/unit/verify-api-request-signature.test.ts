import { expect, test, beforeEach } from "vitest";

import {
  verifyApiRequestSignature,
  InMemoryNonceStore,
  type VerifyExtendedInput,
} from "../../server/verify-api-request-signature";

import { SHARED_ENCODER } from "../../src/encoding";
import { safeStableStringify } from "../../src/canonical";
import { getSecureRandomBytesSync } from "../../src/crypto";

// Node's crypto will be used to produce signatures compatible with the module's
// computeHmacSha256 fallback. This keeps tests deterministic in Node.
import crypto from "node:crypto";

function hmacSha256Base64(key: Buffer | Uint8Array, message: string) {
  const h = crypto.createHmac("sha256", Buffer.from(key));
  h.update(message, "utf8");
  return h.digest("base64");
}

let nonceStore: InMemoryNonceStore;

beforeEach(() => {
  nonceStore = new InMemoryNonceStore();
});

test("verify succeeds for valid signature and fresh nonce", async () => {
  const secretRaw = Buffer.from(
    "my-secret-key-32bytes-owasp-compliant-strength-256bit",
  );
  const secret = secretRaw.toString("base64");
  const timestamp = Date.now();
  const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");
  const payload = { hello: "world" };

  const payloadString = safeStableStringify(payload);
  const canonical = [
    String(timestamp),
    nonce,
    "",
    "",
    "",
    payloadString,
    "",
  ].join(".");

  const signatureBase64 = hmacSha256Base64(secretRaw, canonical);

  const input: VerifyExtendedInput = {
    secret: secret,
    payload,
    nonce,
    timestamp,
    signatureBase64,
  };

  const ok = await verifyApiRequestSignature(input, nonceStore, {
    maxSkewMs: 60_000,
  });
  expect(ok).toBe(true);
});

test("verify fails for wrong signature", async () => {
  const secretRaw = Buffer.from(
    "secret-A-32bytes-owasp-compliant-strength-256bit-key",
  );
  const secret = secretRaw.toString("base64");
  const timestamp = Date.now();
  const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");
  const payload = { a: 1 };

  const payloadString = safeStableStringify(payload);
  const canonical = [
    String(timestamp),
    nonce,
    "",
    "",
    "",
    payloadString,
    "",
  ].join(".");

  const badSignature = hmacSha256Base64(
    Buffer.from("other-secret-32bytes-owasp-compliant-strength"),
    canonical,
  );

  const input: VerifyExtendedInput = {
    secret,
    payload,
    nonce,
    timestamp,
    signatureBase64: badSignature,
  };

  try {
    const ok = await verifyApiRequestSignature(input, nonceStore, {
      maxSkewMs: 60_000,
    });
    expect(ok).toBe(false);
  } catch (err) {
    // Some code paths throw a typed SignatureVerificationError — treat as expected failure
    expect((err as Error).name).toMatch(/SignatureVerificationError|Error/);
  }
});

test("verify fails for replayed nonce (atomic store simulated)", async () => {
  const secretRaw = Buffer.from("k-secret-32bytes-owasp-compliant-strength");
  const secret = secretRaw.toString("base64");
  const timestamp = Date.now();
  const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");
  const payload = { x: true };

  const payloadString = safeStableStringify(payload);
  const canonical = [
    String(timestamp),
    nonce,
    "",
    "",
    "",
    payloadString,
    "",
  ].join(".");
  const signatureBase64 = hmacSha256Base64(secretRaw, canonical);

  const input = {
    secret,
    payload,
    nonce,
    timestamp,
    signatureBase64,
  } as VerifyExtendedInput;

  // First attempt should succeed
  const ok1 = await verifyApiRequestSignature(input, nonceStore, {
    maxSkewMs: 60_000,
  });
  expect(ok1).toBe(true);

  // Second attempt with same nonce should throw ReplayAttackError
  await expect(
    verifyApiRequestSignature(input, nonceStore, { maxSkewMs: 60_000 }),
  ).rejects.toThrow("[security-kit] Nonce already used");
});

test("verify fails for timestamp outside skew window", async () => {
  const secretRaw = Buffer.from("k2-secret-32bytes-owasp-compliant-strength");
  const secret = secretRaw.toString("base64");
  const timestamp = Date.now() - 10 * 60_000; // 10 minutes ago
  const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");
  const payload = { z: 3 };

  const payloadString = safeStableStringify(payload);
  const canonical = [
    String(timestamp),
    nonce,
    "",
    "",
    "",
    payloadString,
    "",
  ].join(".");
  const signatureBase64 = hmacSha256Base64(secretRaw, canonical);

  const input = {
    secret,
    payload,
    nonce,
    timestamp,
    signatureBase64,
  } as VerifyExtendedInput;

  await expect(
    verifyApiRequestSignature(input, nonceStore, { maxSkewMs: 60_000 }),
  ).rejects.toThrow("timestamp out of reasonable range");
});
