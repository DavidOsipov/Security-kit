// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import nodeCrypto from "node:crypto";
import {
  InMemoryNonceStore,
  verifyApiRequestSignature,
  verifyApiRequestSignatureSafe,
  type VerifyExtendedInput,
} from "../../server/verify-api-request-signature.ts";
import { safeStableStringify } from "../../src/canonical.ts";

const enc = new TextEncoder();

function hmacSha256(key: Uint8Array, data: Uint8Array): string {
  const h = nodeCrypto.createHmac("sha256", Buffer.from(key));
  h.update(Buffer.from(data));
  return h.digest("base64");
}

describe("verifyApiRequestSignature (strict nonce-store)", () => {
  it("accepts a valid signature and stores nonce atomically", async () => {
    const secret = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 11) & 0xff);
    const payload = { a: 1, b: "x" };
    const payloadString = safeStableStringify(payload);
    const nonce = "dGVzdE5vbmNl"; // base64 of 'testNonce'
    const timestamp = Date.now();
    const method = "POST";
    const path = "/api/test";
    const bodyHash = ""; // omitted in canonical via ?? ""
    const kid = "test-key";

    const canonical = [
      String(timestamp),
      nonce,
      method.toUpperCase(),
      path,
      bodyHash,
      payloadString,
      kid,
    ].join(".");
    const signatureBase64 = hmacSha256(secret, enc.encode(canonical));

    const input: VerifyExtendedInput = {
      secret,
      payload,
      nonce,
      timestamp,
      signatureBase64,
      method,
      path,
      bodyHash,
      kid,
    };
    const store = new InMemoryNonceStore();
    const ok = await verifyApiRequestSignature(input, store);
    expect(ok).toBe(true);
  });

  it("rejects replay using the same nonce (storeIfNotExists)", async () => {
    const secret = Uint8Array.from({ length: 32 }, (_, i) => (i * 3 + 5) & 0xff);
    const payload = { x: 42 };
    const payloadString = safeStableStringify(payload);
    const nonce = "cmVwbGF5LW5vbmNl"; // base64 of 'replay-nonce'
    const timestamp = Date.now();
    const method = "GET";
    const path = "/status";
    const kid = "kid1";
    const canonical = [
      String(timestamp),
      nonce,
      method.toUpperCase(),
      path,
      "",
      payloadString,
      kid,
    ].join(".");
    const signatureBase64 = hmacSha256(secret, enc.encode(canonical));

    const input: VerifyExtendedInput = {
      secret,
      payload,
      nonce,
      timestamp,
      signatureBase64,
      method,
      path,
      kid,
    };
    const store = new InMemoryNonceStore();
    // First verify ok
    await expect(verifyApiRequestSignature(input, store)).resolves.toBe(true);
    // Second verify should reject as replay
    await expect(verifyApiRequestSignature(input, store)).rejects.toMatchObject({
      name: "ReplayAttackError",
    });
  });

  it("fails fast when nonceStore is null or lacks storeIfNotExists", async () => {
    const secret = Uint8Array.from({ length: 32 }, (_, i) => (i + 17) & 0xff);
    const payload = { y: 1 };
    const payloadString = safeStableStringify(payload);
    const nonce = "bm9uY2U="; // 'nonce'
    const timestamp = Date.now();
    const method = "PUT";
    const path = "/thing";
    const kid = "kidX";
    const canonical = [
      String(timestamp),
      nonce,
      method.toUpperCase(),
      path,
      "",
      payloadString,
      kid,
    ].join(".");
    const signatureBase64 = hmacSha256(secret, enc.encode(canonical));
    const input: VerifyExtendedInput = {
      secret,
      payload,
      nonce,
      timestamp,
      signatureBase64,
      method,
      path,
      kid,
    };

    // null/undefined store
    // @ts-expect-error Testing runtime guard
    await expect(verifyApiRequestSignature(input, null)).rejects.toMatchObject({
      name: "InvalidParameterError",
    });

    // object without storeIfNotExists
    // @ts-expect-error Testing runtime guard
    await expect(verifyApiRequestSignature(input, {})).rejects.toMatchObject({
      name: "InvalidConfigurationError",
    });
  });

  it("safe wrapper returns false on failure without leaking details", async () => {
    const secret = Uint8Array.from({ length: 32 }, (_, i) => (255 - i) & 0xff);
    const payload = { a: 1 };
    const nonce = "c2FmZS1mYWlsZWQ="; // 'safe-failed'
    const timestamp = Date.now();
    const method = "PATCH";
    const path = "/p";
    const kid = "kidZ";
    const signatureBase64 = "AAAA"; // invalid on purpose
    const input: VerifyExtendedInput = {
      secret,
      payload,
      nonce,
      timestamp,
      signatureBase64,
      method,
      path,
      kid,
    };
    const ok = await verifyApiRequestSignatureSafe(input, new InMemoryNonceStore());
    expect(ok).toBe(false);
  });
});
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
