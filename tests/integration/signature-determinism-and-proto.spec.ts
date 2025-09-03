import { describe, it, expect, beforeEach } from "vitest";
import crypto from "node:crypto";

import {
  verifyApiRequestSignature,
  InMemoryNonceStore,
  type VerifyExtendedInput,
} from "../../server/verify-api-request-signature";
import { safeStableStringify } from "../../src/canonical";

function hmacSha256Base64(key: Buffer | Uint8Array, message: string) {
  const h = crypto.createHmac("sha256", Buffer.from(key));
  h.update(message, "utf8");
  return h.digest("base64");
}

describe("Signature determinism and proto-pollution handling (integration)", () => {
  let nonceStore: InMemoryNonceStore;
  const secretRaw = Buffer.from(
    "deterministic-secret-key-32bytes-minimum-length!!",
  );
  const nonce = Buffer.from("fixed-nonce-for-test").toString("base64");

  beforeEach(() => {
    nonceStore = new InMemoryNonceStore();
  });

  it("signatures remain identical across object key order permutations", async () => {
    const timestamp = Date.now();
    const payload1 = { b: 2, a: 1, nested: { y: 2, x: 1 } };
    const payload2 = { a: 1, nested: { x: 1, y: 2 }, b: 2 };

    const s1 = safeStableStringify(payload1);
    const s2 = safeStableStringify(payload2);
    expect(s1).toBe(s2);

    const canonical = [String(timestamp), nonce, "", "", "", s1, ""].join(".");
    const signatureBase64 = hmacSha256Base64(secretRaw, canonical);

    const input1: VerifyExtendedInput = {
      secret: secretRaw.toString("base64"),
      payload: payload1,
      nonce,
      timestamp,
      signatureBase64,
    };
    const ok1 = await verifyApiRequestSignature(input1, nonceStore, {
      maxSkewMs: 60_000,
    });
    expect(ok1).toBe(true);

    // Allow reuse of the same nonce for the second verification strictly for this determinism test
    await nonceStore.delete("default", nonce);

    const input2: VerifyExtendedInput = {
      secret: secretRaw.toString("base64"),
      payload: payload2,
      nonce,
      timestamp,
      signatureBase64,
    };
    const ok2 = await verifyApiRequestSignature(input2, nonceStore, {
      maxSkewMs: 60_000,
    });
    expect(ok2).toBe(true);
  });

  it("proto-pollution keys are ignored and do not affect signatures", async () => {
    const timestamp = Date.now();
    const clean = { a: 1, nested: { b: 2 } } as any;
    const polluted = {
      a: 1,
      nested: { b: 2, __proto__: { hacked: true } },
      __proto__: "forbidden",
      constructor: {},
      prototype: {},
    } as any;

    const sClean = safeStableStringify(clean);
    const sPolluted = safeStableStringify(polluted);
    expect(sClean).toBe(sPolluted);

    const canonical = [String(timestamp), nonce, "", "", "", sClean, ""].join(
      ".",
    );
    const signatureBase64 = hmacSha256Base64(secretRaw, canonical);

    const inputClean: VerifyExtendedInput = {
      secret: secretRaw.toString("base64"),
      payload: clean,
      nonce,
      timestamp,
      signatureBase64,
    };
    const ok1 = await verifyApiRequestSignature(inputClean, nonceStore, {
      maxSkewMs: 60_000,
    });
    expect(ok1).toBe(true);

    // Allow reuse of the same nonce for the second verification strictly for this determinism test
    await nonceStore.delete("default", nonce);

    const inputPolluted: VerifyExtendedInput = {
      secret: secretRaw.toString("base64"),
      payload: polluted,
      nonce,
      timestamp,
      signatureBase64,
    };
    const ok2 = await verifyApiRequestSignature(inputPolluted, nonceStore, {
      maxSkewMs: 60_000,
    });
    expect(ok2).toBe(true);
  });
});
