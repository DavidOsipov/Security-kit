import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import {
  verifyApiRequestSignature,
  verifyApiRequestSignatureWithKeyProvider,
  InMemoryNonceStore,
} from "../../server/verify-api-request-signature";
import { SHARED_ENCODER } from "../../src/encoding";
import { safeStableStringify } from "../../src/canonical";
import {
  InvalidParameterError,
  ReplayAttackError,
  TimestampError,
} from "../../src/errors";

const u = (s: string) => new Uint8Array(Buffer.from(s));

function computeHmac(key: string | Buffer, message: Uint8Array) {
  return createHmac("sha256", key).update(message).digest();
}

function buildCanonical(input: any) {
  return safeStableStringify(input);
}

function buildServerCanonical(input: any) {
  const payloadString = safeStableStringify((input as any).payload);
  const canonicalParts = [
    String((input as any).timestamp),
    (input as any).nonce,
    ((input as any).method ?? "").toUpperCase(),
    (input as any).path ?? "",
    (input as any).bodyHash ?? "",
    payloadString,
    (input as any).kid ?? "",
  ];
  return SHARED_ENCODER.encode(canonicalParts.join("."));
}

describe("verify-api-request-signature — edge cases", () => {
  it("rejects timestamps far in the past and future", async () => {
    const secret = "test-secret-abc";
    const baseInput = {
      method: "POST",
      path: "/api/items",
      timestamp: Date.now() - 1000 * 60 * 60 * 24 * 365, // 1 year ago
      nonce: "nonce-1",
      bodyHash: "SGVsbG8=",
      kid: "k1",
    } as const;

    const canonical = SHARED_ENCODER.encode(buildCanonical(baseInput));
    const sig = computeHmac(secret, canonical).toString("base64");

    const store = new InMemoryNonceStore();

    await expect(
      verifyApiRequestSignature(
        { ...(baseInput as any), signatureBase64: sig, secret },
        store as any,
      ),
    ).rejects.toThrow(TimestampError);

    // future timestamp
    const future = {
      ...baseInput,
      timestamp: Date.now() + 1000 * 60 * 60 * 24 * 365,
    };
    const canonicalFuture = SHARED_ENCODER.encode(buildCanonical(future));
    const sigFuture = computeHmac(secret, canonicalFuture).toString("base64");

    await expect(
      verifyApiRequestSignature(
        { ...(future as any), signatureBase64: sigFuture, secret },
        store as any,
      ),
    ).rejects.toThrow(TimestampError);
  });

  it("does not call nonce store when signature mismatches", async () => {
    const secret = "zzz";
    const input = {
      method: "GET",
      path: "/health",
      timestamp: Date.now(),
      nonce: "n-mismatch",
      bodyHash: "",
      kid: "k1",
    } as const;

    const canonical = buildServerCanonical(input);
    // create a wrong signature by using a different key
    const wrongSig = computeHmac("wrong-key", canonical).toString("base64");

    const store = new InMemoryNonceStore();
    // spy-ish wrapper
    let called = false;
    const spyStore = {
      storeIfNotExists: async (nonce: string, ms: number) => {
        called = true;
        return (store as any).storeIfNotExists(nonce, ms);
      },
    } as any;

    await expect(
      verifyApiRequestSignature(
        { ...(input as any), signatureBase64: wrongSig, secret },
        spyStore,
      ),
    ).rejects.toThrow();

    expect(called).toBe(false);
  });

  it("rejects when nonceStore.storeIfNotExists is missing", async () => {
    const secret = "k";
    const input = {
      method: "GET",
      path: "/x",
      timestamp: Date.now(),
      nonce: "nonce-ok",
      bodyHash: "",
      kid: "k1",
    } as const;

    const canonical = buildServerCanonical(input);
    const sig = computeHmac(secret, canonical).toString("base64");

    const badStore = {} as any;

    await expect(
      verifyApiRequestSignature(
        { ...(input as any), signatureBase64: sig, secret },
        badStore,
      ),
    ).rejects.toThrow();
  });

  it("turns a false storeIfNotExists into a replay attack error", async () => {
    const secret = "a".repeat(64);
    const input = {
      method: "PUT",
      path: "/x",
      timestamp: Date.now(),
      nonce: "nonce-replay",
      bodyHash: "",
      kid: "k1",
    } as const;

    const canonical = buildServerCanonical(input);
    const sig = computeHmac(secret, canonical).toString("base64");

    const store = {
      storeIfNotExists: async () => false,
    } as any;

    const provider = async (kid: string) => SHARED_ENCODER.encode(secret);

    await expect(
      verifyApiRequestSignatureWithKeyProvider(
        { ...(input as any), signatureBase64: sig },
        store,
        { keyProvider: provider },
      ),
    ).rejects.toThrow(ReplayAttackError);
  });

  it("verifyApiRequestSignatureWithKeyProvider resolves and verifies", async () => {
    const secret = "k".repeat(64);
    const input = {
      method: "POST",
      path: "/kp",
      timestamp: Date.now(),
      nonce: "kp-1",
      bodyHash: "AA==",
      kid: "kids-1",
    } as const;

    const canonical = buildServerCanonical(input);
    const sig = computeHmac(secret, canonical).toString("base64");

    const provider = async (kid: string) => SHARED_ENCODER.encode(secret);
    const store = new InMemoryNonceStore();

    const ok = await verifyApiRequestSignatureWithKeyProvider(
      { ...(input as any), signatureBase64: sig },
      store,
      { keyProvider: provider },
    );
    expect(ok).toBe(true);
  });

  it("rejects invalid signature base64", async () => {
    const secret = "s";
    const input = {
      method: "GET",
      path: "/v",
      timestamp: Date.now(),
      nonce: "n-badb64",
      bodyHash: "",
      kid: "k1",
    } as const;

    // invalid base64
    await expect(
      verifyApiRequestSignature(
        { ...(input as any), signatureBase64: "!!notbase64!!", secret },
        new InMemoryNonceStore() as any,
      ),
    ).rejects.toThrow(InvalidParameterError);
  });
});
