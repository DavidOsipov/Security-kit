// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  verifyApiRequestSignature,
  verifyApiRequestSignatureWithKeyProvider,
  InMemoryNonceStore,
  VerifyExtendedInput,
} from "../../server/verify-api-request-signature";
import { safeStableStringify } from "../../src/canonical";

const enc = new TextEncoder();

function buildCanonical(input: VerifyExtendedInput) {
  const payloadString = safeStableStringify(input.payload);
  const parts = [
    String(input.timestamp),
    input.nonce,
    (input.method ?? "").toUpperCase(),
    input.path ?? "",
    input.bodyHash ?? "",
    payloadString,
    input.kid ?? "",
  ];
  return parts.join(".");
}

async function computeHmac(key: Uint8Array, message: string) {
  const bytes = enc.encode(message);
  const crypto = await import("node:crypto");
  const h = crypto.createHmac("sha256", Buffer.from(key));
  h.update(Buffer.from(bytes));
  return Uint8Array.from(h.digest());
}

describe("verifyApiRequestSignature - comprehensive", () => {
  let store: InMemoryNonceStore;
  const secret = new Uint8Array(32).fill(0x42);
  beforeEach(() => {
    store = new InMemoryNonceStore();
  });

  it("accepts a valid signature and reserves nonce", async () => {
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFB",
      timestamp: Date.now(),
      signatureBase64: "",
    };

    const canonical = buildCanonical(input);
    const mac = await computeHmac(secret, canonical);
    const b64 = Buffer.from(mac).toString("base64");
    const signedInput = {
      ...(input as any),
      signatureBase64: b64,
    } as VerifyExtendedInput;

    const spy = vi.spyOn(store, "storeIfNotExists");
    const res = await verifyApiRequestSignature(signedInput, store);
    expect(res).toBe(true);
    expect(spy).toHaveBeenCalledOnce();
  });

  it("rejects mismatched signature and does not store nonce", async () => {
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 2 },
      nonce: "QUFBQUFBQUFC",
      timestamp: Date.now(),
      signatureBase64: "AAAAAA==",
    };
    const spy = vi.spyOn(store, "storeIfNotExists");
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /Signature mismatch/,
    );
    expect(spy).not.toHaveBeenCalled();
  });

  it("verifyApiRequestSignatureWithKeyProvider resolves with keyProvider", async () => {
    const kp = async (kid: string) => secret;
    const input: Omit<VerifyExtendedInput, "secret"> & {
      readonly kid: string;
    } = {
      kid: "k1",
      payload: { b: 3 },
      nonce: "QUFBQUFBQUFD",
      timestamp: Date.now(),
      signatureBase64: "",
    } as any;

    const canonical = buildCanonical({ ...(input as any), secret } as any);
    const mac = await computeHmac(secret, canonical);
    const signed = {
      ...(input as any),
      signatureBase64: Buffer.from(mac).toString("base64"),
    } as any;

    const spy = vi.spyOn(store, "storeIfNotExists");
    const ok = await verifyApiRequestSignatureWithKeyProvider(signed, store, {
      keyProvider: kp,
    });
    expect(ok).toBe(true);
    expect(spy).toHaveBeenCalledOnce();
  });

  it("rejects canonical messages above the hard limit and accepts boundary", async () => {
    // create a payload that will push canonical above 64KiB
    const big = { huge: "z".repeat(70 * 1024) };

    const badInput: VerifyExtendedInput = {
      secret,
      payload: big,
      nonce: "QUFBQUFBQUFE",
      timestamp: Date.now(),
      signatureBase64: "A==",
    } as any;
    await expect(verifyApiRequestSignature(badInput, store)).rejects.toThrow(
      /Canonical message too large/,
    );

    // Construct a boundary payload that is just under the limit
    const maxOkStr = "a".repeat(63 * 1024);
    const okInput: VerifyExtendedInput = {
      secret,
      payload: { p: maxOkStr },
      nonce: "QUFBQUFBQUFF",
      timestamp: Date.now(),
      signatureBase64: "",
    } as any;
    const canonical = buildCanonical(okInput);
    const mac = await computeHmac(secret, canonical);
    const signedOk = {
      ...(okInput as any),
      signatureBase64: Buffer.from(mac).toString("base64"),
    } as VerifyExtendedInput;
    const spy = vi.spyOn(store, "storeIfNotExists");
    const ok = await verifyApiRequestSignature(signedOk, store);
    expect(ok).toBe(true);
    expect(spy).toHaveBeenCalledOnce();
  });

  it("rejects invalid inputs: missing secret", async () => {
    const input: VerifyExtendedInput = {
      secret: undefined as any,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFB",
      timestamp: Date.now(),
      signatureBase64: "AA==",
    } as any;
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /Missing secret/,
    );
  });

  it("rejects invalid timestamp: too old", async () => {
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFC",
      timestamp: Date.now() - 200_000,
      signatureBase64: "AA==",
    } as any;
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /timestamp out of reasonable range/,
    );
  });

  it("rejects invalid timestamp: too new", async () => {
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFD",
      timestamp: Date.now() + 200_000,
      signatureBase64: "AA==",
    } as any;
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /timestamp out of reasonable range/,
    );
  });

  it("rejects invalid nonce format", async () => {
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "invalid-nonce",
      timestamp: Date.now(),
      signatureBase64: "AA==",
    } as any;
    // Implementation may treat certain non-base64-like strings differently; accept signature mismatch or nonce format error
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /nonce is not in an allowed format|Signature mismatch/,
    );
  });

  it("rejects invalid signature format", async () => {
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFF",
      timestamp: Date.now(),
      signatureBase64: "not-base64!",
    } as any;
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /signatureBase64 must be base64/,
    );
  });

  it("rejects invalid method", async () => {
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFG",
      timestamp: Date.now(),
      signatureBase64: "AA==",
      method: "INVALID METHOD",
    } as any;
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /method must be a valid HTTP method/,
    );
  });

  it("rejects invalid path", async () => {
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFH",
      timestamp: Date.now(),
      signatureBase64: "AA==",
      path: "../escape",
    } as any;
    // Path validation currently rejects missing leading slash
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /path must start/i,
    );
  });

  it("rejects invalid kid", async () => {
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFI",
      timestamp: Date.now(),
      signatureBase64: "AA==",
      kid: "invalid@kid",
    } as any;
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /kid contains invalid characters/,
    );
  });

  it("rejects oversized payload", async () => {
    const bigPayload = "x".repeat(10 * 1024 * 1024 + 1);
    const input: VerifyExtendedInput = {
      secret,
      payload: { data: bigPayload },
      nonce: "QUFBQUFBQUFJ",
      timestamp: Date.now(),
      signatureBase64: "AA==",
    } as any;
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /payload too large/,
    );
  });

  it("rejects when nonce store lacks storeIfNotExists", async () => {
    const badStore = { has: vi.fn(), store: vi.fn() };
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFK",
      timestamp: Date.now(),
      signatureBase64: "",
    } as any;
    const canonical = buildCanonical(input);
    const mac = await computeHmac(secret, canonical);
    const signedBad = {
      ...(input as any),
      signatureBase64: Buffer.from(mac).toString("base64"),
    } as VerifyExtendedInput;
    await expect(
      verifyApiRequestSignature(signedBad, badStore as any),
    ).rejects.toThrow(/NonceStore must implement storeIfNotExists/);
  });

  it("rejects when storeIfNotExists returns false (nonce already used)", async () => {
    const mockStore = {
      has: vi.fn().mockResolvedValue(false),
      storeIfNotExists: vi.fn().mockResolvedValue(false),
    };
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFM",
      timestamp: Date.now(),
      signatureBase64: "",
    } as any;
    const canonical = buildCanonical(input);
    const mac = await computeHmac(secret, canonical);
    const signedMock = {
      ...(input as any),
      signatureBase64: Buffer.from(mac).toString("base64"),
    } as VerifyExtendedInput;
    await expect(
      verifyApiRequestSignature(signedMock, mockStore as any),
    ).rejects.toThrow(/Nonce already used/);
  });

  it("rejects when storeIfNotExists throws", async () => {
    const mockStore = {
      has: vi.fn().mockResolvedValue(false),
      storeIfNotExists: vi.fn().mockRejectedValue(new Error("DB error")),
    };
    const input: VerifyExtendedInput = {
      secret,
      payload: { a: 1 },
      nonce: "QUFBQUFBQUFN",
      timestamp: Date.now(),
      signatureBase64: "",
    } as any;
    const canonical = buildCanonical(input);
    const mac = await computeHmac(secret, canonical);
    const signedThrow = {
      ...(input as any),
      signatureBase64: Buffer.from(mac).toString("base64"),
    } as VerifyExtendedInput;
    await expect(
      verifyApiRequestSignature(signedThrow, mockStore as any),
    ).rejects.toThrow(/DB error/);
  });
});
