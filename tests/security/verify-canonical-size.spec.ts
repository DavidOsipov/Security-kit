// SPDX-License-Identifier: LGPL-3.0-or-later
// Basic test for canonical message size cap in server verifier
import { describe, it, expect } from "vitest";
import {
  verifyApiRequestSignature,
  InMemoryNonceStore,
} from "../../server/verify-api-request-signature";

const enc = new TextEncoder();

function makeInput(overBytes: number) {
  const hugePayload = "x".repeat(overBytes);
  return {
    secret: new Uint8Array(32).fill(1),
    payload: { hugePayload },
    nonce: "QUFBQUFBQUFBQUFBQUFBQQ==", // base64('AAAAAAAAAAAAAA')
    timestamp: Date.now(),
    signatureBase64: "AAECAw==", // dummy; we expect pre-HMAC size check to fail
  } as any;
}

describe("verifyApiRequestSignature - canonical size cap", () => {
  it("rejects oversized canonical messages", async () => {
    const input = makeInput(70 * 1024); // will exceed 64KiB after framing
    const store = new InMemoryNonceStore();
    await expect(verifyApiRequestSignature(input, store)).rejects.toThrow(
      /Canonical message too large/,
    );
  });
});
