// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
/**
 * Security tests for enhanced server verification functionality.
 * Tests the mitigations applied based on security audit feedback.
 */

import { describe, it, expect, beforeEach } from "vitest";
import crypto from "node:crypto";
import {
  verifyApiRequestSignature,
  verifyApiRequestSignatureSafe,
  InMemoryNonceStore,
  type INonceStore,
} from "../../server/verify-api-request-signature.js";
import { safeStableStringify } from "../../src/canonical.js";
import { SHARED_ENCODER } from "../../src/encoding.js";
import { getSecureRandomBytesSync } from "../../src/crypto.js";
import {
  InvalidParameterError,
  InvalidConfigurationError,
  ReplayAttackError,
  SignatureVerificationError,
} from "../../src/errors.js";

describe("Server API Signature Verification - Security Enhancements", () => {
  let nonceStore: InMemoryNonceStore;

  beforeEach(() => {
    nonceStore = new InMemoryNonceStore();
  });

  describe("Base64url signature acceptance", () => {
    it("accepts base64url-encoded signature", async () => {
      const secret = Buffer.from("a-strong-shared-secret-32bytes-min-please!");
  const kid = "0123456789abcdef0123456789abcdef";
      const payload = { foo: "bar" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      const payloadStr = safeStableStringify(payload);
      const canonical = [String(timestamp), nonce, "", "", "", payloadStr, kid].join(".");
      const msgBytes = SHARED_ENCODER.encode(canonical);

      const h = crypto.createHmac("sha256", secret);
      h.update(Buffer.from(msgBytes));
      const sigBytes = Uint8Array.from(h.digest());
      const b64 = Buffer.from(sigBytes).toString("base64");
      const b64url = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); // make base64url

      const ok = await verifyApiRequestSignature(
        {
          secret: secret.toString("base64"),
          payload,
          nonce,
          timestamp,
          signatureBase64: b64url,
          kid,
        },
        nonceStore,
      );

      expect(ok).toBe(true);
    });

    it("accepts standard base64-encoded signature", async () => {
      const secret = Buffer.from("another-strong-secret-key-32-bytes!!");
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      const payloadStr = safeStableStringify(payload);
      const canonical = [String(timestamp), nonce, "", "", "", payloadStr, ""].join(".");
      const msgBytes = SHARED_ENCODER.encode(canonical);

      const h = crypto.createHmac("sha256", secret);
      h.update(Buffer.from(msgBytes));
      const sigBytes = Uint8Array.from(h.digest());
      const b64 = Buffer.from(sigBytes).toString("base64"); // standard base64

      const ok = await verifyApiRequestSignature(
        {
          secret: secret.toString("base64"),
          payload,
          nonce,
          timestamp,
          signatureBase64: b64,
        },
        nonceStore,
      );

      expect(ok).toBe(true);
    });

    it("rejects invalid base64/base64url signatures", async () => {
      const secret = "test-secret-32-bytes-owasp-compliant-256bit-entropy-strength";
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      await expect(
        verifyApiRequestSignature(
          {
            secret,
            payload,
            nonce,
            timestamp,
            signatureBase64: "invalid!!!signature",
          },
          nonceStore,
        ),
      ).rejects.toThrow(InvalidParameterError);
    });
  });

  describe("Safe wrapper behavior", () => {
    it("returns false on invalid signature without throwing", async () => {
      const secret = "test-secret-32-bytes-owasp-compliant-256bit-entropy-strength";
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      const ok = await verifyApiRequestSignatureSafe(
        {
          secret,
          payload,
          nonce,
          timestamp,
          signatureBase64: "dGVzdA==", // valid base64 but wrong signature
        },
        nonceStore,
      );

      expect(ok).toBe(false);
    });

    it("returns false on invalid input without throwing", async () => {
      const ok = await verifyApiRequestSignatureSafe(
        {
          secret: "short",
          payload: "x",
          nonce: Buffer.from(getSecureRandomBytesSync(16)).toString("base64"),
          timestamp: Date.now(),
          signatureBase64: "dGVzdA==",
        } as any,
        nonceStore,
      );
      expect(ok).toBe(false);
    });

    it("returns true on valid signature", async () => {
      const secret = Buffer.from("a-strong-shared-secret-32bytes-min-please!");
      const payload = { foo: "bar" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      const payloadStr = safeStableStringify(payload);
      const canonical = [String(timestamp), nonce, "", "", "", payloadStr, ""].join(".");
      const msgBytes = SHARED_ENCODER.encode(canonical);

      const h = crypto.createHmac("sha256", secret);
      h.update(Buffer.from(msgBytes));
      const sigBytes = Uint8Array.from(h.digest());
      const b64 = Buffer.from(sigBytes).toString("base64");

      const ok = await verifyApiRequestSignatureSafe(
        {
          secret: secret.toString("base64"),
          payload,
          nonce,
          timestamp,
          signatureBase64: b64,
        },
        nonceStore,
      );

      expect(ok).toBe(true);
    });
  });

  describe("Typed error throwing behavior", () => {
    it("throws InvalidParameterError for weak secrets", async () => {
      const shortSecret = "short"; // Less than MIN_SECRET_BYTES after normalization
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      await expect(
        verifyApiRequestSignature(
          {
            secret: shortSecret,
            payload,
            nonce,
            timestamp,
            signatureBase64: "dGVzdA==",
          },
          nonceStore,
        ),
      ).rejects.toThrow(InvalidParameterError);
    });

    it("throws SignatureVerificationError for signature mismatch", async () => {
      const secret = Buffer.from("a-strong-shared-secret-32bytes-min-please!");
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      await expect(
        verifyApiRequestSignature(
          {
            secret: secret.toString("base64"),
            payload,
            nonce,
            timestamp,
            signatureBase64: "d3JvbmdTaWduYXR1cmU=", // valid base64 but wrong signature
          },
          nonceStore,
        ),
      ).rejects.toThrow(SignatureVerificationError);
    });

    it("throws ReplayAttackError for duplicate nonce", async () => {
      const secret = Buffer.from("a-strong-shared-secret-32bytes-min-please!");
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      const payloadStr = safeStableStringify(payload);
      const canonical = [String(timestamp), nonce, "", "", "", payloadStr, ""].join(".");
      const msgBytes = SHARED_ENCODER.encode(canonical);

      const h = crypto.createHmac("sha256", secret);
      h.update(Buffer.from(msgBytes));
      const sigBytes = Uint8Array.from(h.digest());
      const b64 = Buffer.from(sigBytes).toString("base64");

      const input = {
        secret: secret.toString("base64"),
        payload,
        nonce,
        timestamp,
        signatureBase64: b64,
      };

      // First verification should succeed
      const ok1 = await verifyApiRequestSignature(input, nonceStore);
      expect(ok1).toBe(true);

      // Second verification with same nonce should fail
      await expect(verifyApiRequestSignature(input, nonceStore)).rejects.toThrow(ReplayAttackError);
    });
  });

  describe("Atomic nonce operations enforcement", () => {
    class NonAtomicNonceStore implements INonceStore {
      #map = new Map<string, number>();

      async has(kid: string, nonce: string): Promise<boolean> {
        const key = `${kid}:${nonce}`;
        const exp = this.#map.get(key);
        return typeof exp === "number" && exp > Date.now();
      }

      async store(kid: string, nonce: string, ttlMs: number): Promise<void> {
        const key = `${kid}:${nonce}`;
        this.#map.set(key, Date.now() + ttlMs);
      }

      async cleanup(): Promise<void> {
        const now = Date.now();
        for (const [k, exp] of this.#map.entries()) {
          if (exp <= now) this.#map.delete(k);
        }
      }
      // No storeIfNotExists or reserve methods
    }

    it("throws InvalidConfigurationError when nonce store lacks atomic methods", async () => {
      const nonAtomicStore = new NonAtomicNonceStore();
      const secret = Buffer.from("a-strong-shared-secret-32bytes-min-please!");

      await expect(
        verifyApiRequestSignature(
          {
            secret: secret.toString("base64"),
            payload: { test: "data" },
            nonce: Buffer.from(getSecureRandomBytesSync(16)).toString("base64"),
            timestamp: Date.now(),
            signatureBase64: "dGVzdA==",
          },
          nonAtomicStore,
        ),
      ).rejects.toThrow(InvalidConfigurationError);
    });

    it("succeeds with atomic storeIfNotExists method", async () => {
      const secret = Buffer.from("a-strong-shared-secret-32bytes-min-please!");
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      const payloadStr = safeStableStringify(payload);
      const canonical = [String(timestamp), nonce, "", "", "", payloadStr, ""].join(".");
      const msgBytes = SHARED_ENCODER.encode(canonical);

      const h = crypto.createHmac("sha256", secret);
      h.update(Buffer.from(msgBytes));
      const sigBytes = Uint8Array.from(h.digest());
      const b64 = Buffer.from(sigBytes).toString("base64");

      // InMemoryNonceStore has storeIfNotExists
      const ok = await verifyApiRequestSignature(
        {
          secret: secret.toString("base64"),
          payload,
          nonce,
          timestamp,
          signatureBase64: b64,
        },
        nonceStore,
      );

      expect(ok).toBe(true);
    });
  });

  describe("Secret normalization and validation", () => {
    it("validates secret byte length after base64 decoding", async () => {
      // This base64 string decodes to only 8 bytes (below MIN_SECRET_BYTES=16)
      const shortBase64Secret = "dGVzdGtleQ=="; // "testkey" in base64 = 7 bytes
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      await expect(
        verifyApiRequestSignature(
          {
            secret: shortBase64Secret,
            payload,
            nonce,
            timestamp,
            signatureBase64: "dGVzdA==",
          },
          nonceStore,
        ),
      ).rejects.toThrow(InvalidParameterError);
    });

    it("accepts UTF-8 secrets that are not base64-like", async () => {
      const utfSecret = "this-is-a-strong-utf8-secret-key-32-plus-chars!"; // 48 chars > 32 bytes
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      const payloadStr = safeStableStringify(payload);
      const canonical = [String(timestamp), nonce, "", "", "", payloadStr, ""].join(".");
      const msgBytes = SHARED_ENCODER.encode(canonical);

      const secretBytes = Buffer.from(utfSecret, "utf8");
      const h = crypto.createHmac("sha256", secretBytes);
      h.update(Buffer.from(msgBytes));
      const sigBytes = Uint8Array.from(h.digest());
      const b64 = Buffer.from(sigBytes).toString("base64");

      const ok = await verifyApiRequestSignature(
        {
          secret: utfSecret,
          payload,
          nonce,
          timestamp,
          signatureBase64: b64,
        },
        nonceStore,
      );

      expect(ok).toBe(true);
    });

    it("accepts base64-encoded secrets correctly", async () => {
      const secretBytes = getSecureRandomBytesSync(32); // 32 bytes
      const base64Secret = Buffer.from(secretBytes).toString("base64");
      const payload = { test: "data" };
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString("base64");

      const payloadStr = safeStableStringify(payload);
      const canonical = [String(timestamp), nonce, "", "", "", payloadStr, ""].join(".");
      const msgBytes = SHARED_ENCODER.encode(canonical);

      const h = crypto.createHmac("sha256", Buffer.from(secretBytes));
      h.update(Buffer.from(msgBytes));
      const sigBytes = Uint8Array.from(h.digest());
      const b64 = Buffer.from(sigBytes).toString("base64");

      const ok = await verifyApiRequestSignature(
        {
          secret: base64Secret,
          payload,
          nonce,
          timestamp,
          signatureBase64: b64,
        },
        nonceStore,
      );

      expect(ok).toBe(true);
    });
  });

  describe("Enhanced input validation", () => {
    it("validates path traversal patterns", async () => {
      const secret = Buffer.from("a-strong-shared-secret-32bytes-min-please!");

      await expect(
        verifyApiRequestSignature(
          {
            secret: secret.toString("base64"),
            payload: { test: "data" },
            nonce: Buffer.from(getSecureRandomBytesSync(16)).toString("base64"),
            timestamp: Date.now(),
            signatureBase64: "dGVzdA==",
            path: "/api/../admin/secret", // path traversal attempt
          },
          nonceStore,
        ),
      ).rejects.toThrow(InvalidParameterError);
    });

    it("validates nonce is standard base64 format", async () => {
      const secret = Buffer.from("a-strong-shared-secret-32bytes-min-please!");

      await expect(
        verifyApiRequestSignature(
          {
            secret: secret.toString("base64"),
            payload: { test: "data" },
            nonce: "invalid-nonce-with-special-chars!@#",
            timestamp: Date.now(),
            signatureBase64: "dGVzdA==",
          },
          nonceStore,
        ),
      ).rejects.toThrow(InvalidParameterError);
    });

    it("validates kid format", async () => {
      const secret = Buffer.from("a-strong-shared-secret-32bytes-min-please!");

      await expect(
        verifyApiRequestSignature(
          {
            secret: secret.toString("base64"),
            payload: { test: "data" },
            nonce: Buffer.from(getSecureRandomBytesSync(16)).toString("base64"),
            timestamp: Date.now(),
            signatureBase64: "dGVzdA==",
            kid: "invalid kid with spaces",
          },
          nonceStore,
        ),
      ).rejects.toThrow(InvalidParameterError);
    });
  });
});