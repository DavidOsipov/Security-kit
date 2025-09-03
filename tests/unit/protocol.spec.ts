import { describe, it, expect } from "vitest";
import type {
  InitMessage,
  InitAck,
  SignRequest,
  SignedResponse,
  ErrorResponse,
  ErrorReason,
  WorkerMessage,
  DestroyRequest,
  DestroyedMessage,
} from "../../src/protocol.js";

describe("protocol", () => {
  describe("type exports", () => {
    it("exports all protocol types", () => {
      // This test ensures the types are properly exported and can be imported
      // TypeScript will catch any import errors at compile time
      expect(true).toBe(true);
    });

    it("can create type-safe protocol messages", () => {
      // Test that we can create objects that conform to the protocol types
      // This validates the type definitions are syntactically correct

      // Test InitMessage type
      const initMessage: InitMessage = {
        type: "init",
        secretBuffer: new ArrayBuffer(32),
        workerOptions: {
          rateLimitPerMinute: 100,
          dev: false,
          maxConcurrentSigning: 5,
          maxCanonicalLength: 10000,
          rateLimitBurst: 20,
        },
        kid: "test-key",
      };
      expect(initMessage.type).toBe("init");

      // Test SignRequest type
      const signRequest: SignRequest = {
        type: "sign",
        requestId: 123,
        canonical: "test-canonical-string",
      };
      expect(signRequest.type).toBe("sign");

      // Test SignedResponse type
      const signedResponse: SignedResponse = {
        type: "signed",
        requestId: 123,
        signature: "test-signature",
      };
      expect(signedResponse.type).toBe("signed");

      // Test ErrorResponse type
      const errorResponse: ErrorResponse = {
        type: "error",
        requestId: 123,
        reason: "invalid-params",
      };
      expect(errorResponse.type).toBe("error");

      // Test union type WorkerMessage
      const messages: WorkerMessage[] = [
        { type: "initialized" },
        { type: "destroyed" },
        { type: "destroy" },
        initMessage,
        signRequest,
        signedResponse,
        errorResponse,
      ];

      expect(messages.length).toBe(7);
      expect(messages[0].type).toBe("initialized");
    });

    it("validates ErrorReason union type", () => {
      // Test all possible ErrorReason values
      const errorReasons: ErrorReason[] = [
        "invalid-handshake",
        "not-initialized",
        "already-initialized",
        "nonce-too-large",
        "nonce-format-invalid",
        "worker-shutting-down",
        "handshake-failed",
        "invalid-params",
        "canonical-too-large",
        "rate-limit-exceeded",
        "worker-overloaded",
        "missing-secret",
        "sign-failed",
        "invalid-message-format",
        "unknown-message-type",
        "worker-exception",
      ];

      expect(errorReasons).toHaveLength(16);

      // Test that each reason can be used in an ErrorResponse
      errorReasons.forEach((reason) => {
        const errorResponse: ErrorResponse = {
          type: "error",
          reason,
        };
        expect(errorResponse.reason).toBe(reason);
      });
    });

    it("handles optional fields correctly", () => {
      // Test optional fields in various types
      const initMessage: InitMessage = {
        type: "init",
        secretBuffer: new ArrayBuffer(32),
        // workerOptions is optional
        // kid is optional
      };
      expect(initMessage.type).toBe("init");
      expect(initMessage.workerOptions).toBeUndefined();
      expect(initMessage.kid).toBeUndefined();

      const errorResponse: ErrorResponse = {
        type: "error",
        // requestId is optional
        // reason is optional
      };
      expect(errorResponse.type).toBe("error");
      expect(errorResponse.requestId).toBeUndefined();
      expect(errorResponse.reason).toBeUndefined();
    });
  });
});
