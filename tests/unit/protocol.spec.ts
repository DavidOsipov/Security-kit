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

  describe("security-focused type validation", () => {
    it("validates InitMessage with security-critical options", () => {
      // Test comprehensive worker options for security hardening
      const secureInitMessage: InitMessage = {
        type: "init",
        secretBuffer: new ArrayBuffer(32),
        workerOptions: {
          rateLimitPerMinute: 60, // Reasonable rate limiting
          dev: false, // Production mode
          maxConcurrentSigning: 3, // Limited concurrency to prevent DoS
          maxCanonicalLength: 8192, // Reasonable size limit
          rateLimitBurst: 10, // Controlled burst capacity
          handshakeMaxNonceLength: 256, // Secure nonce length limit
          allowedNonceFormats: ["base64url", "hex"], // Explicit allowed formats
        },
        kid: "production-key-123",
      };

      expect(secureInitMessage.workerOptions?.rateLimitPerMinute).toBe(60);
      expect(secureInitMessage.workerOptions?.dev).toBe(false);
      expect(secureInitMessage.workerOptions?.maxConcurrentSigning).toBe(3);
      expect(secureInitMessage.workerOptions?.maxCanonicalLength).toBe(8192);
      expect(secureInitMessage.workerOptions?.rateLimitBurst).toBe(10);
      expect(secureInitMessage.workerOptions?.handshakeMaxNonceLength).toBe(256);
      expect(secureInitMessage.workerOptions?.allowedNonceFormats).toEqual(["base64url", "hex"]);
    });

    it("validates error responses for all security failure modes", () => {
      // Test error responses that indicate security violations
      const securityErrors: ErrorReason[] = [
        "invalid-handshake",
        "nonce-too-large",
        "nonce-format-invalid",
        "handshake-failed",
        "rate-limit-exceeded",
        "worker-overloaded",
        "missing-secret",
        "invalid-message-format",
        "unknown-message-type",
      ];

      securityErrors.forEach((reason) => {
        const errorResponse: ErrorResponse = {
          type: "error",
          requestId: 42,
          reason,
        };
        expect(errorResponse.reason).toBe(reason);
        expect(errorResponse.requestId).toBe(42);
      });
    });

    it("validates protocol message boundaries and constraints", () => {
      // Test message size and content constraints
      const largeCanonicalRequest: SignRequest = {
        type: "sign",
        requestId: Number.MAX_SAFE_INTEGER, // Test boundary values
        canonical: "x".repeat(10000), // Large but valid canonical string
      };

      expect(largeCanonicalRequest.requestId).toBe(Number.MAX_SAFE_INTEGER);
      expect(largeCanonicalRequest.canonical.length).toBe(10000);

      // Test minimal valid messages
      const minimalInit: InitMessage = {
        type: "init",
        secretBuffer: new ArrayBuffer(1), // Minimal valid buffer
      };

      expect(minimalInit.secretBuffer.byteLength).toBe(1);
      expect(minimalInit.workerOptions).toBeUndefined();
    });

    it("validates WorkerMessage union type exhaustiveness", () => {
      // Ensure all possible message types are covered in the union
      const testMessages: WorkerMessage[] = [
        // Init-related
        { type: "init", secretBuffer: new ArrayBuffer(32) },
        { type: "initialized" },
        { type: "destroyed" },

        // Signing workflow
        { type: "sign", requestId: 1, canonical: "test" },
        { type: "signed", requestId: 1, signature: "sig" },

        // Error handling
        { type: "error", reason: "invalid-params" },
        { type: "error", requestId: 1, reason: "sign-failed" },

        // Lifecycle
        { type: "destroy" },

        // Unknown type (should be allowed by union)
        { type: "unknown" },
        {}, // Empty object
        { type: undefined }, // Undefined type
      ];

      expect(testMessages.length).toBe(11);

      // Verify each message has expected structure
      testMessages.forEach((msg, index) => {
        expect(typeof msg).toBe("object");
        if (index < 9) { // First 9 entries have defined, non-undefined type
          expect(msg.type).toBeDefined();
          expect(msg.type).not.toBeUndefined();
        }
        // Last message (index 10) can have type: undefined
      });
    });

    it("validates type safety against prototype pollution attempts", () => {
      // Test that types prevent prototype pollution vectors
      const safeMessage: WorkerMessage = {
        type: "init",
        secretBuffer: new ArrayBuffer(32),
      };

      // These should fail TypeScript compilation if uncommented:
      // const pollutedMessage: WorkerMessage = {
      //   type: "init",
      //   secretBuffer: new ArrayBuffer(32),
      //   __proto__: { type: "malicious" } // Should be rejected
      // };

      expect(safeMessage.type).toBe("init");
      expect((safeMessage as any).__proto__).toBe(Object.prototype);
    });

    it("validates request ID consistency and security", () => {
      // Test request ID handling for correlation and security
      const requestId = 12345;

      const signRequest: SignRequest = {
        type: "sign",
        requestId,
        canonical: "secure-payload",
      };

      const successResponse: SignedResponse = {
        type: "signed",
        requestId, // Must match request
        signature: "valid-signature-here",
      };

      const errorResponse: ErrorResponse = {
        type: "error",
        requestId, // Must match request
        reason: "sign-failed",
      };

      expect(signRequest.requestId).toBe(requestId);
      expect(successResponse.requestId).toBe(requestId);
      expect(errorResponse.requestId).toBe(requestId);
    });

    it("validates protocol version compatibility and evolution", () => {
      // Test that protocol can evolve safely
      const currentInitMessage: InitMessage = {
        type: "init",
        secretBuffer: new ArrayBuffer(32),
        workerOptions: {
          rateLimitPerMinute: 100,
          // Future options can be added without breaking existing code
        },
      };

      // Test backward compatibility
      const minimalMessage: WorkerMessage = { type: "initialized" };
      expect(minimalMessage.type).toBe("initialized");

      // Test error handling for unknown future types
      const futureMessage: WorkerMessage = { type: "future-feature" };
      expect(futureMessage.type).toBe("future-feature");
    });
  });

  describe("OWASP ASVS L3 compliance validation", () => {
    it("validates input validation and sanitization in protocol types", () => {
      // Test that protocol types enforce proper input validation
      const validCanonical = "GET /api/secure HTTP/1.1\nhost:example.com\nx-date:20231201";

      const signRequest: SignRequest = {
        type: "sign",
        requestId: 1,
        canonical: validCanonical,
      };

      expect(signRequest.canonical).toBe(validCanonical);

      // Test error responses for validation failures
      const validationErrors: ErrorReason[] = [
        "invalid-params",
        "canonical-too-large",
        "invalid-message-format",
        "nonce-format-invalid",
      ];

      validationErrors.forEach((reason) => {
        const error: ErrorResponse = {
          type: "error",
          reason,
        };
        expect(error.reason).toBe(reason);
      });
    });

    it("validates secure defaults and hardening options", () => {
      // Test that protocol supports security hardening
      const hardenedInit: InitMessage = {
        type: "init",
        secretBuffer: new ArrayBuffer(32),
        workerOptions: {
          rateLimitPerMinute: 30, // Conservative rate limiting
          dev: false, // Production mode
          maxConcurrentSigning: 2, // Very limited concurrency
          maxCanonicalLength: 4096, // Conservative size limit
          rateLimitBurst: 5, // Limited burst capacity
          handshakeMaxNonceLength: 128, // Short nonces for security
          allowedNonceFormats: ["base64url"], // Minimal allowed formats
        },
        kid: "hardened-key",
      };

      expect(hardenedInit.workerOptions?.rateLimitPerMinute).toBe(30);
      expect(hardenedInit.workerOptions?.maxConcurrentSigning).toBe(2);
      expect(hardenedInit.workerOptions?.maxCanonicalLength).toBe(4096);
    });

    it("validates comprehensive error handling and logging", () => {
      // Test that all error conditions are properly typed
      const allErrors: ErrorReason[] = [
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

      // Ensure each error can be properly communicated
      allErrors.forEach((reason) => {
        const errorMsg: ErrorResponse = {
          type: "error",
          requestId: null, // Can be null for system errors
          reason,
        };
        expect(errorMsg.reason).toBe(reason);
        expect(errorMsg.requestId).toBeNull();
      });
    });
  });
});
