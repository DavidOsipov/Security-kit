import { describe, it, expect, beforeEach, vi } from "vitest";

// Use per-test dynamic imports to avoid sharing logging/config state between
// test files. Callers should reset modules before importing stateful modules.

describe("utils logger sanitization", () => {
  beforeEach(() => {
    // ensure development environment for tests
    vi.resetModules();
    return (async () => {
      const { environment } = await import("../../src/environment");
      environment.setExplicitEnv("development");
    })();
  });

  describe("sanitizeLogMessage", () => {
    it("redacts JWT-like strings", () => {
      return (async () => {
        const { sanitizeLogMessage } = await import("../../src/utils");
        const message =
          "User token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        const result = sanitizeLogMessage(message);
        expect(result).toBe("User token=[REDACTED]");
      })();
    });

    it("redacts password patterns", () => {
      return (async () => {
        const { sanitizeLogMessage } = await import("../../src/utils");
        const message = "Login failed for user=test password=hunter2";
        const result = sanitizeLogMessage(message);
        expect(result).toBe("Login failed for user=test password=[REDACTED]");
      })();
    });

    it("redacts token patterns", () => {
      return (async () => {
        const { sanitizeLogMessage } = await import("../../src/utils");
        const message = "Auth failed: token=abc123def456";
        const result = sanitizeLogMessage(message);
        expect(result).toBe("Auth failed: token=[REDACTED]");
      })();
    });

    it("redacts authorization patterns", () => {
      return (async () => {
        const { sanitizeLogMessage } = await import("../../src/utils");
        const message = "Request with authorization=Bearer xyz789";
        const result = sanitizeLogMessage(message);
        // Canonicalize to 'Authorization' for consistency across logs
        expect(result).toBe("Request with Authorization=[REDACTED]");
      })();
    });

    it("redacts secret patterns", () => {
      return (async () => {
        const { sanitizeLogMessage } = await import("../../src/utils");
        const message = "Config: secret=mySecretValue";
        const result = sanitizeLogMessage(message);
        expect(result).toBe("Config: secret=[REDACTED]");
      })();
    });

    it("handles non-string inputs", () => {
      return (async () => {
        const { sanitizeLogMessage } = await import("../../src/utils");
        expect(sanitizeLogMessage(123)).toBe("123");
        expect(sanitizeLogMessage(null)).toBe("null");
        expect(sanitizeLogMessage(undefined)).toBe("undefined");
        expect(sanitizeLogMessage({})).toBe("[object Object]");
      })();
    });

    it("truncates very long messages", () => {
      return (async () => {
        const { sanitizeLogMessage, MAX_LOG_STRING } = await import(
          "../../src/utils"
        );
        const longMessage = "a".repeat(MAX_LOG_STRING + 100);
        const result = sanitizeLogMessage(longMessage);
        expect(result.length).toBeLessThanOrEqual(MAX_LOG_STRING + 50); // Allow some buffer for truncation message
        expect(result).toContain("[TRUNCATED");
      })();
    });

    it("preserves safe messages unchanged", () => {
      return (async () => {
        const { sanitizeLogMessage } = await import("../../src/utils");
        const safeMessage = "User login successful";
        const result = sanitizeLogMessage(safeMessage);
        expect(result).toBe(safeMessage);
      })();
    });

    it("handles sanitizer errors gracefully", () => {
      return (async () => {
        const { sanitizeLogMessage } = await import("../../src/utils");
        // Create a problematic input that might cause errors
        const problematic = {
          toString: () => {
            throw new Error("test error");
          },
        };
        const result = sanitizeLogMessage(problematic as any);
        expect(result).toBe("[REDACTED]");
      })();
    });
  });

  describe("sanitizeComponentName", () => {
    it("accepts valid component names", () => {
      return (async () => {
        const { sanitizeComponentName } = await import("../../src/utils");
        expect(sanitizeComponentName("auth")).toBe("auth");
        expect(sanitizeComponentName("user-service")).toBe("user-service");
        expect(sanitizeComponentName("api.v1")).toBe("api.v1");
        expect(sanitizeComponentName("test_123")).toBe("test_123");
      })();
    });

    it("rejects invalid component names", () => {
      return (async () => {
        const { sanitizeComponentName } = await import("../../src/utils");
        expect(sanitizeComponentName("component with spaces")).toBe(
          "unsafe-component-name",
        );
        expect(sanitizeComponentName("component@domain")).toBe(
          "unsafe-component-name",
        );
        expect(sanitizeComponentName("component<script>")).toBe(
          "unsafe-component-name",
        );
        expect(sanitizeComponentName("")).toBe("unsafe-component-name");
      })();
    });

    it("rejects names that are too long", () => {
      return (async () => {
        const { sanitizeComponentName } = await import("../../src/utils");
        const longName = "a".repeat(70); // Exceeds 64 character limit
        expect(sanitizeComponentName(longName)).toBe("unsafe-component-name");
      })();
    });

    it("handles non-string inputs", () => {
      return (async () => {
        const { sanitizeComponentName } = await import("../../src/utils");
        expect(sanitizeComponentName(123)).toBe("unsafe-component-name");
        expect(sanitizeComponentName(null)).toBe("unsafe-component-name");
        expect(sanitizeComponentName(undefined)).toBe("unsafe-component-name");
        expect(sanitizeComponentName({})).toBe("unsafe-component-name");
      })();
    });

    it("handles sanitizer errors gracefully", () => {
      return (async () => {
        const { sanitizeComponentName } = await import("../../src/utils");
        // Create a problematic input that might cause errors
        const problematic = {
          toString: () => {
            throw new Error("test error");
          },
        };
        const result = sanitizeComponentName(problematic as any);
        expect(result).toBe("unsafe-component-name");
      })();
    });
  });

  describe("integration with secureDevLog", () => {
    it("sanitizes message and component in secureDevLog", () => {
      return (async () => {
        const { secureDevLog } = await import("../../src/utils");
        const consoleSpy = vi
          .spyOn(console, "info")
          .mockImplementation(() => {});

        // Test with sensitive message content
        secureDevLog("info", "auth-service", "Login failed: token=secret123", {
          user: "test",
        });

        // Check that console was called with sanitized content
        expect(consoleSpy).toHaveBeenCalled();
        const callArgs = consoleSpy.mock.calls[0];
        const loggedMessage = callArgs[0] as string;

        // Should contain sanitized component and message
        expect(loggedMessage).toContain("auth-service");
        expect(loggedMessage).toContain("[REDACTED]");
        expect(loggedMessage).not.toContain("secret123");

        consoleSpy.mockRestore();
      })();
    });

    it("sanitizes unsafe component names in secureDevLog", () => {
      return (async () => {
        const { secureDevLog } = await import("../../src/utils");
        const consoleSpy = vi
          .spyOn(console, "info")
          .mockImplementation(() => {});

        // Test with unsafe component name
        secureDevLog("info", "unsafe@component", "Test message", {});

        expect(consoleSpy).toHaveBeenCalled();
        const callArgs = consoleSpy.mock.calls[0];
        const loggedMessage = callArgs[0] as string;

        // Should contain sanitized component name
        expect(loggedMessage).toContain("unsafe-component-name");
        expect(loggedMessage).not.toContain("unsafe@component");

        consoleSpy.mockRestore();
      })();
    });

    it("sanitizes CustomEvent payload", () => {
      return (async () => {
        const { secureDevLog } = await import("../../src/utils");

        // Mock document and CustomEvent
        const mockDispatch = vi.fn();
        global.document = { dispatchEvent: mockDispatch } as any;
        global.CustomEvent = vi.fn().mockImplementation((type, options) => ({
          type,
          detail: options?.detail,
        }));

        // Test with sensitive message
        secureDevLog("info", "test", "Token: abc123", {});

        // Check CustomEvent was dispatched with sanitized data
        expect(global.CustomEvent).toHaveBeenCalled();
        const eventCall = (global.CustomEvent as any).mock.calls[0];
        const eventDetail = eventCall[1].detail;

        expect(eventDetail.message).toContain("[REDACTED]");
        expect(eventDetail.message).not.toContain("abc123");

        // Cleanup
        Reflect.deleteProperty(global as any, "document");
        Reflect.deleteProperty(global as any, "CustomEvent");
      })();
    });
  });

  describe("integration with _devConsole", () => {
    it("sanitizes message in _devConsole", () => {
      return (async () => {
        const { _devConsole } = await import("../../src/utils");
        const consoleSpy = vi
          .spyOn(console, "info")
          .mockImplementation(() => {});

        // Test with sensitive message content
        _devConsole("info", "Login failed: password=secret", { user: "test" });

        expect(consoleSpy).toHaveBeenCalled();
        const callArgs = consoleSpy.mock.calls[0];
        const loggedMessage = callArgs[0] as string;

        // Should contain sanitized message
        expect(loggedMessage).toContain("[REDACTED]");
        expect(loggedMessage).not.toContain("secret");

        consoleSpy.mockRestore();
      })();
    });
  });
});
