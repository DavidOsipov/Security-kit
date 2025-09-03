import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createLogger, type LogLevel } from "../../src/logger.js";
import { environment } from "../../src/environment.js";

// Mock secureDevLog to verify it's called
vi.mock("../../src/utils.js", () => ({
  secureDevLog: vi.fn(),
}));

describe("logger", () => {
  let originalIsProduction: boolean;

  beforeEach(() => {
    originalIsProduction = environment.isProduction;
    // Ensure we're in development mode for logging to work
    environment.setExplicitEnv("development");
  });

  afterEach(() => {
    environment.setExplicitEnv(originalIsProduction ? "production" : "development");
  });

  describe("createLogger", () => {
    it("creates a logger with the correct component name", () => {
      const logger = createLogger("test-component");
      expect(typeof logger).toBe("object");
      expect(typeof logger.debug).toBe("function");
      expect(typeof logger.info).toBe("function");
      expect(typeof logger.warn).toBe("function");
      expect(typeof logger.error).toBe("function");
      expect(typeof logger.child).toBe("function");
    });

    it("returns logger methods that call secureDevLog with correct parameters", async () => {
      const { secureDevLog } = await import("../../src/utils.js");
      const logger = createLogger("test-component");

      logger.debug("debug message", { key: "value" });
      expect(secureDevLog).toHaveBeenCalledWith("debug", "test-component", "debug message", { key: "value" });

      logger.info("info message");
      expect(secureDevLog).toHaveBeenCalledWith("info", "test-component", "info message", undefined);

      logger.warn("warn message", "simple context");
      expect(secureDevLog).toHaveBeenCalledWith("warn", "test-component", "warn message", "simple context");

      logger.error("error message");
      expect(secureDevLog).toHaveBeenCalledWith("error", "test-component", "error message", undefined);
    });

    it("child method creates a logger with prefixed component name", async () => {
      const { secureDevLog } = await import("../../src/utils.js");
      const parentLogger = createLogger("parent");
      const childLogger = parentLogger.child("child");

      childLogger.info("child message");
      expect(secureDevLog).toHaveBeenCalledWith("info", "parent:child", "child message", undefined);
    });

    it("nested child loggers work correctly", async () => {
      const { secureDevLog } = await import("../../src/utils.js");
      const logger = createLogger("root").child("branch").child("leaf");

      logger.warn("nested message");
      expect(secureDevLog).toHaveBeenCalledWith("warn", "root:branch:leaf", "nested message", undefined);
    });

    it("handles all log levels correctly", async () => {
      const { secureDevLog } = await import("../../src/utils.js");
      const logger = createLogger("test");

      const levels: LogLevel[] = ["debug", "info", "warn", "error"];
      levels.forEach(level => {
        logger[level](`${level} test`);
        expect(secureDevLog).toHaveBeenCalledWith(level, "test", `${level} test`, undefined);
      });
    });

    it("passes through context correctly", async () => {
      const { secureDevLog } = await import("../../src/utils.js");
      const logger = createLogger("test");

      const testContext = { userId: 123, action: "login" };
      logger.info("user action", testContext);
      expect(secureDevLog).toHaveBeenCalledWith("info", "test", "user action", testContext);
    });

    it("handles empty component names", async () => {
      const { secureDevLog } = await import("../../src/utils.js");
      const logger = createLogger("");

      logger.info("message");
      expect(secureDevLog).toHaveBeenCalledWith("info", "", "message", undefined);
    });
  });
});