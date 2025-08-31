import { describe, it, expect, beforeEach } from "vitest";
import { createLogger } from "../../src/logger";
import { environment } from "../../src/environment";

describe("createLogger wrapper", () => {
  beforeEach(() => {
    environment.setExplicitEnv("development");
    environment.clearCache();
  });

  it("forwards calls to secureDevLog without throwing", () => {
    const logger = createLogger("test:component");
    expect(() => logger.info("hello", { ok: true })).not.toThrow();
  });
});
