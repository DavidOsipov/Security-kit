import { describe, it, expect } from "vitest";

// Test that the main index exports work correctly
describe("index", () => {
  it("can import core crypto functions", async () => {
    const { hasSyncCrypto, getCryptoCapabilities } = await import(
      "../../src/index.js"
    );
    expect(typeof hasSyncCrypto).toBe("function");
    expect(typeof getCryptoCapabilities).toBe("function");
  });

  it("can import error classes", async () => {
    const { InvalidParameterError, CryptoUnavailableError } = await import(
      "../../src/index.js"
    );
    expect(typeof InvalidParameterError).toBe("function");
    expect(typeof CryptoUnavailableError).toBe("function");
  });

  it("can import utility functions", async () => {
    const { secureCompare, secureWipe } = await import("../../src/index.js");
    expect(typeof secureCompare).toBe("function");
    expect(typeof secureWipe).toBe("function");
  });

  it("can import URL utilities", async () => {
    const { createSecureURL, validateURL } = await import("../../src/index.js");
    expect(typeof createSecureURL).toBe("function");
    expect(typeof validateURL).toBe("function");
  });

  it("can import postMessage utilities", async () => {
    const { sendSecurePostMessage, createSecurePostMessageListener } =
      await import("../../src/index.js");
    expect(typeof sendSecurePostMessage).toBe("function");
    expect(typeof createSecurePostMessageListener).toBe("function");
  });

  it("can import sanitizer utilities", async () => {
    const { Sanitizer } = await import("../../src/index.js");
    expect(typeof Sanitizer).toBe("function");
  });

  it("can import cache utilities", async () => {
    const { SecureLRUCache } = await import("../../src/index.js");
    expect(typeof SecureLRUCache).toBe("function");
  });

  it("can import environment utilities", async () => {
    const { environment, isDevelopment } = await import("../../src/index.js");
    expect(typeof environment).toBe("object");
    expect(typeof isDevelopment).toBe("function");
  });

  it("can import configuration functions", async () => {
    const { setCrypto, sealSecurityKit } = await import("../../src/index.js");
    expect(typeof setCrypto).toBe("function");
    expect(typeof sealSecurityKit).toBe("function");
  });
});
