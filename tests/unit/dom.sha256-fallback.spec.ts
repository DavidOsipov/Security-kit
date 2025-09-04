import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Robust tests for sha256Hex fallback strategies without relying on real modules.
// We simulate environments by overriding the test hook in src/dom.ts

// Helper functions to reduce nesting depth
function createNodeCryptoMock() {
  return {
    createHash(algo: string) {
      expect(algo).toBe("sha256");
      return {
        update(_input: string) {
          return this;
        },
        digest(fmt: string) {
          expect(fmt).toBe("hex");
          return "deadbeef".repeat(8).slice(0, 64);
        },
      };
    },
  };
}

function createFastSha256Mock() {
  return {
    hashHex(input: string) {
      return Array.from(input)
        .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("")
        .slice(0, 64);
    },
  };
}

function createHashWasmMock() {
  return {
    async sha256(input: string) {
      return Array.from(input)
        .reverse()
        .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("")
        .slice(0, 64);
    },
  };
}

describe("dom.sha256Hex fallbacks (simulated modules)", () => {
  let originalCrypto: typeof globalThis.crypto | undefined;

  beforeEach(() => {
    originalCrypto = globalThis.crypto as any;
  });

  afterEach(() => {
    // restore crypto
    if (typeof originalCrypto === "undefined")
      delete (globalThis as any).crypto;
    else (globalThis as any).crypto = originalCrypto as any;
    vi.resetModules();
  });

  it("uses node:crypto when available and webcrypto absent", async () => {
    // remove webcrypto to force node path
    delete (globalThis as any).crypto;
    const mod = await import("../../src/dom");
    const sha = (mod as any).__test_sha256Hex as (
      s: string,
      t?: number,
    ) => Promise<string>;

    (sha as any).__test_importOverride = async (s: string) => {
      if (s !== "node:crypto") throw new Error("unexpected module");
      return createNodeCryptoMock();
    };

    const out = await sha("hello");
    expect(out).toMatch(/^[0-9a-f]{32,64}$/i);
  });

  it("falls back to fast-sha256 shim when node:crypto unavailable", async () => {
    delete (globalThis as any).crypto;
    const mod = await import("../../src/dom");
    const sha = (mod as any).__test_sha256Hex as (
      s: string,
      t?: number,
    ) => Promise<string>;

    (sha as any).__test_importOverride = async (s: string) => {
      if (s === "node:crypto") throw new Error("no node crypto");
      if (s === "fast-sha256") {
        return createFastSha256Mock();
      }
      throw new Error("unexpected module");
    };

    const out = await sha("hi");
    expect(out).toMatch(/^[0-9a-f]+$/i);
  });

  it("falls back to hash-wasm shim when others unavailable", async () => {
    delete (globalThis as any).crypto;
    const mod = await import("../../src/dom");
    const sha = (mod as any).__test_sha256Hex as (
      s: string,
      t?: number,
    ) => Promise<string>;

    (sha as any).__test_importOverride = async (s: string) => {
      if (s === "node:crypto" || s === "fast-sha256")
        throw new Error("unavailable");
      if (s === "hash-wasm") {
        return createHashWasmMock();
      }
      throw new Error("unexpected module");
    };

    const out = await sha("abc");
    expect(out).toMatch(/^[0-9a-f]+$/i);
  });

  it("throws CryptoUnavailableError when no strategy works", async () => {
    delete (globalThis as any).crypto;
    const mod = await import("../../src/dom");
    const sha = (mod as any).__test_sha256Hex as (
      s: string,
      t?: number,
    ) => Promise<string>;

    (sha as any).__test_importOverride = async () => {
      // simulate all module imports fail
      throw new Error("import blocked");
    };

    await expect(sha("x", 10)).rejects.toThrow(
      /No crypto available|sha256_timeout/,
    );
  });
});
