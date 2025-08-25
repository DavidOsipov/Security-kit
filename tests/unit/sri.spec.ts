import { describe, it, expect, vi } from "vitest";
import * as SK from "../../src";

const { generateSRI, setCrypto } = SK as any;

describe("SRI generation", () => {
  it("generateSRI creates valid sha256 base64 output", async () => {
    const stub = {
      getRandomValues: (a: any) => (a.fill(1), a),
      subtle: { digest: vi.fn(async () => new Uint8Array(32).fill(7).buffer) },
    } as unknown as Crypto;
    setCrypto(stub);
    const content = 'console.log("Hello, world!");';
    const sri = await generateSRI(content, "sha256");
    expect(sri).toMatch(/^sha256-[A-Za-z0-9+/]+=*$/);
    setCrypto(null);
  });

  it("generateSRI handles ArrayBuffer input", async () => {
    const stub = {
      getRandomValues: (a: any) => (a.fill(1), a),
      subtle: { digest: vi.fn(async () => new Uint8Array(32).fill(11).buffer) },
    } as unknown as Crypto;
    setCrypto(stub);
    const content = new TextEncoder().encode("test content");
    const sri = await generateSRI(content.buffer, "sha256");
    expect(sri).toMatch(/^sha256-[A-Za-z0-9+/]+=*$/);
    setCrypto(null);
  });

  it("throws on unsupported algorithm", async () => {
    const stub = {
      getRandomValues: (a: any) => (a.fill(1), a),
      subtle: { digest: vi.fn(async () => new Uint8Array(32).buffer) },
    } as unknown as Crypto;
    setCrypto(stub);
    await expect(generateSRI("test", "md5" as any)).rejects.toThrow(/Unsupported SRI algorithm/);
    setCrypto(null);
  });
});
