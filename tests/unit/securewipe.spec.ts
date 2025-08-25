import { describe, it, expect, vi } from "vitest";
import * as SK from "../../src";

const { secureWipe, setAppEnvironment } = SK as any;

describe("secureWipe behaviors", () => {
  it("wipes DataView via Uint8Array view fallback", () => {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    for (let i = 0; i < 8; i++) view.setUint8(i, 0xff);
    secureWipe(view as any);
    const check = new Uint8Array(buf);
    expect(check.every((b) => b === 0)).toBe(true);
  });

  it("warns on wiping large buffers in development mode", () => {
    try {
      setAppEnvironment("development");
    } catch {}
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const big = new Uint8Array(2048);
    big.fill(1);
    secureWipe(big);
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});
