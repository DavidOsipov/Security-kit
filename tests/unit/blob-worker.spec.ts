import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SecureApiSigner } from "../../src/secure-api-signer";
import { VerifiedByteCache } from "../../src/secure-cache";
import { SecurityKitError } from "../../src/errors";

// Mocks for global objects we need: Blob, URL.createObjectURL, URL.revokeObjectURL, Worker

class FakeWorker {
  public terminated = false;
  private handlers: { [k: string]: Function[] } = {};
  constructor(public script: string) {
    // record script URL
  }
  addEventListener(ev: string, fn: Function) {
    this.handlers[ev] = this.handlers[ev] || [];
    this.handlers[ev].push(fn);
  }
  removeEventListener(ev: string, fn: Function) {
    if (!this.handlers[ev]) return;
    this.handlers[ev] = this.handlers[ev].filter((f) => f !== fn);
  }
  postMessage(msg: any) {
    // For handshake: when 'init' with secretBuffer sent, reply with initialized
    const transfer = arguments[1] as any[] | undefined;
    if (msg && msg.type === "init") {
      setTimeout(() => {
        const event = { data: { type: "initialized" } };
        (this.handlers["message"] || []).forEach((h) => h(event));
      }, 10);
      return;
    }
    if (msg && msg.type === "handshake") {
      // If a MessagePort was transferred, post the handshake response on that port
      if (
        transfer &&
        transfer.length > 0 &&
        typeof transfer[0]?.postMessage === "function"
      ) {
        setTimeout(() => {
          try {
            transfer[0].postMessage({ type: "handshake", signature: "AAA" });
          } catch {
            // ignore
          }
        }, 10);
        return;
      }

      // Otherwise, fall back to emitting a message event on the worker
      setTimeout(() => {
        const event = { data: { type: "handshake", signature: "AAA" } };
        (this.handlers["message"] || []).forEach((h) => h(event));
      }, 10);
    }
  }
  terminate() {
    this.terminated = true;
  }
}

let originalBlob: any;
let originalCreate: any;
let originalRevoke: any;
let originalWorker: any;

beforeEach(() => {
  originalBlob = (globalThis as any).Blob;
  originalCreate = (URL as any).createObjectURL;
  originalRevoke = (URL as any).revokeObjectURL;
  originalWorker = (globalThis as any).Worker;

  (globalThis as any).Blob = function (arr: any, opts: any) {
    return { arr, opts };
  };
  (URL as any).createObjectURL = vi.fn(
    (blob: any) => `blob://fake-${Math.random()}`,
  );
  (URL as any).revokeObjectURL = vi.fn(() => {});
  (globalThis as any).Worker = vi.fn(function (script: string, opts: any) {
    return new FakeWorker(script);
  });
});

afterEach(() => {
  (globalThis as any).Blob = originalBlob;
  (URL as any).createObjectURL = originalCreate;
  (URL as any).revokeObjectURL = originalRevoke;
  (globalThis as any).Worker = originalWorker;
  VerifiedByteCache.clear();
  vi.restoreAllMocks();
});

async function makeSigner(init: any) {
  const defaultInit = {
    secret: new Uint8Array(32),
    workerUrl: new URL("http://example.com/worker.js"),
    integrity: "compute",
    allowCrossOriginWorkerOrigins: ["http://example.com"],
  };
  return await SecureApiSigner.create({ ...defaultInit, ...init });
}

describe("Blob worker and policy gating", () => {
  it("caches verified bytes and creates blob worker when allowed", async () => {
    // Simulate fetch to return a small script
    globalThis.fetch = vi.fn(async () => {
      return {
        ok: true,
        redirected: false,
        url: "http://example.com/worker.js",
        arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer,
      } as any;
    });

    // Ensure runtime policy allows blob workers
    const { setRuntimePolicy } = await import("../../src/config");
    setRuntimePolicy({ allowBlobWorkers: true });

    const signer = await makeSigner({});
    expect(VerifiedByteCache.get("http://example.com/worker.js")).toBeDefined();
    await signer.destroy();
  });

  it("throws E_SIGNATURE_MISMATCH when expected hash mismatches", async () => {
    globalThis.fetch = vi.fn(async () => {
      return {
        ok: true,
        redirected: false,
        url: "http://example.com/worker.js",
        arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer,
      } as any;
    });
    const { setRuntimePolicy } = await import("../../src/config");
    setRuntimePolicy({ allowBlobWorkers: true });

    await expect(
      makeSigner({ expectedWorkerScriptHash: "AAAAAAAAAAAAAAAAAAAA" }),
    ).rejects.toThrow(SecurityKitError);
  });

  it("refuses compute in production by default", async () => {
    // Simulate production environment (use public API)
    const env = await import("../../src/environment");
    env.environment.setExplicitEnv("production");

    globalThis.fetch = vi.fn(async () => {
      return {
        ok: true,
        redirected: false,
        url: "http://example.com/worker.js",
        arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer,
      } as any;
    });

    await expect(makeSigner({})).rejects.toThrow(SecurityKitError);

    // restore
    env.environment.setExplicitEnv("development");
  });

  it("throws E_CSP_BLOCKED if Blob worker creation fails", async () => {
    globalThis.fetch = vi.fn(async () => {
      return {
        ok: true,
        redirected: false,
        url: "http://example.com/worker.js",
        arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer,
      } as any;
    });
    const { setRuntimePolicy } = await import("../../src/config");
    setRuntimePolicy({ allowBlobWorkers: true });

    // Make URL.createObjectURL throw
    (URL as any).createObjectURL = () => {
      throw new Error("CSP");
    };

    await expect(makeSigner({})).rejects.toThrow(SecurityKitError);
  });

  it("enforces canonical size limit", async () => {
    // Create a signer with a small worker script
    globalThis.fetch = vi.fn(async () => {
      return {
        ok: true,
        redirected: false,
        url: "http://example.com/worker.js",
        arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer,
      } as any;
    });
    const { setRuntimePolicy } = await import("../../src/config");
    setRuntimePolicy({ allowBlobWorkers: true });

    const signer = await makeSigner({});
    // Attempt to sign a huge payload
    const huge = "A".repeat(3_000_000);
    await expect(signer.sign({ data: huge })).rejects.toThrow(SecurityKitError);
    await signer.destroy();
  });
});
