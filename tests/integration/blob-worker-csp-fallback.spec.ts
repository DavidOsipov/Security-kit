import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SecureApiSigner } from "../../src/secure-api-signer";
import { VerifiedByteCache } from "../../src/secure-cache";
import { secureDevLog } from "../../src/utils";

describe("Blob worker CSP strict behavior (no fallback)", () => {
  let originalCreate: any;
  let originalWorker: any;

  beforeEach(() => {
    originalCreate = (URL as any).createObjectURL;
    originalWorker = (globalThis as any).Worker;

    // Simulate CSP blocking createObjectURL by throwing
    (URL as any).createObjectURL = vi.fn(() => {
      throw new Error("CSP blocked createObjectURL");
    });

    // Capture when Worker is constructed from a string URL (fallback path)
    (globalThis as any).Worker = vi.fn(function (
      this: any,
      script: string,
      _opts: any,
    ) {
      // simple fake worker that responds to init and handshake
      this.handlers = {} as Record<string, Function[]>;
      this.addEventListener = (ev: string, fn: Function) => {
        this.handlers[ev] = this.handlers[ev] || [];
        this.handlers[ev].push(fn);
      };
      this.removeEventListener = (ev: string, fn: Function) => {
        if (!this.handlers[ev]) return;
        this.handlers[ev] = this.handlers[ev].filter((f: Function) => f !== fn);
      };
      this.postMessage = (msg: any, transfer?: any[]) => {
        const port = transfer && transfer.length > 0 ? transfer[0] : undefined;
        if (msg && msg.type === "init") {
          setTimeout(() => {
            const event = { data: { type: "initialized" } } as any;
            // if a port was transferred, respond over the port
            if (port && typeof port.postMessage === "function") {
              try {
                port.postMessage({ type: "initialized" });
                return;
              } catch {
                /* ignore */
              }
            }
            (this.handlers["message"] || []).forEach((h: Function) => h(event));
          }, 1);
        }
        if (msg && msg.type === "handshake") {
          setTimeout(() => {
            const event = {
              data: { type: "handshake", signature: "AAA" },
            } as any;
            if (port && typeof port.postMessage === "function") {
              try {
                port.postMessage({ type: "handshake", signature: "AAA" });
                return;
              } catch {
                /* ignore */
              }
            }
            (this.handlers["message"] || []).forEach((h: Function) => h(event));
          }, 1);
        }
      };
      this.terminate = () => {};
      // expose script for assertions
      this.script = script;
    });

    VerifiedByteCache.clear();
  });

  afterEach(() => {
    (URL as any).createObjectURL = originalCreate;
    (globalThis as any).Worker = originalWorker;
    vi.restoreAllMocks();
  });

  it("throws E_CSP_BLOCKED and does not fallback when createObjectURL is blocked", async () => {
    // Ensure policy allows Blob workers & caching so code attempts createObjectURL first
    const { setRuntimePolicy } = await import("../../src/config");
    setRuntimePolicy({ allowBlobWorkers: true, enableWorkerByteCache: true });

    // Mock fetch to provide bytes to be cached
    globalThis.fetch = vi.fn(
      async () =>
        ({
          ok: true,
          redirected: false,
          url: "https://example.com/csp-worker.js",
          arrayBuffer: async () => new Uint8Array([1, 2, 3, 4]).buffer,
        }) as any,
    );

    // Use secureDevLog to emphasize it's available; it's dev-only and does nothing in prod
    secureDevLog("debug", "test", "Starting CSP fallback test");

    await expect(
      SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: new URL("https://example.com/csp-worker.js"),
        integrity: "compute",
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      } as any),
    ).rejects.toMatchObject({
      name: "SecurityKitError",
      code: "E_CSP_BLOCKED",
    });
  });
});
