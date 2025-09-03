import { test, expect, beforeEach, afterEach, vi } from "vitest";
import { SecureApiSigner } from "../../src/secure-api-signer";
import { createHmac } from "crypto";
import { InvalidParameterError } from "../../src/errors";

// Minimal MockWorker used by these tests. Emulates worker-side signing.
class MockWorker {
  listeners: Record<string, Function[]> = {};
  keyBytes: Buffer | null = null;
  opts: any;

  constructor(url: string, opts?: any) {
    this.opts = opts || {};
  }
  addEventListener(name: string, fn: Function) {
    (this.listeners[name] = this.listeners[name] || []).push(fn);
  }
  removeEventListener(name: string, fn: Function) {
    this.listeners[name] = (this.listeners[name] || []).filter((f) => f !== fn);
  }

  postMessage(msg: any, transfer?: any[]) {
    if (msg.type === "init") {
      this.keyBytes = Buffer.from(
        msg.secretBuffer instanceof ArrayBuffer
          ? new Uint8Array(msg.secretBuffer)
          : msg.secretBuffer,
      );
      setTimeout(
        () => this.emit("message", { data: { type: "initialized" } }),
        0,
      );
      return;
    }
    if (msg.type === "handshake" && transfer && transfer.length === 1) {
      const port = transfer[0] as MessagePort;
      setTimeout(() => {
        try {
          const nonce = msg.nonce as string;
          const signature = this.keyBytes
            ? createHmac("sha256", this.keyBytes).update(nonce).digest("base64")
            : "";
          port.postMessage({ type: "handshake", signature });
        } catch (e) {
          try {
            port.postMessage({ type: "error", reason: "handshake-failed" });
          } catch {}
        } finally {
          try {
            port.close();
          } catch {}
        }
      }, 0);
      return;
    }
    if (msg.type === "sign") {
      const { requestId, canonical, nonce, timestamp } = msg as any;
      const delay = this.opts.delayMs || 5;
      setTimeout(() => {
        const port =
          transfer && transfer.length === 1
            ? (transfer[0] as MessagePort)
            : null;
        if (!this.keyBytes) {
          const errorMsg = {
            type: "error",
            requestId,
            reason: "not-initialized",
          };
          if (port) {
            try {
              port.postMessage(errorMsg);
            } catch {}
          } else {
            this.emit("message", { data: errorMsg });
          }
          return;
        }
        const joined = `${timestamp}.${nonce}.${canonical}`;
        const sig = createHmac("sha256", this.keyBytes)
          .update(joined)
          .digest("base64");
        const successMsg = {
          type: "signed",
          requestId,
          signature: sig,
          nonce,
          timestamp,
        };
        if (port) {
          try {
            port.postMessage(successMsg);
          } catch {}
        } else {
          this.emit("message", { data: successMsg });
        }
      }, delay);
      return;
    }
    if (msg.type === "destroy") {
      setTimeout(
        () => this.emit("message", { data: { type: "destroyed" } }),
        0,
      );
      return;
    }
  }
  terminate() {}
  emit(name: string, ev: any) {
    (this.listeners[name] || []).forEach((fn) => {
      try {
        fn(ev);
      } catch {}
    });
  }
}

let origWorker: any;
beforeEach(() => {
  origWorker = (globalThis as any).Worker;
  (globalThis as any).Worker = MockWorker;
  vi.useFakeTimers();
});
afterEach(() => {
  (globalThis as any).Worker = origWorker;
  vi.useRealTimers();
});

test("SecureApiSigner.create, sign and destroy (roundtrip)", async () => {
  const secret = new Uint8Array(
    Buffer.from("0123456789abcdef0123456789abcdef"),
  );
  // start create and allow the worker's init message to fire via timers
  const createP = SecureApiSigner.create({
    secret,
    workerUrl: new URL("./mock-worker.js", import.meta.url),
    integrity: "none",
  });
  await vi.runAllTimersAsync();
  const signer = await createP;

  // sign and allow worker reply
  const signP = signer.sign("hello-world");
  await vi.runAllTimersAsync();
  const signed = await signP;

  expect(typeof signed.signature).toBe("string");
  expect(signed.nonce).toBeTruthy();
  expect(typeof signed.timestamp).toBe("number");

  const destroyP = signer.destroy();
  await vi.runAllTimersAsync();
  await destroyP;
});

test("SecureApiSigner.create rejects invalid secret types", async () => {
  // This test expects create() to reject synchronously for invalid secret
  // Use real timers here to allow any immediate worker handshakes/timeouts to run
  vi.useRealTimers();
  try {
    await expect(
      SecureApiSigner.create({
        secret: "" as any,
        workerUrl: new URL("./mock-worker.js", import.meta.url),
        integrity: "none",
      }),
    ).rejects.toThrow("secret must be ArrayBuffer or an ArrayBuffer view");
  } finally {
    vi.useFakeTimers();
  }
});
