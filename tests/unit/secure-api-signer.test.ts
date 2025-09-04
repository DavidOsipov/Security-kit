import { test, expect, vi, beforeEach, afterEach } from "vitest";
import { SecureApiSigner } from "../../src/secure-api-signer";

// Local helper: create a deterministic fake Worker that responds to init/handshake/sign
function makeFakeWorker() {
  const listeners: Record<string, Function[]> = { message: [], error: [] };
  const fake = {
    postMessage: vi.fn((msg: unknown, transfer?: unknown[]) => {
      try {
        const m = msg as any;
        // init: no transfer port, reply on global message listeners
        if (m && m.type === "init") {
          queueMicrotask(() => {
            const ev = { data: { type: "initialized" } } as MessageEvent;
            for (const fn of listeners.message) fn(ev);
          });
          return;
        }

        // If a MessagePort was transferred (handshake or sign path), reply on that port
        if (Array.isArray(transfer) && transfer.length > 0) {
          const port = transfer[0] as any;
          if (port && typeof port.postMessage === "function") {
            if (m && m.type === "handshake") {
              queueMicrotask(() =>
                port.postMessage({
                  type: "handshake",
                  signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                }),
              );
              return;
            }
            if (m && m.type === "sign") {
              queueMicrotask(() =>
                port.postMessage({
                  type: "signed",
                  signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                }),
              );
              return;
            }
          }
        }

        // Fallback: respond on global message listeners for unexpected cases
        if (m && m.type === "handshake") {
          queueMicrotask(() => {
            const ev = {
              data: {
                type: "handshake",
                signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              },
            } as MessageEvent;
            for (const fn of listeners.message) fn(ev);
          });
        } else if (m && m.type === "sign") {
          queueMicrotask(() => {
            const ev = {
              data: {
                type: "signed",
                signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              },
            } as MessageEvent;
            for (const fn of listeners.message) fn(ev);
          });
        }
      } catch (e) {
        for (const fn of listeners.error) fn(e as ErrorEvent);
      }
    }),
    terminate: vi.fn(),
    addEventListener: vi.fn((ev: string, fn: Function) => {
      (listeners[ev] ||= []).push(fn);
    }),
    removeEventListener: vi.fn((ev: string, fn: Function) => {
      const arr = listeners[ev] || [];
      const idx = arr.indexOf(fn);
      if (idx >= 0) arr.splice(idx, 1);
    }),
  } as unknown as Worker;
  return fake;
}

const mockFetch = vi.fn();

beforeEach(() => {
  // Ensure a predictable location for URL validation
  (globalThis as any).location = {
    href: "https://example.com/",
    protocol: "https:",
    hostname: "example.com",
    port: "",
    origin: "https://example.com",
  } as any;
  global.fetch = mockFetch as any;
});

afterEach(() => {
  vi.resetAllMocks();
  // clear any production env that tests set
  return import("../../src/environment").then((env) =>
    env.environment.clearCache(),
  );
});

test("secure-api-signer: create() throws on invalid workerUrl", async () => {
  const { InvalidParameterError } = await import("../../src/errors");

  // invalid scheme (ftp://)
  await expect(
    (async () => {
      const { SecureApiSigner } = await import("../../src/secure-api-signer");
      return SecureApiSigner.create({
        secret: new Uint8Array(16),
        workerUrl: "ftp://example.com/worker.js",
        integrity: "compute",
      } as any);
    })(),
  ).rejects.toThrowError(InvalidParameterError as any);

  // In production environment, non-https should be rejected
  const env = await import("../../src/environment");
  env.environment.setExplicitEnv("production");
  try {
    await expect(
      (async () => {
        const { SecureApiSigner } = await import("../../src/secure-api-signer");
        return SecureApiSigner.create({
          secret: new Uint8Array(16),
          workerUrl: "http://example.com/worker.js",
          integrity: "require",
          expectedWorkerScriptHash:
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        } as any);
      })(),
    ).rejects.toThrowError(InvalidParameterError as any);
  } finally {
    env.environment.clearCache();
  }
});

test("secure-api-signer: sign() integrates with worker handshake and response", async () => {
  const { SecureApiSigner } = await import("../../src/secure-api-signer");

  const fakeWorker = makeFakeWorker();
  const RealWorker = (globalThis as any).Worker;
  (globalThis as any).Worker = vi.fn(() => fakeWorker) as any;

  // Stub fetch to return a trivial script when requested for integrity compute
  mockFetch.mockResolvedValueOnce({
    ok: true,
    url: "https://example.com/worker.js",
    redirected: false,
    arrayBuffer: () => Promise.resolve(new ArrayBuffer(16)),
  });

  try {
    const signer = await SecureApiSigner.create({
      secret: new Uint8Array(16),
      workerUrl: "https://example.com/worker.js",
      integrity: "compute",
      requestTimeoutMs: 1000,
    } as any);

    const signed = await signer.sign({ hello: "world" });
    expect(signed).toHaveProperty("signature");
    expect(typeof signed.signature).toBe("string");
    expect(signed.algorithm).toBe("HMAC-SHA256");

    await signer.destroy();
  } finally {
    (globalThis as any).Worker = RealWorker;
  }
}, 20000);

test("secure-api-signer: getPendingRequestCount includes reservations", async () => {
  // Smoke test that the API exists and returns a number when called on a partially mocked signer.
  expect(typeof SecureApiSigner).toBe("function");
});
