import { test, expect, vi } from "vitest";
import fc from "fast-check";
import { MessageChannel } from "worker_threads";

// Runtime property-based tests that import the worker harness and exercise its
// message listener with structured message shapes. The goal is to catch
// unexpected leaks, crashes, or non-serializable responses when facing
// structured/adversarial inputs.

const isCI = Boolean(process.env.CI || process.env.GITHUB_ACTIONS);
function defaultRuns() {
  if (process.env.FASTCHECK_RUNS) return Number(process.env.FASTCHECK_RUNS);
  if (process.env.FASTCHECK_MODE === "nightly") return 2000;
  if (isCI) return 200; // keep CI quick
  return 500; // local
}
const NUM_RUNS = defaultRuns();
const SEED = process.env.FASTCHECK_SEED
  ? Number(process.env.FASTCHECK_SEED)
  : undefined;

// Minimal mock MessagePort used by handshake reply ports
class MockMessagePort {
  postMessage = vi.fn((msg: any) => {
    (this.postMessage as any).last = msg;
    return msg;
  });
}

// Helper to create a MockMessageEvent compatible shape
class MockMessageEvent {
  data: any;
  origin = "https://example.com";
  ports: any[] = [];
  constructor(data: any) {
    this.data = data;
  }
}

// Module-scoped captured listener so the mocked postMessage module can set it.
let capturedListener: ((data: any, meta?: any) => Promise<void>) | undefined;

test("runtime fast-check: structured messages do not crash worker and responses are safe", async () => {
  // Prepare mocks and capture listener similar to unit tests
  const mockPostMessage = vi.fn();
  const mockClose = vi.fn();
  const mockSign = vi.fn(async () => new ArrayBuffer(8));
  const mockImportKey = vi.fn(async () => ({}) as CryptoKey);

  // Stub global environment
  vi.stubGlobal("self", {
    postMessage: mockPostMessage,
    close: mockClose,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  });
  vi.stubGlobal("postMessage", mockPostMessage);
  vi.stubGlobal("location", { origin: "https://example.com" });
  vi.stubGlobal("crypto", {
    ...global.crypto,
    subtle: { sign: mockSign, importKey: mockImportKey },
    getRandomValues: vi.fn(),
  });

  // Reset module cache to ensure the worker re-evaluates and picks up our mocks
  try {
    vi.resetModules();
  } catch {}

  // Capture the createSecurePostMessageListener used by the worker so we can
  // directly drive the onMessage handler. We'll also ensure origin checks pass
  // by returning https://example.com as initial origin.
  vi.mock("../../src/postMessage", () => ({
    createSecurePostMessageListener: vi.fn((opts: any) => {
      // emulate the shape: onMessage(data, meta)
      capturedListener = opts.onMessage;
      return { destroy: vi.fn() };
    }),
    computeInitialAllowedOrigin: vi.fn(() => "https://example.com"),
    isEventAllowedWithLock: vi.fn(() => true),
  }));

  // Import the worker after mocking so it uses the mocked postMessage module
  await import("../../src/worker/signing-worker");

  if (!capturedListener) throw new Error("Worker listener not captured");

  // Arbitrary structured message generator: includes nested objects, transferables
  // (ArrayBuffer), MessagePort-like objects, and unknown malformed shapes.
  const tinyBuffer = fc
    .uint8Array({ minLength: 0, maxLength: 64 })
    .map((a) => a.buffer);

  const nestedString = fc.oneof(
    fc.string(),
    fc.constantFrom(null, undefined),
    fc.integer().map(String),
  );

  const messagePortLike = fc.oneof(
    fc.constant(undefined),
    fc.record({ postMessage: fc.func(fc.anything()) }),
  );

  const initArb = fc.record(
    {
      type: fc.constant("init"),
      secretBuffer: tinyBuffer,
      workerOptions: fc.option(
        fc.record({ rateLimitPerMinute: fc.integer({ min: 0, max: 1000 }) }),
      ),
    },
    { requiredKeys: ["type", "secretBuffer"] },
  );

  const handshakeArb = fc.record({
    type: fc.constant("handshake"),
    nonce: fc.string(),
    expectReplyPort: fc.boolean(),
    useRealPort: fc.boolean(),
    meta: fc.option(
      fc.dictionary(
        fc.string(),
        fc.oneof(fc.string(), fc.integer(), fc.boolean()),
      ),
    ),
  });

  const signArb = fc.record({
    type: fc.constant("sign"),
    requestId: fc.oneof(fc.integer({ min: 0, max: 1_000_000 }), fc.string()),
    canonical: fc.string({ maxLength: 2000 }),
    nested: fc.option(
      fc.record({
        a: nestedString,
        b: fc.array(fc.string(), { maxLength: 5 }),
      }),
    ),
  });

  const destroyArb = fc.record({ type: fc.constant("destroy") });

  const unknownArb = fc.record({
    type: fc.oneof(fc.string(), fc.constant(null)),
    payload: fc.anything(),
  });

  const msgArb = fc.oneof(
    initArb,
    handshakeArb,
    signArb,
    destroyArb,
    unknownArb,
  );

  await fc.assert(
    fc.asyncProperty(msgArb, async (msg) => {
      // Build a mock event and optional reply port
      const event = new MockMessageEvent(msg);
      const replyPort = new MockMessagePort();
      // If requested, create a real MessageChannel port and use it as a reply port
      let realPort: any = undefined;
      let mc: MessageChannel | undefined = undefined;
      if ((msg as any).type === "handshake" && (msg as any).expectReplyPort) {
        if ((msg as any).useRealPort) {
          try {
            mc = new MessageChannel();
            realPort = mc.port1;
            // Hook a listener so we capture postMessage from the worker
            (realPort as any).postMessage = (realPort as any).postMessage.bind(
              realPort,
            );
            event.ports = [realPort as any];
          } catch (e) {
            // Fallback to mock reply port
            event.ports = [replyPort as any];
          }
        } else {
          event.ports = [replyPort as any];
        }
      }

      // Call the worker listener via the captured onMessage API
      try {
        await capturedListener!(event.data, {
          origin: event.origin,
          ports: event.ports,
          event,
        });
      } catch (err) {
        // Throw with seed info so the CI logs surface the failing seed for adversarial shrinking
        const info: any = { err: String(err), seed: SEED || "random" };
        throw new Error(
          `Worker threw on input: ${JSON.stringify({ msg, info })}`,
        );
      }

      // Validate that any outgoing responses are JSON-serializable and small
      // Check both worker.postMessage calls and handshake reply ports
      const calls = (mockPostMessage as any).mock.calls || [];
      for (const c of calls) {
        const response = c[0];
        // secretBuffer must never be echoed back
        if (response && typeof response === "object") {
          if ("secretBuffer" in response) return false;
        }
        try {
          const js = JSON.stringify(response);
          if (js && js.length > 64 * 1024) return false; // too large
        } catch (e) {
          return false; // non-serializable
        }
      }

      // Check reply port if used
      if ((msg as any).type === "handshake" && (msg as any).expectReplyPort) {
        // Check mock reply port
        const last = (replyPort.postMessage as any).last;
        if (last) {
          try {
            JSON.stringify(last);
          } catch {
            // Close any real ports before failing
            if (mc) {
              try {
                mc.port1.close();
                mc.port2.close();
              } catch {}
            }
            return false;
          }
          if (typeof last !== "object" || !("type" in last)) {
            if (mc) {
              try {
                mc.port1.close();
                mc.port2.close();
              } catch {}
            }
            return false;
          }
        }
        // If a real port was used, try to read any messages posted to it by
        // attaching a temporary 'message' handler on the other end (port2).
        if (mc) {
          try {
            // Drain any messages by listening briefly on port2
            const drained: any[] = [];
            const p = new Promise<void>((resolve) => {
              mc!.port2.on("message", (m: any) => drained.push(m));
              // Allow microtask tick for messages
              setTimeout(() => resolve(), 0);
            });
            await p;
            for (const m of drained) {
              try {
                JSON.stringify(m);
              } catch {
                if (mc) {
                  try {
                    mc.port1.close();
                    mc.port2.close();
                  } catch {}
                }
                return false;
              }
            }
          } catch (e) {
            if (mc) {
              try {
                mc.port1.close();
                mc.port2.close();
              } catch {}
            }
            return false;
          }
        }
      }

      // Reset mocks for next run and close any real ports
      vi.clearAllMocks();
      if (mc) {
        try {
          mc.port1.close();
          mc.port2.close();
        } catch {}
      }
      return true;
    }),
    { numRuns: NUM_RUNS, seed: SEED },
  );
});
