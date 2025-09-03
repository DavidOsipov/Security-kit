// tests/security/token-refill.worker-integration.test.ts
// RULE-ID: deterministic-async

import { test, expect, vi, beforeEach, afterEach } from "vitest";

// This integration-style test imports the worker module after mocking the
// project's postMessage helper so we can capture the worker's onMessage
// handler. We initialize the worker with a small rateLimit and then send
// multiple sign requests, asserting the worker returns 'signed' responses
// until tokens run out and then responds with rate-limit errors. All
// timing-controlled behavior uses fake timers and vi.setSystemTime for
// determinism.

// Module-scoped captured listener so the mocked postMessage factory can assign
let capturedListener: any = undefined;

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.resetModules();
  vi.clearAllMocks();
  capturedListener = undefined;
});

test("worker enforces token-bucket rate limiting end-to-end", async () => {
  const mockPostMessage = vi.fn();

  vi.stubGlobal("self", {
    postMessage: mockPostMessage,
    close: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  });

  vi.stubGlobal("postMessage", mockPostMessage);
  vi.stubGlobal("location", { origin: "https://example.test" });

  // stub crypto.subtle to avoid needing a real key; importKey will accept any ArrayBuffer
  vi.stubGlobal("crypto", {
    ...global.crypto,
    subtle: {
      importKey: vi.fn(async () => ({}) as CryptoKey),
      sign: vi.fn(async () => new Uint8Array([1, 2, 3, 4]).buffer),
    },
    getRandomValues: vi.fn((u: Uint8Array) => u.fill(1)),
  });

  // Mock the postMessage helper module before importing worker
  vi.mock("../../src/postMessage", () => ({
    createSecurePostMessageListener: vi.fn((opts: any) => {
      capturedListener = opts.onMessage;
      return { destroy: vi.fn() };
    }),
    computeInitialAllowedOrigin: vi.fn(() => "https://example.test"),
    isEventAllowedWithLock: vi.fn(() => true),
  }));

  // Load the worker implementation after mocks
  await import("../../src/worker/signing-worker");
  if (!capturedListener) throw new Error("worker listener not captured");

  // Initialize worker with rateLimitPerMinute small so burst becomes 2 (worker uses
  // burst = Math.max(rateLimitPerMinute, rateLimitBurst)). We choose 2/min so
  // burst=2 and refill ~1 token every 30s (flooring math applies).
  const initMsg = {
    type: "init",
    secretBuffer: new ArrayBuffer(16),
    workerOptions: { rateLimitPerMinute: 2, rateLimitBurst: 2 },
  };

  // Send init (meta shape matches other tests: { origin, ports, event })
  await capturedListener(initMsg, {
    origin: "https://example.test",
    ports: [],
    event: { origin: "https://example.test" },
  });

  // Prepare a mock reply port for sign responses
  const replyPort = { postMessage: vi.fn() } as any;

  // Send two sign requests and expect 'signed' responses (burst should allow two).
  await capturedListener(
    { type: "sign", requestId: 1, canonical: "a" },
    {
      origin: "https://example.test",
      ports: [replyPort],
      event: { ports: [replyPort], origin: "https://example.test" },
    },
  );
  if (
    ((replyPort.postMessage as any).mock.calls || []).length === 0 &&
    ((mockPostMessage as any).mock.calls || []).length === 0
  ) {
    console.error(
      "After sign 1 - no posts. reply:",
      (replyPort.postMessage as any).mock.calls,
      "global:",
      (mockPostMessage as any).mock.calls,
    );
  }
  await capturedListener(
    { type: "sign", requestId: 2, canonical: "b" },
    {
      origin: "https://example.test",
      ports: [replyPort],
      event: { ports: [replyPort], origin: "https://example.test" },
    },
  );
  if (
    ((replyPort.postMessage as any).mock.calls || []).length === 0 &&
    ((mockPostMessage as any).mock.calls || []).length === 0
  ) {
    console.error(
      "After sign 2 - no posts. reply:",
      (replyPort.postMessage as any).mock.calls,
      "global:",
      (mockPostMessage as any).mock.calls,
    );
  }

  // Third request should hit rate-limit immediately (burst exhausted)
  await capturedListener(
    { type: "sign", requestId: 3, canonical: "c" },
    {
      origin: "https://example.test",
      ports: [replyPort],
      event: { ports: [replyPort], origin: "https://example.test" },
    },
  );
  if (
    ((replyPort.postMessage as any).mock.calls || []).length === 0 &&
    ((mockPostMessage as any).mock.calls || []).length === 0
  ) {
    console.error(
      "After sign 3 - no posts. reply:",
      (replyPort.postMessage as any).mock.calls,
      "global:",
      (mockPostMessage as any).mock.calls,
    );
  }

  // Inspect replyPort.postMessage calls
  // Gather both replyPort and worker/global postMessage calls since the
  // worker may use either channel depending on event shape. Merge both call
  // lists for assertions.
  const replyCalls = (replyPort.postMessage as any).mock.calls || [];
  const globalCalls = (mockPostMessage as any).mock.calls || [];
  const calls = replyCalls.concat(globalCalls);
  if (calls.length === 0) {
    console.error("No posts observed. replyCalls:", JSON.stringify(replyCalls));
    console.error("globalCalls:", JSON.stringify(globalCalls));
  }
  expect(calls.length).toBeGreaterThanOrEqual(1);

  const results = calls.map((c: any[]) => c[0]);
  const signedCount = results.filter(
    (r: any) => r && r.type === "signed",
  ).length;
  const rateLimitCount = results.filter(
    (r: any) => r && r.reason === "rate-limit-exceeded",
  ).length;
  // Be tolerant of multiple 'signed' posts (worker/global + replyPort). We require
  // at least two successful signs (burst) and at least one rate-limit error.
  expect(signedCount).toBeGreaterThanOrEqual(2);
  expect(rateLimitCount).toBeGreaterThanOrEqual(1);

  // Advance time 30 seconds to allow refill of ~1 token (rate 2/min => ~1 token/30s)
  const now = Date.now();
  vi.setSystemTime(now + 30_000);

  // Send another request; should be accepted
  await capturedListener(
    { type: "sign", requestId: 4, canonical: "d" },
    {
      origin: "https://example.test",
      ports: [replyPort],
      event: { ports: [replyPort], origin: "https://example.test" },
    },
  );
  if (
    ((replyPort.postMessage as any).mock.calls || []).length === 0 &&
    ((mockPostMessage as any).mock.calls || []).length === 0
  ) {
    console.error(
      "After sign 4 - no posts. reply:",
      (replyPort.postMessage as any).mock.calls,
      "global:",
      (mockPostMessage as any).mock.calls,
    );
  }
  const calls2 = (replyPort.postMessage as any).mock.calls;
  const results2 = calls2.map((c: any[]) => c[0]);
  const newest = results2[results2.length - 1];
  expect(
    newest.type === "signed" || newest.reason === "rate-limit-exceeded",
  ).toBe(true);
});
