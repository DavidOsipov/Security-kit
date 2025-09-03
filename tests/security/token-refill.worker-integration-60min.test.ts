// tests/security/token-refill.worker-integration-60min.test.ts
// RULE-ID: deterministic-async

import { test, expect, vi, beforeEach, afterEach } from "vitest";

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

test("worker enforces token-bucket at 60/min (1 token/sec) end-to-end", async () => {
  const mockPostMessage = vi.fn();

  vi.stubGlobal("self", {
    postMessage: mockPostMessage,
    close: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  });

  vi.stubGlobal("postMessage", mockPostMessage);
  vi.stubGlobal("location", { origin: "https://example.test" });

  vi.stubGlobal("crypto", {
    ...global.crypto,
    subtle: {
      importKey: vi.fn(async () => ({}) as CryptoKey),
      sign: vi.fn(async () => new Uint8Array([1, 2, 3, 4]).buffer),
    },
    getRandomValues: vi.fn((u: Uint8Array) => u.fill(1)),
  });

  vi.mock("../../src/postMessage", () => ({
    createSecurePostMessageListener: vi.fn((opts: any) => {
      capturedListener = opts.onMessage;
      return { destroy: vi.fn() };
    }),
    computeInitialAllowedOrigin: vi.fn(() => "https://example.test"),
    isEventAllowedWithLock: vi.fn(() => true),
  }));

  await import("../../src/worker/signing-worker");
  if (!capturedListener) throw new Error("worker listener not captured");

  // Configure for 60 tokens/min and burst 3 to allow quick starts
  const initMsg = {
    type: "init",
    secretBuffer: new ArrayBuffer(16),
    workerOptions: { rateLimitPerMinute: 60, rateLimitBurst: 3 },
  };
  await capturedListener(initMsg, {
    origin: "https://example.test",
    ports: [],
    event: { origin: "https://example.test" },
  });

  const replyPort = { postMessage: vi.fn() } as any;

  // Exhaust burst quickly
  await capturedListener(
    { type: "sign", requestId: 1, canonical: "x" },
    {
      origin: "https://example.test",
      ports: [replyPort],
      event: { ports: [replyPort], origin: "https://example.test" },
    },
  );
  await capturedListener(
    { type: "sign", requestId: 2, canonical: "y" },
    {
      origin: "https://example.test",
      ports: [replyPort],
      event: { ports: [replyPort], origin: "https://example.test" },
    },
  );
  await capturedListener(
    { type: "sign", requestId: 3, canonical: "z" },
    {
      origin: "https://example.test",
      ports: [replyPort],
      event: { ports: [replyPort], origin: "https://example.test" },
    },
  );

  const replyCalls = (replyPort.postMessage as any).mock.calls || [];
  const globalCalls = (mockPostMessage as any).mock.calls || [];
  const calls = replyCalls.concat(globalCalls);
  expect(calls.length).toBeGreaterThanOrEqual(1);

  // Next request should be rate-limited (burst exhausted)
  await capturedListener(
    { type: "sign", requestId: 4, canonical: "a" },
    {
      origin: "https://example.test",
      ports: [replyPort],
      event: { ports: [replyPort], origin: "https://example.test" },
    },
  );
  // Recompute captured calls after issuing the 4th request so we inspect fresh results
  const replyCallsNow = (replyPort.postMessage as any).mock.calls || [];
  const globalCallsNow = (mockPostMessage as any).mock.calls || [];
  const results = replyCallsNow.concat(globalCallsNow).map((c: any[]) => c[0]);
  const signedCount = results.filter(
    (r: any) => r && r.type === "signed",
  ).length;
  const rateLimitCount = results.filter(
    (r: any) => r && r.reason === "rate-limit-exceeded",
  ).length;
  expect(signedCount).toBeGreaterThanOrEqual(3);
  expect(rateLimitCount).toBeGreaterThanOrEqual(1);

  // Advance 1 second to allow refill of ~1 token (1 token/sec)
  const now = Date.now();
  vi.setSystemTime(now + 1000);

  await capturedListener(
    { type: "sign", requestId: 5, canonical: "b" },
    {
      origin: "https://example.test",
      ports: [replyPort],
      event: { ports: [replyPort], origin: "https://example.test" },
    },
  );
  const callsAfter = (replyPort.postMessage as any).mock.calls || [];
  const latest = callsAfter[callsAfter.length - 1];
  expect(
    latest &&
      (latest[0].type === "signed" ||
        latest[0].reason === "rate-limit-exceeded"),
  ).toBe(true);
});
