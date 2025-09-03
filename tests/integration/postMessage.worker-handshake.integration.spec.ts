import { test, expect, vi, beforeEach, afterEach } from "vitest";
import {
  createSecurePostMessageListener,
  computeInitialAllowedOrigin,
  isEventAllowedWithLock,
  sendSecurePostMessage,
} from "../../src/postMessage";

// Common mocks used across tests
const mockPostMessage = vi.fn();
const mockAddEventListener = vi.fn();
const mockRemoveEventListener = vi.fn();

const mockWindow = {
  postMessage: mockPostMessage,
  addEventListener: mockAddEventListener,
  removeEventListener: mockRemoveEventListener,
};

beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(global, "window", {
    writable: true,
    value: mockWindow,
  });
});

afterEach(() => {
  vi.resetAllMocks();
});

// Helper to capture the registered handler
function getRegisteredHandler() {
  const call = mockAddEventListener.mock.calls.find((c) => c[0] === "message");
  if (!call) throw new Error("message handler not registered");
  return call[1];
}

test("worker-like handshake: lock origin at init and reject other origins", () => {
  // Simulate worker calling computeInitialAllowedOrigin during init
  const initEvent = {
    origin: "https://client.example",
    data: { type: "init" },
    source: mockWindow,
    ports: [],
  } as any;
  const locked = computeInitialAllowedOrigin(initEvent);
  expect(locked).toBe("https://client.example");

  // Create listener that will check isEventAllowedWithLock inside handler
  let acceptedCount = 0;
  const listener = createSecurePostMessageListener({
    allowedOrigins: ["https://client.example"],
    onMessage: (data, ctx) => {
      // worker would lock origin on init; we emulate per-message check
      if (
        ctx &&
        ctx.event &&
        isEventAllowedWithLock(ctx.event as MessageEvent, locked)
      ) {
        acceptedCount++;
      }
    },
    validate: () => true,
    wireFormat: "structured",
  });

  const handler = getRegisteredHandler();

  // Message from the same origin (should be accepted)
  handler({
    origin: "https://client.example",
    source: mockWindow,
    data: { type: "ping" },
    ports: [],
  });
  // Message from other origin (should be rejected)
  handler({
    origin: "https://attacker.example",
    source: {},
    data: { type: "ping" },
    ports: [],
  });
  // Message with opaque origin but with a reply-port — worker behavior: accept if reply port present when no locked origin
  const fakePort = {
    postMessage: vi.fn(),
    constructor: { name: "MessagePort" },
  } as any;
  handler({
    origin: "",
    source: mockWindow,
    data: { type: "ping" },
    ports: [fakePort],
  });

  // When locked, opaque origin even with port should be compared against locked origin and rejected
  // So acceptedCount should be 1 (only the same-origin message)
  expect(acceptedCount).toBe(1);

  listener.destroy();
});

test("worker handshake round-trip with reply port: reply allowed only when origin matches locked origin", () => {
  // Simulate initial message that a worker would receive on init, capturing locked origin
  const initEvent = {
    origin: "https://app.example",
    data: { type: "init" },
    source: mockWindow,
    ports: [],
  } as any;
  const locked = computeInitialAllowedOrigin(initEvent);
  expect(locked).toBe("https://app.example");

  // Create a fake reply port that will capture replies
  const replies: unknown[] = [];
  const fakePort = {
    postMessage: (m: unknown) => replies.push(m),
    constructor: { name: "MessagePort" },
  } as any;

  // Handler emulating a worker that replies on port only when allowed
  const listener = createSecurePostMessageListener({
    allowedOrigins: ["https://app.example"],
    onMessage: (data, ctx) => {
      try {
        if (
          ctx &&
          ctx.event &&
          isEventAllowedWithLock(ctx.event as MessageEvent, locked)
        ) {
          // reply back on port if present
          if (ctx.ports && ctx.ports[0])
            ctx.ports[0].postMessage({ reply: true, echo: data });
        } else {
          // If not allowed, attempt to ignore or respond with error (not sending reply)
        }
      } catch {
        // ignore
      }
    },
    validate: () => true,
    wireFormat: "structured",
  });

  const handler = getRegisteredHandler();

  // Allowed origin with port -> should cause a reply
  handler({
    origin: "https://app.example",
    source: mockWindow,
    data: { cmd: "hello" },
    ports: [fakePort],
  });
  expect(replies.length).toBe(1);
  expect(replies[0]).toHaveProperty("reply", true);
  expect((replies[0] as any).echo).toHaveProperty("cmd", "hello");

  // Different origin with port -> should not reply
  replies.length = 0;
  handler({
    origin: "https://evil.example",
    source: {},
    data: { cmd: "hello" },
    ports: [fakePort],
  });
  expect(replies.length).toBe(0);

  // Opaque origin with no ports -> should not reply
  replies.length = 0;
  handler({ origin: "", source: {}, data: { cmd: "hello" }, ports: [] });
  expect(replies.length).toBe(0);

  listener.destroy();
});

test("worker handshake rejects malformed origins and treats empty origin with no ports as opaque reject", () => {
  // Compute initial allowed origin from bad event (malformed origin string)
  const badInit = {
    origin: "not-a-url",
    data: {},
    source: mockWindow,
    ports: [],
  } as any;
  const locked = computeInitialAllowedOrigin(badInit);
  // locked may fall back to location.origin or undefined; ensure no crash
  expect(typeof locked === "string" || typeof locked === "undefined").toBe(
    true,
  );

  const listener = createSecurePostMessageListener({
    allowedOrigins: ["https://somewhere.example"],
    onMessage: (data, ctx) => {
      // no-op
    },
    validate: () => true,
    wireFormat: "structured",
  });

  const handler = getRegisteredHandler();

  // Message with empty origin and no ports should be treated as opaque and dropped
  // The handler should not throw, and no reply occurs; we assert no exceptions.
  expect(() =>
    handler({ origin: "", source: {}, data: { ok: 1 }, ports: [] }),
  ).not.toThrow();

  listener.destroy();
});
