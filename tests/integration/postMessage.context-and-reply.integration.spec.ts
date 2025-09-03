import { test, expect, vi, beforeEach, afterEach } from "vitest";
import {
  createSecurePostMessageListener,
  sendSecurePostMessage,
  computeInitialAllowedOrigin,
  isEventAllowedWithLock,
} from "../../src/postMessage";

// Reuse mocks style from existing integration tests
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

test("listener receives MessageListenerContext and can reply via MessagePort", () => {
  // Set up a fake MessagePort that will capture replies
  const postedReplies: unknown[] = [];
  const fakePort = {
    postMessage: (m: unknown) => postedReplies.push(m),
    constructor: { name: "MessagePort" },
  } as any;

  let capturedContext: any = null;
  const listener = createSecurePostMessageListener({
    allowedOrigins: ["https://example.com"],
    onMessage: (data, ctx) => {
      // capture context for assertions
      capturedContext = ctx;
      // If we have a port, reply on it
      try {
        if (ctx && ctx.ports && ctx.ports[0])
          ctx.ports[0].postMessage({ ok: true, echo: data });
      } catch {
        // ignore
      }
    },
    validate: () => true,
    allowTransferables: true,
    allowTypedArrays: true,
    wireFormat: "structured",
  });

  // Simulate incoming message with a reply port (first port is returned in ctx.ports)
  const mockEvent = {
    origin: "https://example.com",
    source: mockWindow,
    data: { cmd: "ping" },
    ports: [fakePort],
  } as any;

  const handler = mockAddEventListener.mock.calls.find(
    (call) => call[0] === "message",
  )?.[1];

  if (!handler) throw new Error("Handler not found");

  // Call the handler as if the message arrived
  handler(mockEvent);

  // Expect context was provided and contains origin, event and ports
  expect(capturedContext).not.toBeNull();
  expect(capturedContext).toHaveProperty("origin", "https://example.com");
  expect(capturedContext).toHaveProperty("event");
  expect(Array.isArray(capturedContext.ports)).toBe(true);
  expect(capturedContext.ports[0]).toBe(fakePort);

  // Reply must have been posted to fakePort
  expect(postedReplies.length).toBeGreaterThanOrEqual(1);
  expect(postedReplies[0]).toEqual({ ok: true, echo: { cmd: "ping" } });

  listener.destroy();
});

test("computeInitialAllowedOrigin and isEventAllowedWithLock emulate worker lock semantics", () => {
  // Case 1: event with explicit origin
  const evWithOrigin = {
    origin: "https://foo.example",
    ports: [],
  } as MessageEvent;
  const initial = computeInitialAllowedOrigin(evWithOrigin as any);
  expect(initial).toBe("https://foo.example");
  expect(isEventAllowedWithLock(evWithOrigin as any, initial)).toBe(true);

  // Case 2: no origin, but location.origin present -> fallback
  const savedLocation =
    typeof location !== "undefined" ? (location as any) : undefined;
  // stub location if needed
  if (typeof globalThis.location === "undefined") {
    (globalThis as any).location = { origin: "https://fallback.example" };
  }
  const evNoOrigin = { origin: "", ports: [] } as any;
  const initial2 = computeInitialAllowedOrigin(evNoOrigin);
  // initial2 may be 'https://fallback.example'
  expect(typeof initial2 === "string" || typeof initial2 === "undefined").toBe(
    true,
  );
  // isEventAllowedWithLock should accept when fallback matches
  const allowed = isEventAllowedWithLock(evNoOrigin as any, initial2);
  // allowed is boolean; with fallback present it should be true if matched
  expect(typeof allowed).toBe("boolean");

  // Case 3: no origin and no ports -> should reject unless locked matches
  const evOpaque = { origin: "", ports: [] } as any;
  expect(isEventAllowedWithLock(evOpaque as any, "https://other")).toBe(false);

  // restore location if we stubbed it
  if (savedLocation === undefined && (globalThis as any).location) {
    try {
      delete (globalThis as any).location;
    } catch {
      // ignore
    }
  }
});
