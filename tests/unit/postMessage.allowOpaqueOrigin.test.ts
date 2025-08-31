import { test, expect, vi, beforeEach, afterEach } from 'vitest';
import { createSecurePostMessageListener } from '../../src/postMessage';

const mockAddEventListener = vi.fn();
const mockRemoveEventListener = vi.fn();
const mockWindow = { addEventListener: mockAddEventListener, removeEventListener: mockRemoveEventListener } as any;

beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(global, 'window', { writable: true, value: mockWindow });
});

afterEach(() => {
  vi.resetAllMocks();
});

// Helper to find the registered 'message' handler
function findHandler() {
  // Multiple listeners may be registered during the test; return the most
  // recently-registered handler for 'message'. Search the mock calls from
  // the end to avoid invoking an earlier listener's handler accidentally.
  const calls = mockAddEventListener.mock.calls;
  for (let i = calls.length - 1; i >= 0; i--) {
    const c = calls[i];
    if (c && c[0] === 'message') return c[1];
  }
  throw new Error('message handler not registered');
}

// Very thorough unit test for allowOpaqueOrigin behavior
test('createSecurePostMessageListener: allowOpaqueOrigin opt-in and default reject behavior', () => {
  // Case A: allowOpaqueOrigin = false (default) -> opaque origin rejected even if ports present
  let receivedA: any = null;
  const listenerA = createSecurePostMessageListener({ allowedOrigins: [], onMessage: (d, ctx) => { receivedA = { d, ctx }; }, validate: () => true, wireFormat: 'structured' });
  const handlerA = findHandler();

  const fakePort = { postMessage: vi.fn(), constructor: { name: 'MessagePort' } } as any;
  // Simulate an opaque-origin message with a reply port
  handlerA({ origin: '', source: mockWindow, data: { foo: 'a' }, ports: [fakePort] } as any);

  // Expect dropped (no invocation)
  expect(receivedA).toBeNull();
  listenerA.destroy();

  // Case B: allowOpaqueOrigin = true -> opaque origin accepted if opt-in
  let receivedB: any = null;
  const listenerB = createSecurePostMessageListener({ allowedOrigins: [], onMessage: (d, ctx) => { receivedB = { d, ctx }; }, validate: () => true, wireFormat: 'structured', allowOpaqueOrigin: true });
  const handlerB = findHandler();

  const fakePortB = { postMessage: vi.fn(), constructor: { name: 'MessagePort' } } as any;
  handlerB({ origin: '', source: mockWindow, data: { foo: 'b' }, ports: [fakePortB] } as any);

  expect(receivedB).not.toBeNull();
  expect(receivedB.ctx).toHaveProperty('ports');
  expect(Array.isArray(receivedB.ctx?.ports)).toBeTruthy();
  listenerB.destroy();

  // Case C: allowOpaqueOrigin = true but no ports -> still accepted by opt-in (library allows opaque when opted-in)
  // The opt-in is explicit and library does not require ports when allowOpaqueOrigin=true
  let receivedC: any = null;
  const listenerC = createSecurePostMessageListener({ allowedOrigins: [], onMessage: (d, ctx) => { receivedC = { d, ctx }; }, validate: () => true, wireFormat: 'structured', allowOpaqueOrigin: true });
  const handlerC = findHandler();

  handlerC({ origin: '', source: mockWindow, data: { foo: 'c' }, ports: [] } as any);
  expect(receivedC).not.toBeNull();
  listenerC.destroy();

  // Case D: explicitly rejected malformed 'null' string vs empty string consistency
  let receivedD: any = null;
  const listenerD = createSecurePostMessageListener({ allowedOrigins: [], onMessage: (d, ctx) => { receivedD = { d, ctx }; }, validate: () => true, wireFormat: 'structured', allowOpaqueOrigin: true });
  const handlerD = findHandler();

  handlerD({ origin: 'null', source: mockWindow, data: { foo: 'd' }, ports: [fakePort] } as any);
  expect(receivedD).not.toBeNull();
  listenerD.destroy();
});
