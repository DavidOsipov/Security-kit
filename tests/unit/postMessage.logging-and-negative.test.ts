import { test, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createSecurePostMessageListener,
  POSTMESSAGE_MAX_PAYLOAD_BYTES,
} from '../../src/postMessage';
import { InvalidParameterError } from '../../src/errors';

const mockAddEventListener = vi.fn();
const mockRemoveEventListener = vi.fn();
const mockWindow = { addEventListener: mockAddEventListener, removeEventListener: mockRemoveEventListener } as any;

beforeEach(() => {
  vi.clearAllMocks();
  // Provide a window target used by listener registration
  Object.defineProperty(global, 'window', { writable: true, value: mockWindow });
});

afterEach(() => {
  vi.resetAllMocks();
});

// Helper to find the most recently-registered 'message' handler
function findHandler() {
  const calls = mockAddEventListener.mock.calls;
  for (let i = calls.length - 1; i >= 0; i--) {
    const c = calls[i];
    if (c && c[0] === 'message') return c[1];
  }
  throw new Error('message handler not registered');
}

test('secureDevLog emits security-kit:log events for origin-format warnings and for missing validator errors, and onMessage is not invoked in those cases', () => {
  // Capture security-kit:log events emitted via document.dispatchEvent
  const events: any[] = [];
  if (typeof document === 'undefined' || typeof document.addEventListener !== 'function') {
    // If document isn't available, create a minimal event target to receive dispatched events.
    // This should be unusual in the test harness; keep as fallback.
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    global.document = { addEventListener: (name: string, cb: any) => { /* noop */ }, dispatchEvent: () => true };
  }
  document.addEventListener('security-kit:log', (ev: any) => {
    try {
      events.push(ev.detail);
    } catch {
      events.push(null);
    }
  });

  // 1) Malformed/opaque origin triggers a warning via secureDevLog
  let invoked = false;
  const listener = createSecurePostMessageListener({
    allowedOrigins: ['https://example.com'],
    onMessage: () => { invoked = true; },
    validate: () => true,
    wireFormat: 'structured',
  });

  const handler = findHandler();
  // Simulate opaque origin (empty string) with no ports
  handler({ origin: '', source: {}, data: { a: 1 }, ports: [] } as any);

  // Allow some microtask time if dispatch is async — but document.dispatchEvent is sync
  expect(events.length).toBeGreaterThanOrEqual(1);
  const warnEvent = events.find((e) => typeof e?.message === 'string' && e.message.indexOf('Dropped message due to invalid origin format') !== -1);
  expect(warnEvent).toBeDefined();
  expect(invoked).toBe(false);

  listener.destroy();

  // Clear events for next sub-case
  events.length = 0;

  // 2) Missing validator logs an error and does not call consumer
  let invoked2 = false;
  const listenerNoValidator = createSecurePostMessageListener({
    allowedOrigins: ['https://example.com'],
    onMessage: () => { invoked2 = true; },
    // validate intentionally omitted
    wireFormat: 'structured',
  } as any);
  const handlerNoValidator = findHandler();
  handlerNoValidator({ origin: 'https://example.com', source: {}, data: { ok: 1 }, ports: [] } as any);

  const errEvent = events.find((e) => typeof e?.message === 'string' && e.message.indexOf('Message validator missing at runtime') !== -1);
  expect(errEvent).toBeDefined();
  expect(invoked2).toBe(false);
  listenerNoValidator.destroy();
});

test('createSecurePostMessageListener throws for invalid allowedOrigins', () => {
  expect(() => createSecurePostMessageListener({ allowedOrigins: [''], onMessage: () => {}, validate: () => true, wireFormat: 'structured' } as any)).toThrow(InvalidParameterError);
});

// Negative case: oversized JSON payload throws in sendSecurePostMessage (sanity)
// This ensures the constant is honored and surfaces in unit tests
import { sendSecurePostMessage } from '../../src/postMessage';

test('sendSecurePostMessage rejects oversized JSON payload', () => {
  const big = 'x'.repeat(POSTMESSAGE_MAX_PAYLOAD_BYTES + 1);
  const payload = { p: big };
  const mockTarget = { postMessage: vi.fn() } as any;
  expect(() => sendSecurePostMessage({ targetWindow: mockTarget, payload, targetOrigin: 'https://example.com', wireFormat: 'json' })).toThrow();
});
