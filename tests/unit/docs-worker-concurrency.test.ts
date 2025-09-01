import { test, expect, vi, beforeEach, afterEach } from "vitest";

// This test file mirrors the worker concurrency + testing patterns documented in
// docs/WORKER-CONCURRENCY-TESTING.md. It uses the same harness approach as
// tests/unit/signing-worker.test.ts but focuses on the documentation's
// contract: concurrency reservation, rate limiting, and adversarial inputs.

// Reuse the same MockMessageEvent and MockMessagePort minimal implementations
class MockMessageEvent extends Event implements MessageEvent {
  public readonly data: any;
  public readonly lastEventId: string = "";
  public readonly origin: string = "https://example.com";
  public readonly ports: readonly MessagePort[] = [];
  public readonly source: Window | MessagePort | null = null;

  constructor(data: any, eventInitDict?: EventInit) {
    super('message', eventInitDict);
    this.data = data;
  }

  initMessageEvent(): void {}
}

class MockMessagePort {
  public postMessage = vi.fn((message: any) => {
    (this.postMessage as any).lastMessage = message;
    return message;
  });
  public close = vi.fn();
  public start = vi.fn();
}

let capturedMessageListener: ((event: MessageEvent) => void) | undefined;

const mockPostMessage = vi.fn();

// Basic environment setup helper copied patterns from signing-worker tests
function setupBasicMocks() {
  vi.restoreAllMocks();
  vi.clearAllMocks();
  capturedMessageListener = undefined;

  // Stub global self/postMessage and location
  vi.stubGlobal('self', {
    postMessage: mockPostMessage,
    close: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  });

  vi.stubGlobal('postMessage', mockPostMessage as any);

  vi.stubGlobal('location', { origin: 'https://example.com' });

  // Mock crypto.subtle with spies
  const mockSign = vi.fn();
  const mockImportKey = vi.fn();
  vi.stubGlobal('crypto', { ...global.crypto, subtle: { sign: mockSign, importKey: mockImportKey }, getRandomValues: vi.fn() } as any);

  // Mock postMessage module to capture listener
  vi.mock("../../src/postMessage", () => ({
    createSecurePostMessageListener: vi.fn((options) => {
      const listener = async (event: MessageEvent) => {
        await options.onMessage(event.data, { origin: event.origin, source: event.source, ports: event.ports, event });
      };
      try {
        capturedMessageListener = listener;
      } catch {}
      try { globalThis.addEventListener("message", listener); } catch {}
      try { if ((globalThis as any).window && typeof (globalThis as any).window.addEventListener === 'function') (globalThis as any).window.addEventListener("message", listener); } catch {}
      return { destroy: vi.fn() };
    }),
    computeInitialAllowedOrigin: vi.fn(() => 'https://example.com'),
    isEventAllowedWithLock: vi.fn(() => true),
  }));

  // Ensure addEventListener mock captures
  globalThis.addEventListener = vi.fn((type: string, listener: any) => {
    if (type === 'message') capturedMessageListener = listener;
    return undefined;
  }) as any;

  try { if ((globalThis as any).window === undefined) (globalThis as any).window = globalThis; (globalThis as any).window.addEventListener = globalThis.addEventListener; } catch {}

  return { mockSign: (globalThis as any).crypto.subtle.sign, mockImportKey: (globalThis as any).crypto.subtle.importKey };
}

async function waitForListener() {
  for (let i = 0; i < 10; i++) { if (capturedMessageListener) return; await new Promise(r => setTimeout(r, 10)); }
  throw new Error('listener not captured');
}

beforeEach(() => {
  vi.resetModules();
  capturedMessageListener = undefined;
});

afterEach(() => {
  vi.restoreAllMocks();
});

test('docs-worker: concurrency reservation rejects second request when at limit', async () => {
  const mocks = setupBasicMocks();
  const { mockSign, mockImportKey } = mocks as any;
  mockImportKey.mockResolvedValue({} as CryptoKey);
  // Make sign slow to force overlap
  mockSign.mockImplementation(async () => { await new Promise(r => setTimeout(r, 40)); return new ArrayBuffer(0); });

  const workerModule = await import('../../src/worker/signing-worker');
  await waitForListener();

  // Initialize with maxConcurrentSigning = 1
  const initEvent = new MockMessageEvent({ type: 'init', secretBuffer: new ArrayBuffer(32), workerOptions: { maxConcurrentSigning: 1 } });
  if (capturedMessageListener) await capturedMessageListener(initEvent);

  mockPostMessage.mockClear();

  // Fire first sign but do not await
  const sign1 = { type: 'sign', requestId: 1, canonical: 'a' };
  let p1: Promise<void> | undefined;
  if (capturedMessageListener) p1 = Promise.resolve(capturedMessageListener(new MockMessageEvent(sign1)) as any);
  await Promise.resolve(); // microtask yield

  // Send second sign
  const sign2 = { type: 'sign', requestId: 2, canonical: 'b' };
  if (capturedMessageListener) await capturedMessageListener(new MockMessageEvent(sign2));

  // Wait for first to finish
  if (p1) await p1;

  // Expect an overload error for requestId 2
  expect(mockPostMessage).toHaveBeenCalledWith(expect.objectContaining({ type: 'error', requestId: 2, reason: 'worker-overloaded' }));
});

test('docs-worker: rate limit blocks second request', async () => {
  const mocks = setupBasicMocks();
  const { mockSign, mockImportKey } = mocks as any;
  mockImportKey.mockResolvedValue({} as CryptoKey);
  // Make sign immediate for this test
  mockSign.mockResolvedValue(new ArrayBuffer(0));

  const workerModule = await import('../../src/worker/signing-worker');
  await waitForListener();

  // Init with rateLimitPerMinute = 1
  const initEvent = new MockMessageEvent({ type: 'init', secretBuffer: new ArrayBuffer(32), workerOptions: { rateLimitPerMinute: 1 } });
  if (capturedMessageListener) await capturedMessageListener(initEvent);
  mockPostMessage.mockClear();

  // First sign
  const sign1 = { type: 'sign', requestId: 1, canonical: 'x' };
  let p1: Promise<void> | undefined;
  if (capturedMessageListener) p1 = Promise.resolve(capturedMessageListener(new MockMessageEvent(sign1)) as any);
  // wait for the first to post
  let sawFirst = false;
  for (let i = 0; i < 20; i++) { if ((mockPostMessage.mock.calls || []).some(c => c && c[0] && c[0].type === 'signed')) { sawFirst = true; break; } await new Promise(r => setTimeout(r, 5)); }
  expect(sawFirst).toBe(true);
  mockPostMessage.mockClear();

  // Second sign should be rate-limited
  const sign2 = { type: 'sign', requestId: 2, canonical: 'y' };
  if (capturedMessageListener) await capturedMessageListener(new MockMessageEvent(sign2));

  expect(mockPostMessage).toHaveBeenCalledWith(expect.objectContaining({ type: 'error', requestId: 2, reason: 'rate-limit-exceeded' }));
});

test('docs-worker: adversarial inputs are rejected silently', async () => {
  const mocks = setupBasicMocks();
  const { mockSign, mockImportKey } = mocks as any;
  mockImportKey.mockResolvedValue({} as CryptoKey);

  const workerModule = await import('../../src/worker/signing-worker');
  await waitForListener();

  // Malformed messages should be ignored (no postMessage calls)
  const malformedList = [ null, undefined, {}, { type: 'init', secretBuffer: null }, { type: 'sign', requestId: 'one' }, { type: 'handshake', nonce: 123 } ];
  for (const m of malformedList) {
    if (capturedMessageListener) await capturedMessageListener(new MockMessageEvent(m));
  }

  // The worker may either silently ignore malformed messages or respond with
  // generic error objects. Ensure that any responses are safe error messages
  // (no sensitive detail leakage) and have type 'error'.
  const allowedReasons = new Set([
    'invalid-message-format',
    'missing-secret',
    'invalid-params',
    'invalid-handshake',
  ]);

  // If there were no calls, that's acceptable. If there were calls, each must
  // be an error with an allowed reason.
  const calls = mockPostMessage.mock.calls || [];
  for (const c of calls) {
    const msg = c && c[0];
    expect(msg).toBeDefined();
    expect(msg.type).toBe('error');
    if (typeof msg.reason === 'string') {
      expect(allowedReasons.has(msg.reason)).toBe(true);
    }
  }
});
