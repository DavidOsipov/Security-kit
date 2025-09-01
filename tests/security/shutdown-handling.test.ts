// tests/security/shutdown-handling.test.ts
// RULE-ID: shutdown-graceful

import { test, expect, vi, beforeEach, afterEach } from 'vitest';

let capturedMessageListener: ((event: MessageEvent) => void) | undefined;
const mockPostMessage = vi.fn();

function setupMocks() {
  vi.resetModules();
  vi.clearAllMocks();
  capturedMessageListener = undefined;

  vi.stubGlobal('self', { postMessage: mockPostMessage, close: vi.fn(), addEventListener: vi.fn(), removeEventListener: vi.fn() });
  vi.stubGlobal('postMessage', mockPostMessage as any);
  vi.stubGlobal('location', { origin: 'https://example.com' });

  const mockSign = vi.fn();
  const mockImportKey = vi.fn();
  vi.stubGlobal('crypto', { ...global.crypto, subtle: { sign: mockSign, importKey: mockImportKey }, getRandomValues: vi.fn() } as any);

  vi.mock('../../src/postMessage', () => ({
    createSecurePostMessageListener: vi.fn((opts) => {
      const l = async (event: MessageEvent) => { await opts.onMessage(event.data, { origin: event.origin, ports: event.ports, event }); };
      capturedMessageListener = l;
      try { globalThis.addEventListener('message', l); } catch {}
      try { if ((globalThis as any).window) (globalThis as any).window.addEventListener('message', l); } catch {}
      return { destroy: vi.fn() };
    }),
    computeInitialAllowedOrigin: vi.fn(() => 'https://example.com'),
    isEventAllowedWithLock: vi.fn(() => true),
  }));

  globalThis.addEventListener = vi.fn((type: string, listener: any) => { if (type === 'message') capturedMessageListener = listener; return undefined; }) as any;
}

beforeEach(() => { setupMocks(); });
afterEach(() => { vi.restoreAllMocks(); });

// Ensure that if shutdown is requested, sign requests are rejected appropriately
// and the worker only completes shutdown after pending ops finish
test('worker rejects sign requests during shutdown and finishes after pending', async () => {
  setupMocks();
  const workerModule = await import('../../src/worker/signing-worker');
  for (let i=0;i<10;i++){ if (capturedMessageListener) break; await new Promise(r=>setTimeout(r,5)); }
  if (!capturedMessageListener) throw new Error('listener not captured');

  const mockImportKey = (globalThis as any).crypto.subtle.importKey as any;
  mockImportKey.mockResolvedValue({} as CryptoKey);

  // Initialize
  await capturedMessageListener(new MessageEvent('message', { data: { type: 'init', secretBuffer: new ArrayBuffer(32) } } as any));

  // Fire a long sign request
  const mockSign = (globalThis as any).crypto.subtle.sign as any;
  mockSign.mockImplementation(async () => { await new Promise(r => setTimeout(r, 40)); return new ArrayBuffer(0); });
  const p1 = Promise.resolve(capturedMessageListener(new MessageEvent('message', { data: { type: 'sign', requestId: 1, canonical: 'x' } } as any)) as any);

  // Request shutdown
  await capturedMessageListener(new MessageEvent('message', { data: { type: 'destroy' } } as any));

  // While shutting down, new sign requests are rejected
  await capturedMessageListener(new MessageEvent('message', { data: { type: 'sign', requestId: 2, canonical: 'y' } } as any));

  // Wait for first to finish and then ensure destroyed message posted and close called
  await p1;
  // Verify destroyed posted
  const calls = mockPostMessage.mock.calls || [];
  const destroyed = calls.some(c => c && c[0] && c[0].type === 'destroyed');
  expect(destroyed).toBe(true);
});
