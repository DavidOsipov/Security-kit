// tests/security/init-guard.test.ts
// RULE-ID: init-guard

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

test('worker rejects duplicate init during initializing', async () => {
  setupMocks();
  const workerModule = await import('../../src/worker/signing-worker');
  for (let i=0;i<10;i++){ if (capturedMessageListener) break; await new Promise(r=>setTimeout(r,5)); }
  if (!capturedMessageListener) throw new Error('listener not captured');

  const mockImportKey = (globalThis as any).crypto.subtle.importKey as any;
  // Make importKey slow to simulate concurrent init attempts
  mockImportKey.mockImplementation(async () => { await new Promise(r => setTimeout(r, 40)); return {} as CryptoKey; });

  const init1 = new MessageEvent('message', { data: { type: 'init', secretBuffer: new ArrayBuffer(32) }, origin: 'https://example.com' } as any);
  const init2 = new MessageEvent('message', { data: { type: 'init', secretBuffer: new ArrayBuffer(32) }, origin: 'https://example.com' } as any);

  const p1 = Promise.resolve(capturedMessageListener(init1) as any);
  // Fire the second init immediately to ensure it arrives during the first's importKey
  await capturedMessageListener(init2);

  // Wait for first to finish
  await p1;

  // Validate responses: we should see one 'initialized' and at least one safe error (already-initialized or missing-secret)
  const calls = mockPostMessage.mock.calls || [];
  const types = calls.map((c) => (c && c[0] && c[0].type));
  expect(types).toContain('initialized');

  const errorCalls = calls.map((c) => (c && c[0])).filter(Boolean).filter((m) => m.type === 'error');
  // There should be at least one error response (the second init should be rejected)
  expect(errorCalls.length).toBeGreaterThanOrEqual(1);
  const allowed = new Set(['already-initialized', 'missing-secret']);
  expect(errorCalls.some((m) => typeof m.reason === 'string' && allowed.has(m.reason))).toBe(true);
});
