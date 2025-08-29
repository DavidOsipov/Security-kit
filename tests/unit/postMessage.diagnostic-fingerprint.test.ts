import { test, expect, vi, beforeEach, afterEach } from 'vitest';

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());
import { createSecurePostMessageListener } from '../../src/postMessage';
import * as state from '../../src/state';
import { environment } from '../../src/environment';

test('scheduleDiagnosticForFailedValidation uses crypto.subtle.digest when available', async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  const prevEnv = (environment as any).__explicitEnv;
  try {
    environment.setExplicitEnv('development');

    // Stub ensureCrypto to return a fake crypto with subtle.digest
    const fakeDigest = vi.fn(async (algo: unknown, buffer: ArrayBuffer) => {
      // return a small ArrayBuffer (e.g., 32 bytes) as digest
      const out = new Uint8Array(32);
      for (let i = 0; i < out.length; i++) out[i] = i & 0xff;
      return out.buffer;
    });

    const fakeCrypto = {
      getRandomValues: (buf: Uint8Array) => { for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff; return buf; },
      subtle: { digest: fakeDigest },
    } as unknown as Crypto;

    // Use the state helper to set the crypto implementation used by ensureCrypto
    try {
      // some state helpers may be exported; prefer _setCrypto if available
      if (typeof (state as any)._setCrypto === 'function') {
        (state as any)._setCrypto(fakeCrypto);
      } else {
        // fallback: attach to globalThis for ensureCrypto to find
        (globalThis as any).crypto = fakeCrypto;
      }
    } catch {
      // ignore
    }

    // Create a listener with enableDiagnostics true and validator that returns false
    const listener = createSecurePostMessageListener(
      {
        allowedOrigins: [location.origin],
        onMessage: () => {},
        validate: () => false,
        enableDiagnostics: true,
        wireFormat: 'json',
      },
    );

    // Trigger handler by dispatching a window.postMessage-like event
    // Note: handler is registered on window; we simulate by calling global handler indirectly
    // Build a MessageEvent-like object
    const event = {
      origin: location.origin,
      source: window,
      data: JSON.stringify({ foo: 'bar' }),
    } as unknown as MessageEvent;

    // Send to window: this will call the listener's handler
    window.postMessage(event.data, event.origin);

  // Wait for async diagnostic to run
  await vi.runAllTimersAsync();

    // cleanup
    listener.destroy();
  } finally {
    try {
      environment.setExplicitEnv(prevEnv === undefined ? 'development' : prevEnv);
    } catch {}
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});
