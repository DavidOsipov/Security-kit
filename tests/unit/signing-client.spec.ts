import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SecureApiSigner } from '../../src/secure-api-signer';
import { createHmac } from 'crypto';

// Minimal MockWorker used only by these tests. It emulates the worker-side
// signing behavior (HMAC-SHA256 over `${timestamp}.${nonce}.${payload}`) and
// supports configurable artificial delays.
class MockWorker {
  listeners: Record<string, Function[]> = {};
  keyBytes: Buffer | null = null;
  opts: any;

  constructor(url: string, opts?: any) {
    this.opts = opts || {};
  }

  addEventListener(name: string, fn: Function) {
    (this.listeners[name] = this.listeners[name] || []).push(fn);
  }
  removeEventListener(name: string, fn: Function) {
    this.listeners[name] = (this.listeners[name] || []).filter(f => f !== fn);
  }

  postMessage(msg: any, transfer?: any[]) {
    if (msg.type === 'init') {
      // store key and reply initialized
      this.keyBytes = Buffer.from(msg.secretBuffer instanceof ArrayBuffer ? new Uint8Array(msg.secretBuffer) : msg.secretBuffer);
      setTimeout(() => this.emit('message', { data: { type: 'initialized' } }), 0);
      return;
    }

    // Handle handshake message transferred with a MessagePort
    if (msg.type === 'handshake' && transfer && transfer.length === 1) {
      const port = transfer[0] as MessagePort;
      // Compute a simple HMAC over the nonce using the stored keyBytes if available,
      // else reply with an empty signature so the test path continues.
      setTimeout(() => {
        try {
          const nonce = msg.nonce as string;
          const signature = this.keyBytes
            ? createHmac('sha256', this.keyBytes).update(nonce).digest('base64')
            : '';
          port.postMessage({ type: 'handshake', signature });
        } catch (e) {
          try { port.postMessage({ type: 'error', reason: 'handshake-failed' }); } catch {}
        } finally {
          try { port.close(); } catch {}
        }
      }, 0);
      return;
    }

    if (msg.type === 'sign') {
      const { requestId, payload, nonce, timestamp } = msg;
      const delay = this.opts.delayMs || 5;
      setTimeout(() => {
        // If a MessagePort was transferred, use it to respond so the client
        // receives the response on the corresponding local port.
        const port = transfer && transfer.length === 1 ? transfer[0] as MessagePort : null;
        if (!this.keyBytes) {
          const errorMsg = { type: 'error', requestId, reason: 'not-initialized' };
          if (port) {
            try { port.postMessage(errorMsg); } catch {};
            try { port.close(); } catch {}
          } else {
            this.emit('message', { data: errorMsg });
          }
          return;
        }
        const joined = `${timestamp}.${nonce}.${payload}`;
        const sig = createHmac('sha256', this.keyBytes).update(joined).digest('base64');
        const successMsg = { type: 'signed', requestId, signature: sig, nonce, timestamp };
        if (port) {
          try { port.postMessage(successMsg); } catch {};
          try { port.close(); } catch {}
        } else {
          this.emit('message', { data: successMsg });
        }
      }, delay);
      return;
    }

    if (msg.type === 'destroy') {
      setTimeout(() => this.emit('message', { data: { type: 'destroyed' } }), 0);
      return;
    }
  }

  terminate() {}

  emit(name: string, ev: any) {
    (this.listeners[name] || []).forEach(fn => {
      try { fn(ev); } catch (e) { /* swallow */ }
    });
  }
}

describe('SecureApiSigner (client) - basic flows', () => {
  let origWorker: any;

  beforeEach(() => {
    origWorker = (globalThis as any).Worker;
    (globalThis as any).Worker = MockWorker;
  });
  afterEach(() => {
    (globalThis as any).Worker = origWorker;
  });

  it('can create, sign and destroy (roundtrip with mock worker)', async () => {
  const key = new Uint8Array(Buffer.from('test-key-0123456789'));
  const signer = await SecureApiSigner.create({ secret: key, kid: 'unit-kid', workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });

    const signed = await signer.sign('hello-world');
    expect(typeof signed.signature).toBe('string');
    expect(signed.nonce).toBeTruthy();
    expect(typeof signed.timestamp).toBe('number');
    expect(signed.kid).toBe('unit-kid');

    await signer.destroy();
  });

  it('enforces maxPendingRequests on the client', async () => {
  const key = new Uint8Array(Buffer.from('test-key-xx'));
  const signer = await SecureApiSigner.create({ secret: key, maxPendingRequests: 2, workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });

    // start two long-running sign calls (slow worker to ensure overlap)
    (globalThis as any).Worker = function(url: string, opts?: any) {
      return new MockWorker(url, { delayMs: 50 });
    } as any;
    const p1 = signer.sign('a');
    const p2 = signer.sign('b');

    // third should throw synchronously (too many pending)
    await expect(signer.sign('c')).rejects.toThrow(/too-many-pending-sign-requests/);

    // cleanup: ensure promises resolve
    await Promise.allSettled([p1, p2]);
    await signer.destroy();
  });

  it('times out sign requests that take too long', async () => {
    // Replace Worker with a slow mock
    (globalThis as any).Worker = function(url: string, opts?: any) {
      return new MockWorker(url, { delayMs: 100 });
    } as any;

  const key = new Uint8Array(Buffer.from('timeout-key-zzz'));
  const signer = await SecureApiSigner.create({ secret: key, requestTimeoutMs: 20, workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });
    await expect(signer.sign('slow')).rejects.toThrow(/timed out/);
    await signer.destroy();
  });
});
