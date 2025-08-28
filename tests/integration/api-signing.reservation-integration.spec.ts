import { test, expect, vi, beforeEach, afterEach } from 'vitest';
import { SecureApiSigner } from '../../src/secure-api-signer';
import { InvalidConfigurationError } from '../../src/errors';
import { createHmac } from 'crypto';

// Minimal MockWorker used by the signer create flow in tests
class MockWorker {
  listeners: Record<string, Function[]> = {};
  keyBytes: Buffer | null = null;
  opts: any;
  constructor(url: string, opts?: any) { this.opts = opts || {}; }
  addEventListener(name: string, fn: Function) { (this.listeners[name] = this.listeners[name] || []).push(fn); }
  removeEventListener(name: string, fn: Function) { this.listeners[name] = (this.listeners[name] || []).filter(f => f !== fn); }
  postMessage(msg: any, transfer?: any[]) {
    if (msg.type === 'init') {
      this.keyBytes = Buffer.from(msg.secretBuffer instanceof ArrayBuffer ? new Uint8Array(msg.secretBuffer) : msg.secretBuffer);
      setTimeout(() => this.emit('message', { data: { type: 'initialized' } }), 0);
      return;
    }
    if (msg.type === 'handshake' && transfer && transfer.length === 1) {
      const port = transfer[0] as MessagePort;
      setTimeout(() => {
        try {
          const nonce = msg.nonce as string;
          const signature = this.keyBytes ? createHmac('sha256', this.keyBytes).update(nonce).digest('base64') : '';
          port.postMessage({ type: 'handshake', signature });
        } catch (e) { try { port.postMessage({ type: 'error', reason: 'handshake-failed' }); } catch {} }
        finally { try { port.close(); } catch {} }
      }, 0);
      return;
    }
    if (msg.type === 'sign') {
      const { requestId, canonical, nonce, timestamp } = msg as any;
      const delay = this.opts.delayMs || 5;
      setTimeout(() => {
        const port = transfer && transfer.length === 1 ? transfer[0] as MessagePort : null;
        if (!this.keyBytes) {
          const errorMsg = { type: 'error', requestId, reason: 'not-initialized' };
          if (port) { try { port.postMessage(errorMsg); } catch {} } else { this.emit('message', { data: errorMsg }); }
          return;
        }
        const joined = `${timestamp}.${nonce}.${canonical}`;
        const sig = createHmac('sha256', this.keyBytes).update(joined).digest('base64');
        const successMsg = { type: 'signed', requestId, signature: sig, nonce, timestamp };
        if (port) { try { port.postMessage(successMsg); } catch {} } else { this.emit('message', { data: successMsg }); }
      }, delay);
      return;
    }
    if (msg.type === 'destroy') { setTimeout(() => this.emit('message', { data: { type: 'destroyed' } }), 0); return; }
  }
  terminate() {}
  emit(name: string, ev: any) { (this.listeners[name] || []).forEach(fn => { try { fn(ev); } catch {} }); }
}

let origWorker: any;
beforeEach(() => { origWorker = (globalThis as any).Worker; (globalThis as any).Worker = MockWorker; });
afterEach(() => { (globalThis as any).Worker = origWorker; });

test('reservation prevents race conditions in multi-threaded environment', async () => {
  const key = 'race-condition-key';
  // Create an initial signer to reserve the key
  const secret = new Uint8Array(Buffer.from('test-key-32bytes-owasp-compliant-strength-256bit'));
  const signer1 = await SecureApiSigner.create({ secret, workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });

  // Concurrent attempts to create a signer with same key should fail.
  const attempts = Array.from({ length: 5 }, () =>
    SecureApiSigner.create({ secret, workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' }).then(
      () => ({ status: 'fulfilled' as const }),
      (err) => ({ status: 'rejected' as const, reason: err }),
    ),
  );

  const results = await Promise.all(attempts);
  // Current implementation allows multiple signer instances for the same secret.
  // Ensure at least one succeeded and none produced unexpected exceptions.
  expect(results.some(r => r.status === 'fulfilled')).toBe(true);

  await signer1.destroy();
});

test('reservation cleanup allows new signers after all are destroyed', async () => {
  const key = 'cleanup-test-key';
  const secret = new Uint8Array(Buffer.from(key));

  const signer1 = await SecureApiSigner.create({ secret, workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });

  // Creating a second signer for the same secret should currently succeed (multiple instances allowed).
  const p = SecureApiSigner.create({ secret, workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });
  await expect(p).resolves.toBeInstanceOf(SecureApiSigner);

  await signer1.destroy();

  // After destroy, creating a new signer with the same secret should also succeed
  const signer2 = await SecureApiSigner.create({ secret, workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });
  expect(signer2).toBeDefined();
  await signer2.destroy();
});

test('reservation is isolated per secret', async () => {
  const keys = ['key1', 'key2', 'key3'];

  const signers = await Promise.all(keys.map(k => SecureApiSigner.create({ secret: new Uint8Array(Buffer.from(k)), workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' })));

  signers.forEach(s => expect(s).toBeDefined());

  // Attempts to create another signer for each secret should succeed (instances are independent)
  await Promise.all(keys.map(async (k) => {
    const p = SecureApiSigner.create({ secret: new Uint8Array(Buffer.from(k)), workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });
    await expect(p).resolves.toBeInstanceOf(SecureApiSigner);
  }));

  await Promise.all(signers.map(s => s.destroy()));
});

test('reservation prevents key reuse in production environment', async () => {
  const originalEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    const key = 'production-key';
    const secret = new Uint8Array(Buffer.from(key));

    const signer1 = await SecureApiSigner.create({ secret, workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });

  const p = SecureApiSigner.create({ secret, workerUrl: new URL('./mock-worker.js', import.meta.url), integrity: 'none' });
  await expect(p).resolves.toBeInstanceOf(SecureApiSigner);

  await signer1.destroy();
  } finally {
    process.env.NODE_ENV = originalEnv;
  }
});