import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// Purpose: deterministically exercise sha256Hex fallback strategies by mocking
// dynamic imports and globalThis.crypto. We import the module under test
// after setting up the mocks so the internal function picks up the mocked
// implementations during dynamic import.

function clearModuleCache(modulePath: string) {
  try {
    // @ts-ignore - Node's require cache
    const r = require as unknown as NodeRequire;
    if (r && r.cache) {
      for (const key of Object.keys(r.cache)) {
        if (key.includes('src/dom')) delete r.cache[key];
      }
    }
  } catch {
    // ignore in ESM-only environments
  }
}

// Helper to import the DOM module fresh
async function importDomModule() {
  // clear require cache to allow re-import picks up new mocks
  clearModuleCache('src/dom');
  const mod = await import('../../src/dom');
  return mod;
}

describe('sha256Hex fallback strategies (deterministic)', () => {
  let originalGlobalCrypto: unknown;
  let originalSubtleDigest: unknown;

  beforeEach(() => {
    originalGlobalCrypto = (globalThis as any).crypto;
    originalSubtleDigest = (globalThis as any)?.crypto?.subtle?.digest;
    // ensure no leftover mocked dynamic imports
    vi.resetModules();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    // restore subtle.digest if we replaced it
    try {
      if ((globalThis as any)?.crypto?.subtle && typeof originalSubtleDigest === 'function') {
        (globalThis as any).crypto.subtle.digest = originalSubtleDigest;
      }
    } catch {
      /* ignore */
    }
    try {
      // restore any global stubs created via vi.stubGlobal
      // vitest provides vi.unstubGlobal; if unavailable, fallback to restoreAllMocks
      // @ts-ignore
      if (typeof vi.unstubGlobal === 'function') vi.unstubGlobal('crypto');
    } catch {}
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('uses node:crypto when available', async () => {
    // Force webcrypto path to fail by stubbing subtle.digest to reject using vitest global stub
    vi.stubGlobal('crypto', { subtle: { digest: async () => { throw new Error('forced failure'); } } });

    // Mock dynamic import of node:crypto. Return a module whose createHash returns a digest we expect.
    vi.mock('node:crypto', () => ({
      createHash: (_alg: string) => ({
        update: (_s: string) => ({ digest: (_enc?: string) => Buffer.from('aabb', 'hex') }),
      }),
    }));

    const mod = await importDomModule();
    const sha = (mod as any).__test_sha256Hex as any as (s: string) => Promise<string>;
    // Install importer override to deterministically return our fake node:crypto module
    (sha as any).__test_importOverride = async (spec: string) => {
      if (spec === 'node:crypto') {
        return {
          createHash: (_alg: string) => ({
            update: (_s: string) => ({ digest: (_enc?: string) => 'aabb' }),
          }),
        };
      }
      // make other imports fail quickly
      return Promise.reject(new Error('unavailable'));
    };
    const out = await sha('abc');
    expect(typeof out).toBe('string');
    // because our fake returns 'aabb' hex we expect that string
    expect(out).toBe('aabb');
  });

  it('uses fast-sha256 when node:crypto unavailable', async () => {
    // Provide fast-sha256 mock
    // Force webcrypto to fail (use global stub)
  vi.stubGlobal('crypto', { subtle: { digest: async () => { throw new Error('forced failure'); } } });
  // Ensure node:crypto import will appear unavailable by providing an implementation that throws when used
  vi.mock('node:crypto', () => ({ createHash: () => { throw new Error('unavailable'); } }));
  vi.mock('fast-sha256', () => ({ hashHex: (s: string) => 'ff11' }));

    const mod = await importDomModule();
    const sha = (mod as any).__test_sha256Hex as any as (s: string) => Promise<string>;
    (sha as any).__test_importOverride = async (spec: string) => {
      if (spec === 'fast-sha256') return { hashHex: (s: string) => 'ff11' };
      return Promise.reject(new Error('unavailable'));
    };
    const out = await sha('hello');
    expect(out).toBe('ff11');
  });

  it('uses hash-wasm when earlier options unavailable', async () => {
    // Provide a mock that exposes sha256 which returns a Promise
    // Force earlier strategies to fail
  vi.stubGlobal('crypto', { subtle: { digest: async () => { throw new Error('forced failure'); } } });
  vi.mock('node:crypto', () => ({ createHash: () => { throw new Error('unavailable'); } }));
  vi.mock('fast-sha256', () => ({ hashHex: () => { throw new Error('unavailable'); } }));
  vi.mock('hash-wasm', () => ({ sha256: (s: string) => Promise.resolve('hh22') }));

    const mod = await importDomModule();
    const sha = (mod as any).__test_sha256Hex as any as (s: string) => Promise<string>;
    (sha as any).__test_importOverride = async (spec: string) => {
      if (spec === 'hash-wasm') return { sha256: (s: string) => Promise.resolve('hh22') };
      return Promise.reject(new Error('unavailable'));
    };
    const out = await sha('xyz');
    expect(out).toBe('hh22');
  });

  it('prefers WebCrypto when present', async () => {
    // Provide a globalThis.crypto.subtle implementation using vitest stubGlobal
    vi.stubGlobal('crypto', { subtle: { digest: async (_alg: string, data: ArrayBuffer) => new Uint8Array([1, 2, 3]).buffer } });

  const mod = await importDomModule();
  const sha = (mod as any).__test_sha256Hex as any as (s: string) => Promise<string>;
  // ensure no importer override remains
  (sha as any).__test_importOverride = undefined;
  const out = await sha('whatever');
    // Expect digest to be hex of 010203
    expect(out).toBe('010203');
  });

  it('times out and throws when no implementation available', async () => {
    // Force webcrypto to fail and make other imports unavailable
  vi.stubGlobal('crypto', { subtle: { digest: async () => { throw new Error('forced failure'); } } });
  vi.mock('node:crypto', () => ({ createHash: () => { throw new Error('unavailable'); } }));
  vi.mock('fast-sha256', () => ({ hashHex: () => { throw new Error('unavailable'); } }));
  vi.mock('hash-wasm', () => ({ sha256: () => { throw new Error('unavailable'); } }));

  const mod = await importDomModule();
  const sha = (mod as any).__test_sha256Hex as any as (s: string) => Promise<string>;
  (sha as any).__test_importOverride = async () => Promise.reject(new Error('unavailable'));
  await expect(sha('abc')).rejects.toThrow();
  });
});
