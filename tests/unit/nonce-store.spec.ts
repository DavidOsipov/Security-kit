import { describe, it, expect, beforeEach } from 'vitest';
import { NonceStore } from '../../server/nonce-store';
import { InvalidParameterError } from '../../src/errors';

describe('NonceStore (sync test wrapper)', () => {
  let store: NonceStore;
  beforeEach(() => {
    store = new NonceStore();
  });

  it('validates params for has/store/delete', () => {
    expect(() => store.has('', 'AA==')).toThrow(InvalidParameterError);
    expect(() => store.has('k', '')).toThrow(InvalidParameterError);
    expect(() => store.store('k', 'AA==', 0)).toThrow(InvalidParameterError);
    expect(() => store.store('k', 'AA==', 86400001)).toThrow(InvalidParameterError);
    expect(() => store.delete('', 'AA==')).toThrow(InvalidParameterError);
  });

  it('stores and has with ttl semantics', async () => {
    const kid = 'test-kid';
    // use a minimal valid base64 nonce
    const nonce = 'AA==';
    expect(store.has(kid, nonce)).toBe(false);
    store.store(kid, nonce, 50); // 50ms
    expect(store.has(kid, nonce)).toBe(true);
    // wait for expiry
    await new Promise((r) => setTimeout(r, 60));
    expect(store.has(kid, nonce)).toBe(false);
  });

  it('cleanup removes expired entries and size reports correctly', async () => {
    store.store('k1', 'AA==', 10);
    store.store('k2', 'AQ==', 1000);
    expect(store.size).toBe(2);
    // after some time first expires
    await new Promise((r) => setTimeout(r, 20));
    store.cleanup();
    expect(store.size).toBe(1);
  });
});

