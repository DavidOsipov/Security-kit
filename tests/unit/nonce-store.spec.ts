import { describe, it, expect } from 'vitest';
import { InMemoryNonceStore as NonceStore } from '../../server/verify-api-request-signature';
import { getSecureRandomBytesSync } from '../../src/crypto';

describe('NonceStore', () => {
  it('stores and expires nonces', async () => {
    const s = new NonceStore();
    const kid = 'unit-kid';
  // Use a valid 16-byte base64 nonce
  const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString('base64');
  await s.store(kid, nonce, 50); // 50ms TTL
    expect(await s.has(kid, nonce)).toBe(true);
    // wait for expiration
    await new Promise((r) => setTimeout(r, 120));
    expect(await s.has(kid, nonce)).toBe(false);
  });
});
