import { describe, it, expect } from 'vitest';
import { verifyApiRequestSignature, InMemoryNonceStore } from '../../server/verify-api-request-signature';
import { createHmac, randomBytes } from 'crypto';
import { getSecureRandomBytesSync } from '../../src/crypto';

function signLikeWorker(key: Buffer, payload: unknown, nonce: string, timestamp: number, kid?: string) {
  const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload ?? '');
  // Use the shared, extended canonical format used by the server
  const canonicalParts = [String(timestamp), nonce, '', '', '', payloadStr, kid ?? ''];
  const canonical = canonicalParts.join('.');
  return createHmac('sha256', key).update(canonical).digest('base64');
}

describe('integration: sign -> verify (simulated worker)', () => {
  it('roundtrips a signed JSON payload with kid propagation', async () => {
  const key = Buffer.from(randomBytes(32));
    const payload = { hello: 'world' };
    const ts = Date.now();
  // Generate a 16-byte base64-encoded nonce as required by validation
  const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString('base64');
    const kid = 'integration-kid';
  const sig = signLikeWorker(key, payload, nonce, ts, kid);

    const nonceStore = new InMemoryNonceStore();
    const ok = await verifyApiRequestSignature({ secret: key, payload, nonce, timestamp: ts, signatureBase64: sig, kid }, nonceStore);
    expect(ok).toBe(true);
  });
});
