import { describe, it, expect } from 'vitest';
import { verifyApiRequestSignature, InMemoryNonceStore } from '../../server/verify-api-request-signature';
import { SHARED_ENCODER } from '../../src/encoding';
import { safeStableStringify } from '../../src/canonical';
import { getSecureRandomBytesSync } from '../../src/crypto';

// We can't easily instantiate a browser Worker in Node test runner. Instead
// we'll import the worker logic as a module function (simulate) by calling
// the same crypto primitives to create a signature, then verify with server

describe('sign -> verify (integration)', () => {
  it('creates a signature and verifies it', async () => {
    const secretBytes = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
    const secretB64 = Buffer.from(secretBytes).toString('base64');
    const payload = { v: 1 };
  // Use a 16-byte (128-bit) base64-encoded nonce as required by validation
  const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString('base64');
    const timestamp = Date.now();
    const payloadStr = safeStableStringify(payload);
    // Build canonical using server's canonical format: timestamp, nonce, methodUpper, path, bodyHash, payloadString, kid
    const canonicalParts = [String(timestamp), nonce, '', '', '', payloadStr, 'integration-kid'];
    const msg = canonicalParts.join('.');
    const msgBytes = SHARED_ENCODER.encode(msg);

    // Node HMAC to simulate worker sign
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require('crypto');
    const h = crypto.createHmac('sha256', Buffer.from(secretBytes));
    h.update(Buffer.from(msgBytes));
    const sig = Uint8Array.from(h.digest());
    const sigB64 = Buffer.from(sig).toString('base64');

    const nonceStore = new InMemoryNonceStore();
    const ok = await verifyApiRequestSignature({ secret: secretB64, payload, nonce, timestamp, signatureBase64: sigB64, kid: 'integration-kid' } as any, nonceStore);
    expect(ok).toBe(true);
  });
});
