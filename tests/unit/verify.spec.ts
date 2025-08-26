import { describe, it, expect } from 'vitest';
import { verifyApiRequestSignature, InMemoryNonceStore } from '../../server/verify-api-request-signature';

import { SHARED_ENCODER } from '../../src/encoding';
import { safeStableStringify } from '../../src/canonical';
import { getSecureRandomBytesSync } from '../../src/crypto';

function base64FromBytes(bytes: Uint8Array) {
  if (typeof btoa === 'function') {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  return Buffer.from(bytes).toString('base64');
}

describe('verifyApiRequestSignature (unit)', () => {
  it('verifies a known signature (node fallback)', async () => {
    const secret = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // base64-ish
    const payload = { hello: 'world' };
  // Use a 16-byte (128-bit) base64-encoded nonce as required by validation
  const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString('base64');
    const timestamp = Date.now();

    // Construct canonical message and sign with Node crypto to simulate client
  const payloadStr = safeStableStringify(payload);
    const canonical = [String(timestamp), nonce, '', '', '', payloadStr, 'k1'].join('.');
    const msgBytes = SHARED_ENCODER.encode(canonical);
    // Node HMAC
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require('crypto');
  const key = Buffer.from(secret, 'base64');
  const h = crypto.createHmac('sha256', key);
  h.update(Buffer.from(msgBytes));
    const sig = Uint8Array.from(h.digest());
    const sigB64 = base64FromBytes(sig);

    const nonceStore = new InMemoryNonceStore();
    const ok = await verifyApiRequestSignature({ secret, payload, nonce, timestamp, signatureBase64: sigB64, kid: 'k1' } as any, nonceStore);
    expect(ok).toBe(true);
  });
});
