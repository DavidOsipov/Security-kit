// In a new file: src/api-signing.ts

import { generateSecureIdSync } from './crypto';
import { secureWipe, _arrayBufferToBase64 } from './utils';
import { ensureCrypto } from './state';
import { SHARED_ENCODER } from './encoding';
import { InvalidParameterError } from './errors';

/**
 * Creates a CryptoKey from a raw string secret for HMAC-SHA256.
 * @param secret The raw secret string.
 * @returns A non-extractable CryptoKey.
 */
export async function importHmacKey(secret: string): Promise<CryptoKey> {
  if (!secret || typeof secret !== 'string') {
    throw new InvalidParameterError('HMAC secret must be a non-empty string.');
  }
  const keyData = SHARED_ENCODER.encode(secret);
  try {
    const crypto = await ensureCrypto();
    return await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false, // non-extractable
      ['sign', 'verify']
    );
  } finally {
    secureWipe(keyData);
  }
}

/**
 * Generates an HMAC-SHA256 signature for an API request payload.
 * @param key The HMAC CryptoKey.
 * @param payload The JSON-serializable payload to sign.
 * @returns An object with the signature (base64) and nonce.
 */
export async function createApiRequestSignature(
  key: CryptoKey,
  payload: unknown,
): Promise<{ signature: string; nonce: string }> {
  const nonce = generateSecureIdSync(16);
  const timestamp = Date.now();
  
  // Create the canonical string to sign: nonce + timestamp + payload
  const serializedPayload = JSON.stringify(payload);
  const dataToSign = `${nonce}.${timestamp}.${serializedPayload}`;
  const encodedData = SHARED_ENCODER.encode(dataToSign);

  const crypto = await ensureCrypto();
  const signatureBuffer = await crypto.subtle.sign('HMAC', key, encodedData);
  
  return {
    signature: _arrayBufferToBase64(signatureBuffer),
    nonce,
    timestamp: timestamp.toString(), // Send timestamp to server
  };
}