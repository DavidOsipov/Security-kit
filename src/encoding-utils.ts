// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
// Shared encoding and crypto helpers used by both main thread and worker.

const DEFAULT_CHUNK = 8192;

export function bytesToBase64(bytes: Uint8Array, chunkSize = DEFAULT_CHUNK): string {
  // Prefer Node Buffer when available (fast and correct), otherwise use btoa
  try {
    // @ts-ignore - Buffer may exist in Node
    const BufferCtor = (globalThis as any).Buffer;
    if (BufferCtor && typeof BufferCtor.from === 'function') {
      return BufferCtor.from(bytes).toString('base64');
    }
  } catch {
    // fallthrough to browser approach
  }

  if (typeof btoa === 'function') {
    let binary = '';
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const slice = bytes.subarray(i, i + chunkSize);
      for (let j = 0; j < slice.length; j++) binary += String.fromCharCode(slice[j]);
    }
    return btoa(binary);
  }

  throw new Error('No base64 encoder available in this environment');
}

export function base64ToBytes(b64: string): Uint8Array {
  try {
    if (typeof atob === 'function') {
      const bin = atob(b64);
      const len = bin.length;
      const out = new Uint8Array(len);
      for (let i = 0; i < len; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
  } catch {
    // fallthrough
  }

  try {
    // @ts-ignore
    const BufferCtor = (globalThis as any).Buffer;
    if (BufferCtor && typeof BufferCtor.from === 'function') {
      const buf = BufferCtor.from(b64, 'base64');
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
  } catch {
    // fallthrough
  }

  throw new Error('No base64 decoder available in this environment');
}

export function isLikelyBase64(s: string): boolean {
  return /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

async function getSubtle(): Promise<SubtleCrypto> {
  if (globalThis.crypto && (globalThis.crypto as any).subtle) {
    return (globalThis.crypto as any).subtle as SubtleCrypto;
  }
  // Per instruction: ignore older Node fallback guidance. If subtle isn't available, throw.
  throw new Error('SubtleCrypto not available in this environment');
}

export async function sha256Base64(input: BufferSource): Promise<string> {
  const subtle = await getSubtle();
  const digest = await subtle.digest('SHA-256', input as BufferSource);
  return bytesToBase64(new Uint8Array(digest));
}

export function secureWipeWrapper(view: Uint8Array): void {
  try {
    // Best-effort overwrite
    for (let i = 0; i < view.length; i++) view[i] = 0;
  } catch {
    // ignore
  }
}
