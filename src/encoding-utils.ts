// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
// Shared encoding and crypto helpers used by both main thread and worker.

const DEFAULT_CHUNK = 8192;

export function bytesToBase64(
  bytes: Uint8Array,
  chunkSize = DEFAULT_CHUNK,
): string {
  // Prefer Node Buffer when available (fast and correct), otherwise use btoa
  try {
    // @ts-ignore - Buffer may exist in Node
    const BufferCtor = (globalThis as any).Buffer;
    if (BufferCtor && typeof BufferCtor.from === "function") {
      return BufferCtor.from(bytes).toString("base64");
    }
  } catch {
    // fallthrough to browser approach
  }

  if (typeof btoa === "function") {
    let binary = "";
    for (let index = 0; index < bytes.length; index += chunkSize) {
      const slice = bytes.subarray(index, index + chunkSize);
      for (let index_ = 0; index_ < slice.length; index_++)
        binary += String.fromCharCode(slice[index_] as number);
    }
    return btoa(binary);
  }

  throw new Error("No base64 encoder available in this environment");
}

export function base64ToBytes(b64: string): Uint8Array {
  try {
    if (typeof atob === "function") {
      const bin = atob(b64);
      const length = bin.length;
      const out = new Uint8Array(length);
      for (let index = 0; index < length; index++)
        out[index] = bin.charCodeAt(index);
      return out;
    }
  } catch {
    // fallthrough
  }

  try {
    // @ts-ignore
    const BufferCtor = (globalThis as any).Buffer;
    if (BufferCtor && typeof BufferCtor.from === "function") {
      const buf = BufferCtor.from(b64, "base64");
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
  } catch {
    // fallthrough
  }

  throw new Error("No base64 decoder available in this environment");
}

export function isLikelyBase64(s: string): boolean {
  return /^[A-Z0-9+/]+={0,2}$/i.test(s);
}

async function getSubtle(): Promise<SubtleCrypto> {
  if (globalThis.crypto && (globalThis.crypto as any).subtle) {
    return (globalThis.crypto as any).subtle as SubtleCrypto;
  }
  // Per instruction: ignore older Node fallback guidance. If subtle isn't available, throw.
  throw new Error("SubtleCrypto not available in this environment");
}

export async function sha256Base64(input: BufferSource): Promise<string> {
  const subtle = await getSubtle();
  const digest = await subtle.digest("SHA-256", input as BufferSource);
  return bytesToBase64(new Uint8Array(digest));
}

export function secureWipeWrapper(view: Uint8Array): void {
  try {
    // Best-effort overwrite
    for (let index = 0; index < view.length; index++) view[index] = 0;
  } catch {
    // ignore
  }
}
