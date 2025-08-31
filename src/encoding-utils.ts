// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
// Shared encoding and crypto helpers used by both main thread and worker.
/*
 * This file intentionally provides cross-runtime helpers (browser/Node). We avoid
 * importing Node types at runtime and instead use small, local type guards.
 * The filename contains an abbreviation by convention; disable the rule locally.
 */
/* eslint-disable unicorn/prevent-abbreviations */

import { CryptoUnavailableError, EncodingError } from "./errors";

const DEFAULT_CHUNK = 8192;

// Minimal Buffer constructor surface we rely on when running under Node.js
interface NodeBufferMinimal {
  readonly buffer: ArrayBuffer;
  readonly byteOffset: number;
  readonly byteLength: number;
  toString(encoding: string): string;
}
interface NodeBufferCtorLike {
  // bytes -> base64 string path
  from(input: Uint8Array): NodeBufferMinimal;
  // base64 string -> bytes path
  from(input: string, encoding: "base64"): NodeBufferMinimal;
}

function isNodeBufferCtorLike(x: unknown): x is NodeBufferCtorLike {
  try {
    // Accept function or object with a callable `from` method
    const maybe = x as { readonly from?: unknown } | null | undefined;
    return !!maybe && typeof maybe.from === "function";
  } catch {
    return false;
  }
}

function resolveNodeBuffer(): NodeBufferCtorLike | undefined {
  try {
    const g = globalThis as { readonly Buffer?: unknown };
    const B = g.Buffer;
    if (isNodeBufferCtorLike(B)) return B;
  } catch {
    // ignore
  }
  return undefined;
}

// Normalize base64url to standard base64 and fix padding
function normalizeBase64(input: string): string {
  const s = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (s.length % 4)) % 4;
  return s + "=".repeat(padLength);
}

export function bytesToBase64(
  bytes: Uint8Array,
  chunkSize = DEFAULT_CHUNK,
): string {
  // Prefer Node Buffer when available (fast and correct), otherwise use btoa
  try {
    const BufferCtor = resolveNodeBuffer();
    if (BufferCtor) return BufferCtor.from(bytes).toString("base64");
  } catch {
    // fallthrough to browser approach
  }

  if (typeof btoa === "function") {
    // eslint-disable-next-line functional/no-let -- Local binary string accumulator; scoped to function
    let binary = "";
    // eslint-disable-next-line functional/no-let -- Local loop index; scoped to function
    for (let index = 0; index < bytes.length; index += chunkSize) {
      const slice = bytes.subarray(index, index + chunkSize);
      for (const b of slice) binary += String.fromCharCode(b);
    }
    return btoa(binary);
  }

  throw new EncodingError("No base64 encoder available in this environment");
}

export function base64ToBytes(b64: string): Uint8Array {
  const normalized = normalizeBase64(b64.trim());
  try {
    if (typeof atob === "function") {
      const bin = atob(normalized);
      const length = bin.length;
      const out = new Uint8Array(length);
      // eslint-disable-next-line functional/no-let -- Local loop index; scoped to function
      for (let index = 0; index < length; index++)
        // Intentional in-place write into a fresh buffer for decoding
        // eslint-disable-next-line functional/immutable-data
        out[index] = bin.charCodeAt(index);
      return out;
    }
  } catch {
    // fallthrough
  }

  try {
    const BufferCtor = resolveNodeBuffer();
    if (BufferCtor) {
      const buf = BufferCtor.from(normalized, "base64");
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
  } catch {
    // fallthrough
  }

  throw new EncodingError("No base64 decoder available in this environment");
}

export function isLikelyBase64(s: string): boolean {
  // Accept base64 and base64url chars; allow unpadded base64url but ensure padding would make length % 4 === 0
  if (typeof s !== "string" || s.length === 0) return false;
  // Allow standard base64 and base64url characters (- and _). Optional padding '=' allowed.
  // Use an explicit character set to avoid ambiguity and unnecessary escapes.
  if (!/^[-\w+/]+={0,2}$/.test(s)) return false;
  const normalized = normalizeBase64(s);
  return normalized.length % 4 === 0 && normalized.length >= 4;
}

export function isLikelyBase64Url(s: string): boolean {
  // base64url allows A-Z a-z 0-9 - _ and optionally padding may be omitted.
  if (typeof s !== "string" || s.length === 0) return false;
  // base64url characters (dash and underscore allowed). Use \w for letters/digits/underscore and allow dash.
  if (!/^[-\w]+$/.test(s)) return false;
  // Padding may be omitted; normalize and ensure decoded length is plausible
  const normalized = normalizeBase64(s);
  return normalized.length % 4 === 0 && normalized.length >= 4;
}

async function getSubtle(): Promise<SubtleCrypto> {
  const maybe = (globalThis as { readonly crypto?: Crypto }).crypto;
  if (maybe && (maybe as { readonly subtle?: SubtleCrypto }).subtle) {
    return (maybe as { readonly subtle: SubtleCrypto }).subtle;
  }
  // Per instruction: ignore older Node fallback guidance. If subtle isn't available, throw.
  throw new CryptoUnavailableError(
    "SubtleCrypto not available in this environment",
  );
}

export async function sha256Base64(input: BufferSource): Promise<string> {
  const subtle = await getSubtle();
  const digest = await subtle.digest("SHA-256", input);
  return bytesToBase64(new Uint8Array(digest));
}

export function secureWipeWrapper(view: Uint8Array): void {
  try {
    // Best-effort overwrite
    // eslint-disable-next-line functional/no-let, functional/immutable-data -- Local loop index and intentional array modification for secure wipe; scoped to function
    for (let index = 0; index < view.length; index++) view[index] = 0;
  } catch {
    // ignore
  }
}

export function arrayBufferToBase64(buf: ArrayBuffer): string {
  return bytesToBase64(new Uint8Array(buf));
}
