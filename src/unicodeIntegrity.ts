// SPDX-License-Identifier: LGPL-3.0-or-later
// Placeholder integrity verification for Unicode binary data.
// Future enhancement: embed SHA-256 hashes or signatures generated at build time
// and perform constant-time comparison via secureCompareAsync (async variant will
// require refactoring loader to async path). For now we validate header + minimal
// structural sanity when requireUnicodeDataIntegrity is enabled.

import { SecurityValidationError } from "./errors.ts";
import { getUnicodeSecurityConfig } from "./config.ts";
import { createHash } from 'node:crypto';
import { UNICODE_DATA_DIGESTS } from './generated/unicode-digests.ts';

// Basic magic headers for current binary formats
const MAGIC_IDENTIFIER = 0x52_36_31_55; // 'U16R' little-endian when read as LE uint32
const MAGIC_CONFUSABLE = 0x43_36_31_55; // 'U16C'

function readUint32LE(bytes: Uint8Array, offset: number): number {
  return (
    bytes[offset]! |
    (bytes[offset + 1]! << 8) |
    (bytes[offset + 2]! << 16) |
    (bytes[offset + 3]! << 24)
  ) >>> 0;
}

export type UnicodeDataKind = "identifier" | "confusables";

export function verifyUnicodeDataIntegrity(
  kind: UnicodeDataKind,
  profile: string,
  bytes: Uint8Array,
): void {
  const cfg = getUnicodeSecurityConfig();
  if (!cfg.requireUnicodeDataIntegrity) return; // skip in dev when disabled
  if (bytes.length === 0) {
    throw new SecurityValidationError(
      `Unicode ${kind} data empty for profile ${profile}`,
      0,
      0,
      kind,
      "Binary data unexpectedly empty.",
      "unicode-integrity",
    );
  }
  // Header validation
  if (kind === "identifier") {
    if (bytes.length < 12) {
      throw new SecurityValidationError(
        `Identifier data too small for profile ${profile}`,
        0,
        0,
        kind,
        "Truncated identifier header.",
        "unicode-integrity",
      );
    }
    const magic = readUint32LE(bytes, 0);
    if (magic !== MAGIC_IDENTIFIER) {
      throw new SecurityValidationError(
        `Identifier data magic mismatch for profile ${profile}`,
        0,
        0,
        kind,
        "Magic header mismatch.",
        "unicode-integrity",
      );
    }
  } else if (kind === "confusables") {
    if (bytes.length < 32) {
      throw new SecurityValidationError(
        `Confusables data too small for profile ${profile}`,
        0,
        0,
        kind,
        "Truncated confusables header.",
        "unicode-integrity",
      );
    }
    const magic = readUint32LE(bytes, 0);
    if (magic !== MAGIC_CONFUSABLE) {
      throw new SecurityValidationError(
        `Confusables data magic mismatch for profile ${profile}`,
        0,
        0,
        kind,
        "Magic header mismatch.",
        "unicode-integrity",
      );
    }
  }
  // Future: compute hash/signature verification here.
  const digestEntry = UNICODE_DATA_DIGESTS[profile]?.[kind];
  if (!digestEntry) {
    throw new SecurityValidationError(
      `Missing pinned digest for Unicode ${kind} (${profile}). Regenerate digests before publishing.`,
      0,
      0,
      kind,
      "Digest entry absent while integrity enforcement enabled.",
      "unicode-integrity",
    );
  } else {
    const algo = digestEntry.algo as 'SHA-256'|'SHA-384'|'SHA-512';
    const h = createHash(algo.replace('-','').toLowerCase());
    h.update(bytes);
    const computed = h.digest('hex');
    // Constant-time compare (lengths equal since same algo).
    let mismatch = 0;
    for (let i = 0; i < computed.length; i++) {
      mismatch |= computed.charCodeAt(i) ^ digestEntry.hash.charCodeAt(i);
    }
    if (mismatch !== 0) {
      throw new SecurityValidationError(
        `Unicode ${kind} data digest mismatch for profile ${profile}`,
        0,
        0,
        kind,
        "Digest verification failed.",
        "unicode-integrity",
      );
    }
  }
}
