// SPDX-License-Identifier: LGPL-3.0-or-later
// Placeholder integrity verification for Unicode binary data.
// Future enhancement: embed SHA-256 hashes or signatures generated at build time
// and perform constant-time comparison via secureCompareAsync (async variant will
// require refactoring loader to async path). For now we validate header + minimal
// structural sanity when requireUnicodeDataIntegrity is enabled.

import { SecurityValidationError, SecurityKitError } from "./errors.ts";
import { getUnicodeSecurityConfig } from "./config.ts";
import { normalizeInputString } from "./canonical.ts";

export type UnicodeDataKind = "identifier" | "confusables";

// Basic magic headers for current binary formats
const MAGIC_IDENTIFIER = 0x52_36_31_55; // 'U16R' little-endian when read as LE uint32
const MAGIC_CONFUSABLE = 0x43_36_31_55; // 'U16C'

function readUint32LE(bytes: Uint8Array, offset: number): number {
  if (offset + 3 >= bytes.length) {
    throw new SecurityValidationError(
      "Insufficient data for uint32 read",
      0,
      0,
      "structural",
      "Data truncation detected",
      "unicode-integrity",
    );
  }

  const byte0 = bytes[offset];
  const byte1 = bytes[offset + 1];
  const byte2 = bytes[offset + 2];
  const byte3 = bytes[offset + 3];

  return (
    ((byte0 !== undefined ? byte0 : 0) |
      ((byte1 !== undefined ? byte1 : 0) << 8) |
      ((byte2 !== undefined ? byte2 : 0) << 16) |
      ((byte3 !== undefined ? byte3 : 0) << 24)) >>>
    0
  );
}

async function computeDigest(
  algo: "SHA-256" | "SHA-384" | "SHA-512",
  data: Uint8Array,
): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    // Fallback (very rare – Node w/out WebCrypto) -> throw to force explicit environment support
    throw new SecurityKitError(
      "WebCrypto not available for Unicode data integrity verification",
    );
  }
  const digest = await crypto.subtle.digest(algo, data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function verifyUnicodeDataIntegrity(
  kind: UnicodeDataKind,
  profile: string,
  bytes: Uint8Array,
): void {
  const cfg = getUnicodeSecurityConfig();
  if (!cfg.requireUnicodeDataIntegrity) return; // allowed disabled only in non‑prod

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

  // Normalize inputs for security
  const normalizedKind = normalizeInputString(kind);
  const normalizedProfile = normalizeInputString(profile);

  // Header validation
  if (normalizedKind === "identifier") {
    validateIdentifierHeader(bytes, normalizedProfile);
  } else if (normalizedKind === "confusables") {
    validateConfusablesHeader(bytes, normalizedProfile);
  }

  // Structural sanity already validated above; a future enhancement will
  // compare against signed digests (current build emits hashes for reference).
}

function validateIdentifierHeader(bytes: Uint8Array, profile: string): void {
  if (bytes.length < 12) {
    throw new SecurityValidationError(
      `Identifier data too small for profile ${profile}`,
      0,
      0,
      "identifier",
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
      "identifier",
      "Magic header mismatch.",
      "unicode-integrity",
    );
  }
}

function validateConfusablesHeader(bytes: Uint8Array, profile: string): void {
  if (bytes.length < 32) {
    throw new SecurityValidationError(
      `Confusables data too small for profile ${profile}`,
      0,
      0,
      "confusables",
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
      "confusables",
      "Magic header mismatch.",
      "unicode-integrity",
    );
  }
}
