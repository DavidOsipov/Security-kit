// SPDX-License-Identifier: LGPL-3.0-or-later
// Placeholder integrity verification for Unicode binary data.
// Future enhancement: embed SHA-256 hashes or signatures generated at build time
// and perform constant-time comparison via secureCompareAsync (async variant will
// require refactoring loader to async path). For now we validate header + minimal
// structural sanity when requireUnicodeDataIntegrity is enabled.

import { SecurityValidationError } from "./errors.ts";
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
  return (
    ((bytes[offset] || 0) |
      ((bytes[offset + 1] || 0) << 8) |
      ((bytes[offset + 2] || 0) << 16) |
      ((bytes[offset + 3] || 0) << 24)) >>>
    0
  );
}

export async function verifyUnicodeDataIntegrity(
  kind: UnicodeDataKind,
  profile: string,
  bytes: Uint8Array,
): Promise<void> {
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

  // Normalize inputs for security
  const normalizedKind = normalizeInputString(kind);
  const normalizedProfile = normalizeInputString(profile);

  // Header validation
  if (normalizedKind === "identifier") {
    validateIdentifierHeader(bytes, normalizedProfile);
  } else if (normalizedKind === "confusables") {
    validateConfusablesHeader(bytes, normalizedProfile);
  }

  // For now, we only do basic structural validation
  // Future enhancement: implement full cryptographic digest verification
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
