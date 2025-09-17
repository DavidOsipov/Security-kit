// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Advanced Unicode 16.0.0 data parser with multi-profile compression
 * 
 * Generates optimized binary data for different deployment scenarios:
 * - minimal: Frontend-optimized identifier validation (~4KB)
 * - standard: Backend default with compact confusables (~20KB)  
 * - complete: Full confusables mapping (~86KB)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

/**
 * Calculate BLAKE3 hash (fallback to SHA-256 if BLAKE3 unavailable)
 * SECURITY: Provides compile-time integrity verification for OWASP ASVS L3 compliance
 */
function calculateSecureHash(data: Uint8Array): string {
  // Use SHA-256 as it's universally available in Node.js and browsers
  // TODO: Add optional BLAKE3 when available as dependency
  const hash = createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
}

// Helper to summarize top-N index usage for decision guidance (placed early to avoid hoist issues)
function summarizeTop<T>(values: T[], sourceFreq: Uint32Array, targetFreq: Uint32Array, topN: number) {
  const combined: { value: T; s: number; t: number; total: number; index: number }[] = [];
  for (let i = 0; i < values.length; i++) {
    const s = sourceFreq[i]; const t = targetFreq[i]; const total = s + t;
    if (total > 0) combined.push({ value: values[i], s, t, total, index: i });
  }
  combined.sort((a,b)=>b.total - a.total);
  return combined.slice(0, topN);
}

interface IdentifierEntry {
  codePoint: number;
  status: 'Allowed' | 'Disallowed' | 'Restricted' | 'Obsolete';
}

interface ConfusableEntry {
  source: string;
  target: string;
  type?: 'ML' | 'SL' | 'SA' | 'MA';
}

interface RangeEntry {
  start: number;
  end: number;
  status: 'Allowed' | 'Disallowed' | 'Restricted' | 'Obsolete';
}

// -------------------- Varint helpers (LE base-128) --------------------
function encodeVarint(value: number, out: number[]): void {
  if (value < 0) throw new Error('varint negative');
  while (value > 0x7F) {
    out.push((value & 0x7F) | 0x80);
    value >>>= 7;
  }
  out.push(value & 0x7F);
}

// -------------------- Range delta encoding (v2) --------------------
function encodeRangesV2(ranges: RangeEntry[]): Uint8Array {
  // Header: 0-3 magic 'U16R', 4 version=2, 5 reserved, 6-7 reserved, 8-11 rangeCount
  const header = new Uint8Array(12);
  header[0] = 'U'.charCodeAt(0);
  header[1] = '1'.charCodeAt(0);
  header[2] = '6'.charCodeAt(0);
  header[3] = 'R'.charCodeAt(0); // R for Ranges
  header[4] = 2; // version 2
  // 5-7 zero
  const view = new DataView(header.buffer);
  view.setUint32(8, ranges.length, true);
  if (ranges.length === 0) return header;
  const bytes: number[] = Array.from(header);
  // First start absolute
  let prevStart = ranges[0]!.start;
  const tmp: number[] = [];
  tmp.length = 0;
  encodeVarint(prevStart, bytes);
  // First length
  encodeVarint(ranges[0]!.end - ranges[0]!.start, bytes);
  for (let i = 1; i < ranges.length; i++) {
    const r = ranges[i]!;
    const deltaStart = r.start - prevStart;
    prevStart = r.start;
    encodeVarint(deltaStart, bytes);
    encodeVarint(r.end - r.start, bytes);
  }
  return new Uint8Array(bytes);
}

// Efficient range compression for identifier status - OPTIMIZED VERSION
// Only store 'Allowed' ranges since Unicode 16.0.0 spec only defines these
// All other code points default to 'Restricted' per UTS #39
function compressRanges(entries: IdentifierEntry[]): RangeEntry[] {
  if (entries.length === 0) return [];
  
  // Filter to only 'Allowed' entries - all others default to 'Restricted'
  const allowedEntries = entries.filter(entry => entry.status === 'Allowed');
  
  if (allowedEntries.length === 0) return [];
  
  allowedEntries.sort((a, b) => a.codePoint - b.codePoint);
  const ranges: RangeEntry[] = [];
  let current = { start: allowedEntries[0].codePoint, end: allowedEntries[0].codePoint, status: 'Allowed' as const };
  
  for (let i = 1; i < allowedEntries.length; i++) {
    const entry = allowedEntries[i];
    
    // Extend current range if consecutive
    if (entry.codePoint === current.end + 1) {
      current.end = entry.codePoint;
    } else {
      ranges.push({ ...current });
      current = { start: entry.codePoint, end: entry.codePoint, status: 'Allowed' };
    }
  }
  
  ranges.push(current);
  return ranges;
}

// Optimized encoding for Allowed-only ranges (no status byte needed)
function encodeRangesLegacy(ranges: RangeEntry[]): Uint8Array {
  const buffer = new ArrayBuffer(ranges.length * 8);
  const view = new DataView(buffer);
  let offset = 0;
  for (const range of ranges) {
    view.setUint32(offset, range.start, true);
    view.setUint32(offset + 4, range.end, true);
    offset += 8;
  }
  return new Uint8Array(buffer);
}

// Advanced confusables compression with frequency analysis
function compressConfusables(entries: ConfusableEntry[], profile: 'minimal' | 'standard' | 'complete'): Uint8Array {
  if (profile === 'minimal') {
    // Skip confusables for minimal profile
    return new Uint8Array(0);
  }
  
  let filteredEntries = entries;
  
  if (profile === 'standard') {
    // OPTIMIZATION: More sophisticated filtering for standard profile
    // Focus on high-security-risk confusables that are commonly exploited
    const highRiskCategories = new Set([
      // Latin/Cyrillic confusables (common in domain spoofing)
      'а', 'е', 'о', 'р', 'с', 'у', 'х', 'А', 'В', 'С', 'Е', 'Н', 'К', 'М', 'О', 'Р', 'Т', 'Х',
      // Greek confusables (mathematical/scientific contexts)
      'α', 'β', 'γ', 'δ', 'ε', 'ζ', 'η', 'θ', 'ι', 'κ', 'λ', 'μ', 'ν', 'ξ', 'π', 'ρ', 'σ', 'τ', 'φ', 'χ', 'ψ', 'ω',
      // Common digit confusables (financial/numeric contexts)
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      // Punctuation that affects parsing/security
      '"', "'", '`', '-', '_', '.', ',', ';', ':', '!', '?'
    ]);
    
    filteredEntries = entries.filter(entry => {
      // Keep if either character is high-risk
      if (highRiskCategories.has(entry.source) || highRiskCategories.has(entry.target)) {
        return true;
      }
      
      // Keep single-character mappings (most security-relevant)
      if (entry.source.length === 1 && entry.target.length === 1) {
        // But filter out obviously non-malicious mappings like different types of spaces
        // (these are handled by normalization, not confusable detection)
        const sourceCode = entry.source.codePointAt(0)!;
        const targetCode = entry.target.codePointAt(0)!;
        
        // Skip mappings between different space characters
        const isSourceSpace = /\s/.test(entry.source);
        const isTargetSpace = /\s/.test(entry.target);
        if (isSourceSpace && isTargetSpace) return false;
        
        // Skip mappings between similar punctuation that aren't security-relevant
        const bothPunctuation = sourceCode >= 0x2000 && sourceCode <= 0x206F && 
                               targetCode >= 0x2000 && targetCode <= 0x206F;
        if (bothPunctuation) return false;
        
        return true;
      }
      
      // Keep multi-character sequences that could be security-relevant
      // (like ligatures that could be confused with individual characters)
      return entry.source.length <= 3 && entry.target.length <= 3;
    });
  }
  
  // Build separate tables: single (codepoints) and multi (front-coded)
  const singleSet = new Set<number>();
  const multiSet = new Set<string>();
  for (const e of filteredEntries) {
    if (e.source.length === 1) singleSet.add(e.source.codePointAt(0)!); else multiSet.add(e.source);
    if (e.target.length === 1) singleSet.add(e.target.codePointAt(0)!); else multiSet.add(e.target);
  }
  const single = Array.from(singleSet).sort((a,b)=>a-b); // uint32 list
  const multi = Array.from(multiSet).sort();
  // Front-coding multi
  const multiBytes: number[] = [];
  const encoder = new TextEncoder();
  let prev = '';
  for (const m of multi) {
    const prefixLen = (() => {
      let l = 0; const max = Math.min(m.length, prev.length, 255);
      while (l < max && m[l] === prev[l]) l++;
      return l;
    })();
    const remainder = m.slice(prefixLen);
    const remBytes = Array.from(encoder.encode(remainder));
    multiBytes.push(prefixLen); // 1 byte prefix length
    multiBytes.push(remBytes.length); // 1 byte remainder length (assume short sequences)
    multiBytes.push(...remBytes);
    prev = m;
  }
  const multiBlock = new Uint8Array(multiBytes);

  // Index maps
  const singleIndex = new Map<number, number>(single.map((cp,i)=>[cp,i]));
  const multiIndex = new Map<string, number>(multi.map((s,i)=>[s,i]));

  // --- Instrumentation data collection (for compression strategy tuning) ---
  const sourceFreqSingle = new Uint32Array(single.length);
  const targetFreqSingle = new Uint32Array(single.length);
  const sourceFreqMulti = new Uint32Array(multi.length);
  const targetFreqMulti = new Uint32Array(multi.length);
  // Track target reuse sets to understand fan-out convergence
  const targetReuseMap = new Map<string, number>();
  // Prefix overlap histogram for multi front-coding efficiency insight
  const prefixOverlapHistogram: number[] = new Array(16).fill(0); // bucket prefix lengths 0-14, 15+ aggregated

  // Pre-compute prefix overlap stats (multi already sorted)
  {
    let prevLocal = '';
    for (const m of multi) {
      let l = 0; const max = Math.min(m.length, prevLocal.length);
      while (l < max && m[l] === prevLocal[l]) l++;
      if (l >= 15) prefixOverlapHistogram[15]++; else prefixOverlapHistogram[l]++;
      prevLocal = m;
    }
  }

  // Defensive caps (OWASP ASVS L3 style resource constraints)
  const MAX_MAPPING_COUNT = 20000; // generous upper bound (> 7284 current complete)
  if (filteredEntries.length > MAX_MAPPING_COUNT) {
    throw new Error(`Confusables mapping count (${filteredEntries.length}) exceeds safety cap (${MAX_MAPPING_COUNT})`);
  }
  // Variable length mapping encoding: flags byte + indices (1 or 2 bytes each)
  const mappingBytes: number[] = [];
  for (const m of filteredEntries) {
    const sIsMulti = m.source.length !== 1;
    const tIsMulti = m.target.length !== 1;
    const sIndex = sIsMulti ? multiIndex.get(m.source)! : singleIndex.get(m.source.codePointAt(0)!)!;
    const tIndex = tIsMulti ? multiIndex.get(m.target)! : singleIndex.get(m.target.codePointAt(0)!)!;
    // Frequency stats
    if (sIsMulti) sourceFreqMulti[sIndex]++; else sourceFreqSingle[sIndex]++;
    if (tIsMulti) targetFreqMulti[tIndex]++; else targetFreqSingle[tIndex]++;
    const key = m.target; // reuse counting by exact target sequence
    targetReuseMap.set(key, (targetReuseMap.get(key) || 0) + 1);
    const sSmall = sIndex < 256;
    const tSmall = tIndex < 256;
    let flags = 0;
    if (sIsMulti) flags |= 0x01;
    if (tIsMulti) flags |= 0x02;
    if (sSmall) flags |= 0x04; // size bit: 1 byte if set else 2
    if (tSmall) flags |= 0x08;
    mappingBytes.push(flags);
    if (sSmall) mappingBytes.push(sIndex); else { mappingBytes.push(sIndex & 0xFF, (sIndex >>> 8) & 0xFF); }
    if (tSmall) mappingBytes.push(tIndex); else { mappingBytes.push(tIndex & 0xFF, (tIndex >>> 8) & 0xFF); }
  }
  const mappingsBlock = new Uint8Array(mappingBytes);

  // Attach lightweight stats for caller via symbol side-channel (avoids changing return type)
  (mappingsBlock as any).__stats = {
    singleCount: single.length,
    multiCount: multi.length,
    mappingCount: filteredEntries.length,
    profile,
    singleIndexUsage: summarizeTop(single, sourceFreqSingle, targetFreqSingle, 10),
    multiIndexUsage: summarizeTop(multi, sourceFreqMulti, targetFreqMulti, 10),
    targetReuseTop: Array.from(targetReuseMap.entries())
      .filter(([,c]) => c > 1)
      .sort((a,b)=>b[1]-a[1]).slice(0,10),
    prefixOverlapHistogram: prefixOverlapHistogram.map((c,i)=>({bucket: i===15? '15+': String(i), count: c}))
  } as const;

  // Header v2 (32 bytes total):
  // 0-3  magic 'U16C'
  // 4    version 2
  // 5    profile byte
  // 6-7  reserved
  // 8-11 singleCount
  // 12-15 multiCount
  // 16-19 multiBytesSize
  // 20-23 mappingsCount
  // 24-27 unused/reserved for future (0)
  // 28-31 unused/reserved (0)
  const HEADER_SIZE = 32;
  const profileByte = profile === 'standard' ? 1 : (profile === 'complete' ? 2 : 0);
  const totalSize = HEADER_SIZE + single.length * 4 + multiBlock.length + mappingsBlock.length;
  const out = new Uint8Array(totalSize);
  out[0] = 'U'.charCodeAt(0); out[1] = '1'.charCodeAt(0); out[2] = '6'.charCodeAt(0); out[3] = 'C'.charCodeAt(0);
  out[4] = 2; out[5] = profileByte; // version/profile
  const dv = new DataView(out.buffer);
  dv.setUint32(8, single.length, true);
  dv.setUint32(12, multi.length, true);
  dv.setUint32(16, multiBlock.length, true);
  dv.setUint32(20, filteredEntries.length, true);
  // copy single table
  let ptr = HEADER_SIZE;
  for (const cp of single) {
    dv.setUint32(ptr, cp, true); ptr += 4;
  }
  out.set(multiBlock, ptr); ptr += multiBlock.length;
  out.set(mappingsBlock, ptr);
  return out;
}

export function parseIdentifierStatus(filePath: string): IdentifierEntry[] {
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const entries: IdentifierEntry[] = [];
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    // Parse format like: "0027          ; Allowed    # 1.1        APOSTROPHE"
    // or: "002D..002E    ; Allowed    # 1.1    [2] HYPHEN-MINUS..FULL STOP"
    
    const parts = trimmed.split(/\s*;\s*/);
    if (parts.length < 2) continue;
    
    const codePointPart = parts[0].trim();
    const status = parts[1].split(/\s+/)[0] as IdentifierEntry['status'];
    
    if (!['Allowed', 'Disallowed', 'Restricted', 'Obsolete'].includes(status)) continue;
    
    // Handle ranges (e.g., "002D..002E")
    if (codePointPart.includes('..')) {
      const [start, end] = codePointPart.split('..').map(s => parseInt(s, 16));
      for (let cp = start; cp <= end; cp++) {
        entries.push({ codePoint: cp, status });
      }
    } else {
      const codePoint = parseInt(codePointPart, 16);
      if (!isNaN(codePoint)) {
        entries.push({ codePoint, status });
      }
    }
  }
  
  return entries;
}

export function parseConfusables(filePath: string): ConfusableEntry[] {
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const entries: ConfusableEntry[] = [];
  let currentCanonical: string | null = null;
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('#')) { // group header resets canonical
      currentCanonical = null;
      continue;
    }
    const parts = trimmed.split('\t').filter(p => p.trim().length > 0);
    if (parts.length < 3) continue;
    const hasArrow = parts[0] === '←';
    const charSlotIndex = hasArrow ? 1 : 0;
    const hexSlotIndex = hasArrow ? 2 : 1;
    const charMatch = parts[charSlotIndex]?.match(/\(‎\s*(.+?)\s*‎\)/);
    if (!charMatch) continue;
    const display = charMatch[1]?.trim();
    if (!display) continue;
    const hexPart = parts[hexSlotIndex]?.trim();
    if (!hexPart) continue;
    const hexCodes = hexPart.split(/\s+/).filter(h => /^[0-9A-F]{2,}$/i.test(h));
    if (!hexCodes.length) continue;
    try {
      const cps = hexCodes.map(h => parseInt(h, 16));
      const sequence = String.fromCodePoint(...cps);
      if (!hasArrow) {
        currentCanonical = sequence;
        continue;
      }
      if (!currentCanonical) continue;
      if (sequence === currentCanonical) continue; // identical (rare)
      // Drop pure bidi/control only sequences (all code points are controls)
      const controlOnly = /^[\u200E\u200F\u202A-\u202E\u2066-\u2069]+$/.test(sequence) || /^[\u200E\u200F\u202A-\u202E\u2066-\u2069]+$/.test(currentCanonical);
      if (controlOnly) continue;
      // Minimal pruning: if both single ASCII alphanum and differ only by case we skip (handled elsewhere)
      if (sequence.length === 1 && currentCanonical.length === 1) {
        const a = sequence.codePointAt(0)!;
        const b = currentCanonical.codePointAt(0)!;
        const isAsciiAlnum = (cp: number) => cp <= 0x7F && /[0-9A-Za-z]/.test(String.fromCharCode(cp));
        if (isAsciiAlnum(a) && isAsciiAlnum(b) && sequence.toLowerCase() === currentCanonical.toLowerCase()) {
          continue;
        }
      }
      entries.push({ source: sequence, target: currentCanonical });
    } catch { /* ignore malformed */ }
  }
  // Deduplicate
  const map = new Map<string, ConfusableEntry>();
  for (const e of entries) map.set(e.source + '\0' + e.target, e);
  return Array.from(map.values());
}

/**
 * Generate embedded TypeScript data with BLAKE3/SHA-256 integrity verification
 * SECURITY: Implements OWASP ASVS L3 integrity requirements for embedded data
 */
async function generateEmbeddedDataWithIntegrity(
  outputDir: string, 
  rangesDataV2: Uint8Array, 
  confusableEntries: ConfusableEntry[]
): Promise<void> {
  
  // Generate minimal confusables (empty for frontend performance)
  const minimalConfusables = generateMinimalConfusablesV2();
  
  // Calculate secure hashes
  const rangesHash = calculateSecureHash(rangesDataV2);
  const minimalConfusablesHash = calculateSecureHash(minimalConfusables);
  
  // Calculate hashes for external files (if they exist)
  const externalHashes: Record<string, string> = {};
  
  try {
    const standardRanges = readFileSync(join(outputDir, 'unicode-identifier-ranges-standard.bin'));
    externalHashes['unicode-identifier-ranges-standard.bin'] = calculateSecureHash(standardRanges);
  } catch { /* File may not exist yet */ }
  
  try {
    const completeRanges = readFileSync(join(outputDir, 'unicode-identifier-ranges-complete.bin'));  
    externalHashes['unicode-identifier-ranges-complete.bin'] = calculateSecureHash(completeRanges);
  } catch { /* File may not exist yet */ }
  
  try {
    const standardConfusables = readFileSync(join(outputDir, 'unicode-confusables-standard.bin'));
    externalHashes['unicode-confusables-standard.bin'] = calculateSecureHash(standardConfusables);
  } catch { /* File may not exist yet */ }
  
  try {
    const completeConfusables = readFileSync(join(outputDir, 'unicode-confusables-complete.bin'));
    externalHashes['unicode-confusables-complete.bin'] = calculateSecureHash(completeConfusables);
  } catch { /* File may not exist yet */ }
  
  // Generate TypeScript embedded data
  const embeddedDataTs = `/**
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * 
 * SECURITY NOTICE: This file contains embedded Unicode binary data.
 * Data integrity is verified via compile-time BLAKE3/SHA-256 checksums.
 * DO NOT MODIFY - Generated by scripts/parse-unicode-data-optimized.ts
 * 
 * HYBRID SECURITY ARCHITECTURE:
 * - Minimal profile (~845B): Embedded for zero-dependency frontend use
 * - Standard/Complete profiles: External files with integrity verification
 * 
 * Generated: ${new Date().toISOString()}
 * Unicode Version: 16.0.0
 */

import { SecurityKitError } from '../errors.ts';

// Compile-time integrity verification hashes (SHA-256)
const EMBEDDED_RANGES_HASH = "${rangesHash}";
const EMBEDDED_MINIMAL_CONFUSABLES_HASH = "${minimalConfusablesHash}"; 

// External file integrity hashes (for standard/complete profiles)
export const EXTERNAL_FILE_HASHES = {
  'unicode-identifier-ranges-standard.bin': "${externalHashes['unicode-identifier-ranges-standard.bin'] || 'PLACEHOLDER_STANDARD_RANGES_HASH'}",
  'unicode-identifier-ranges-complete.bin': "${externalHashes['unicode-identifier-ranges-complete.bin'] || 'PLACEHOLDER_COMPLETE_RANGES_HASH'}", 
  'unicode-confusables-standard.bin': "${externalHashes['unicode-confusables-standard.bin'] || 'PLACEHOLDER_STANDARD_CONFUSABLES_HASH'}",
  'unicode-confusables-complete.bin': "${externalHashes['unicode-confusables-complete.bin'] || 'PLACEHOLDER_COMPLETE_CONFUSABLES_HASH'}"
} as const;

// EMBEDDED DATA: Minimal profile only (OWASP ASVS L3 compliant)
export const EMBEDDED_IDENTIFIER_RANGES_MINIMAL = new Uint8Array([
${Array.from(rangesDataV2).map((byte, i) => 
    (i % 16 === 0 ? '\n  ' : '') + `0x${byte.toString(16).padStart(2, '0').toUpperCase()}`
  ).join(', ')}
]);

// Minimal confusables is empty (zero mappings for frontend performance)
export const EMBEDDED_CONFUSABLES_MINIMAL = new Uint8Array([
${Array.from(minimalConfusables).map((byte, i) => 
    (i % 16 === 0 ? '\n  ' : '') + `0x${byte.toString(16).padStart(2, '0').toUpperCase()}`
  ).join(', ')}
]);

/**
 * Verify embedded data integrity using Web Crypto API  
 * Implements OWASP ASVS V8.1.1 (Data Integrity)
 */
async function verifyEmbeddedIntegrity(): Promise<void> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    // Fallback for environments without Web Crypto API
    console.warn('Web Crypto API unavailable - skipping integrity verification');
    return;
  }

  try {
    // Verify identifier ranges
    const rangesHash = await crypto.subtle.digest('SHA-256', EMBEDDED_IDENTIFIER_RANGES_MINIMAL);
    const rangesHex = Array.from(new Uint8Array(rangesHash))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    
    if (rangesHex !== EMBEDDED_RANGES_HASH.toLowerCase()) {
      throw new SecurityKitError('Embedded identifier ranges integrity check failed - potential tampering detected');
    }

    // Verify minimal confusables  
    const confusablesHash = await crypto.subtle.digest('SHA-256', EMBEDDED_CONFUSABLES_MINIMAL);
    const confusablesHex = Array.from(new Uint8Array(confusablesHash))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    
    if (confusablesHex !== EMBEDDED_MINIMAL_CONFUSABLES_HASH.toLowerCase()) {
      throw new SecurityKitError('Embedded minimal confusables integrity check failed - potential tampering detected');
    }

  } catch (error) {
    if (error instanceof SecurityKitError) {
      throw error;
    }
    // Don't fail hard if integrity check has issues - degrade gracefully
    console.warn('Embedded data integrity verification failed:', error);
  }
}

/**
 * Verify external binary file integrity
 * Implements OWASP ASVS V8.1.1 (Data Integrity) 
 */
export async function verifyExternalFileIntegrity(
  data: Uint8Array, 
  filename: keyof typeof EXTERNAL_FILE_HASHES
): Promise<void> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    console.warn('Web Crypto API unavailable - skipping external file integrity verification');
    return;
  }

  const expectedHash = EXTERNAL_FILE_HASHES[filename];
  if (!expectedHash || expectedHash.startsWith('PLACEHOLDER')) {
    console.warn(\`No integrity hash available for \${filename} - verification skipped\`);
    return;
  }

  try {
    const actualHash = await crypto.subtle.digest('SHA-256', data);
    const actualHex = Array.from(new Uint8Array(actualHash))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    
    if (actualHex !== expectedHash.toLowerCase()) {
      throw new SecurityKitError(\`External file \${filename} integrity check failed - potential tampering detected\`);
    }
  } catch (error) {
    if (error instanceof SecurityKitError) {
      throw error;
    }
    console.warn(\`External file \${filename} integrity verification failed:\`, error);
  }
}

// Verify embedded data integrity at module load time
// This runs automatically when the module is imported
let _integrityVerified = false;
export const verifyOnLoad = (async (): Promise<void> => {
  if (_integrityVerified) return;
  await verifyEmbeddedIntegrity();
  _integrityVerified = true;
})();

/**
 * Get embedded data for minimal profile with integrity verification
 */
export async function getEmbeddedData(): Promise<{
  readonly ranges: Uint8Array;
  readonly confusables: Uint8Array;
}> {
  // Ensure integrity verification completed
  await verifyOnLoad;
  
  return Object.freeze({
    ranges: EMBEDDED_IDENTIFIER_RANGES_MINIMAL,
    confusables: EMBEDDED_CONFUSABLES_MINIMAL
  });
}
`;

  writeFileSync(join(outputDir, 'unicode-embedded-data.ts'), embeddedDataTs);
  
  console.log('🔒 Generated embedded data with SHA-256 integrity verification');
  console.log(`   📱 Embedded minimal ranges: ${rangesDataV2.length} bytes (${rangesHash.slice(0, 16)}...)`);
  console.log(`   📱 Embedded minimal confusables: ${minimalConfusables.length} bytes (${minimalConfusablesHash.slice(0, 16)}...)`);
}

/**
 * Generate minimal confusables V2 format (empty for frontend performance)
 */
function generateMinimalConfusablesV2(): Uint8Array {
  const header = new Uint8Array(32);
  const view = new DataView(header.buffer);
  
  // Magic: U16C
  header[0] = 0x55; header[1] = 0x31; header[2] = 0x36; header[3] = 0x43;
  // Version: 2, Profile: 0 (minimal)
  header[4] = 2; header[5] = 0;
  // Reserved
  header[6] = 0; header[7] = 0;
  // All counts are zero
  view.setUint32(8, 0, true);  // Single Count
  view.setUint32(12, 0, true); // Multi Count  
  view.setUint32(16, 0, true); // Multi Bytes Size
  view.setUint32(20, 0, true); // Mapping Count
  // Reserved future fields (already zeroed)
  
  return header;
}

async function generateOptimizedUnicodeData() {
  const verboseStats = process.argv.includes('--stats');
  const projectRoot = process.cwd();
  const unicodeDir = join(projectRoot, 'docs/Additional security guidelines/Specifications and RFC/Unicode 16.0.0');
  const outputDir = join(projectRoot, 'src/generated');
  
  console.log('🔍 Parsing Unicode 16.0.0 data...');
  
  const identifierEntries = parseIdentifierStatus(join(unicodeDir, 'IdentifierStatus.txt'));
  const confusableEntries = parseConfusables(join(unicodeDir, 'confusablesSummary.txt'));
  
  console.log(`📊 Parsed ${identifierEntries.length} identifier entries, ${confusableEntries.length} confusable mappings`);
  
  // Compress ranges for all profiles
  const ranges = compressRanges(identifierEntries);
  const rangesDataLegacy = encodeRangesLegacy(ranges);
  const rangesDataV2 = encodeRangesV2(ranges);
  
  console.log(`🗜️ Compressed identifier ranges: ${identifierEntries.length} entries → ${ranges.length} ranges (v2 ${rangesDataV2.length} bytes, legacy ${rangesDataLegacy.length} bytes)`);
  
  // Generate different profiles
  const profiles = ['minimal', 'standard', 'complete'] as const;
  
  function logStats(tag: string, stats: any) {
    if (!stats || !verboseStats) return;
    console.log(`   • ${tag} stats:`);
    const fmtEntry = (e: any) => {
      const value = typeof e.value === 'number' ? `U+${e.value.toString(16).toUpperCase()}` : JSON.stringify(e.value);
      return `${value}{s:${e.s},t:${e.t},Σ:${e.total},i:${e.index}}`;
    };
    if (stats.singleIndexUsage.length) {
      console.log('     Top single indices:', stats.singleIndexUsage.map(fmtEntry).join(' '));
    }
    if (stats.multiIndexUsage.length) {
      console.log('     Top multi indices:', stats.multiIndexUsage.map(fmtEntry).join(' '));
    }
    if (stats.targetReuseTop.length) {
      console.log('     Target reuse:', stats.targetReuseTop.map(([t,c]: [string,number]) => `${JSON.stringify(t)}×${c}`).join(' '));
    } else {
      console.log('     Target reuse: (no duplicates above threshold)');
    }
    console.log('     Prefix overlap histogram:', stats.prefixOverlapHistogram.map((b: any)=>`${b.bucket}:${b.count}`).join(' '));
  }

  for (const profile of profiles) {
    const confusablesData = compressConfusables(confusableEntries, profile);
    
    console.log(`📦 ${profile} profile confusables: ${confusablesData.length} bytes (includes versioned header if >0)`);
    const stats = (confusablesData as any).__stats;
  if (stats) logStats(profile, stats);
    
    // Write profile-specific files
    // Write v2 primary file
    writeFileSync(
      join(outputDir, `unicode-identifier-ranges-${profile}.bin`),
      rangesDataV2
    );
    // Also keep legacy for fallback debugging (optional)
    writeFileSync(
      join(outputDir, `unicode-identifier-ranges-legacy-${profile}.bin`),
      rangesDataLegacy
    );
    
    if (confusablesData.length > 0) {
      writeFileSync(
        join(outputDir, `unicode-confusables-${profile}.bin`),
        confusablesData
      );
    }
  }
  
  // Generate a unified loader with profile selection
  const loaderCode = `// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Optimized Unicode 16.0.0 binary data loader with profile selection
 * Generated by parse-unicode-data-optimized.ts
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getUnicodeSecurityConfig } from '../config.ts';

export type UnicodeProfile = 'minimal' | 'standard' | 'complete';
export type IdentifierStatus = 'Allowed' | 'Disallowed' | 'Restricted' | 'Obsolete';

export interface UnicodeRangeEntry {
  readonly start: number;
  readonly end: number;
  readonly status: IdentifierStatus;
}


export interface UnicodeConfusableEntry {
  readonly source: string;
  readonly target: string;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _STATUS_NAMES: readonly IdentifierStatus[] = ['Allowed', 'Disallowed', 'Restricted', 'Obsolete'] as const;

// In-memory cache for loaded data
const dataCache = new Map<string, UnicodeRangeEntry[] | UnicodeConfusableEntry[]>();

function getDataPath(filename: string): string {
  if (typeof __dirname !== 'undefined') {
    // Node.js environment
    return join(__dirname, filename);
  } else {
    // Browser/Deno - would need bundler support
    throw new Error('Binary Unicode data loading not supported in this environment');
  }
}

function loadIdentifierRanges(profile: UnicodeProfile): UnicodeRangeEntry[] {
  const cacheKey = \`identifier-ranges-\${profile}\`;
  if (dataCache.has(cacheKey)) return dataCache.get(cacheKey) as UnicodeRangeEntry[];
  try {
    const data = readFileSync(getDataPath(\`unicode-identifier-ranges-\${profile}.bin\`));
    if (data.length === 0) return [];
    const isV2 = data.length >= 12 && data[0] === 0x55 && data[1] === 0x31 && data[2] === 0x36 && data[3] === 0x52; // 'U16R'
    const ranges: UnicodeRangeEntry[] = [];
    if (!isV2) {
      for (let offset = 0; offset + 8 <= data.length; offset += 8) {
        const start = data.readUInt32LE(offset);
        const end = data.readUInt32LE(offset + 4);
        ranges.push({ start, end, status: 'Allowed' });
      }
    } else {
      const version = data[4];
      if (version !== 2) throw new Error(\`Unsupported identifier ranges version \${version}\`);
      const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const count = dv.getUint32(8, true);
      let offset = 12;
      const readVarint = () => {
        let shift = 0; let result = 0; for (let i = 0; i < 5; i++) { if (offset >= data.length) throw new Error('Truncated varint'); const b = data[offset++]; result |= (b & 0x7F) << shift; if ((b & 0x80) === 0) return result; shift += 7; } throw new Error('Varint too long'); };
      if (count > 10000) throw new Error('Range count sanity exceeded');
      if (count > 0) {
        let start = readVarint();
        let length = readVarint();
        let end = start + length;
        ranges.push({ start, end, status: 'Allowed' });
        for (let i = 1; i < count; i++) {
          const deltaStart = readVarint();
          start = start + deltaStart;
          length = readVarint();
            end = start + length;
            ranges.push({ start, end, status: 'Allowed' });
        }
      }
    }
    dataCache.set(cacheKey, ranges);
    return ranges;
  } catch (error) {
    console.warn(\`Failed to load Unicode identifier ranges for profile \${profile}:\`, error);
    return [];
  }
}

function loadConfusables(profile: UnicodeProfile): UnicodeConfusableEntry[] {
  if (profile === 'minimal') return [];
  const cacheKey = \`confusables-\${profile}\`;
  if (dataCache.has(cacheKey)) return dataCache.get(cacheKey) as UnicodeConfusableEntry[];
  try {
    const data = readFileSync(getDataPath(\`unicode-confusables-\${profile}.bin\`));
    if (data.length === 0) { dataCache.set(cacheKey, []); return []; }
    // v2 magic 'U16C' + version 2 (header >=32 bytes)
    const isV2 = data.length >= 32 && data[0] === 0x55 && data[1] === 0x31 && data[2] === 0x36 && data[3] === 0x43 && data[4] === 2;
    let mappings: UnicodeConfusableEntry[] = [];
    if (!isV2) {
      // legacy v1
      if (data.length < 8) throw new Error('Confusables legacy file too small');
      const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const stringTableSize = dv.getUint32(0, true);
      const mappingsCount = dv.getUint32(4, true);
      if (8 + stringTableSize + mappingsCount * 4 > data.length) throw new Error('Legacy confusables truncated');
      const tableBytes = data.subarray(8, 8 + stringTableSize);
      const table = new TextDecoder().decode(tableBytes).split('\\0').filter(Boolean);
      let offset = 8 + stringTableSize;
      mappings = new Array(mappingsCount);
      for (let i = 0; i < mappingsCount; i++) {
        const s = dv.getUint16(offset, true);
        const t = dv.getUint16(offset + 2, true);
        offset += 4;
        mappings[i] = { source: table[s]!, target: table[t]! };
      }
    } else {
      const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const singleCount = dv.getUint32(8, true);
      const multiCount = dv.getUint32(12, true);
      const multiBytesSize = dv.getUint32(16, true);
      const mappingCount = dv.getUint32(20, true);
      let offset = 32;
      const single: string[] = new Array(singleCount);
      for (let i = 0; i < singleCount; i++) { const cp = dv.getUint32(offset, true); offset += 4; single[i] = String.fromCodePoint(cp); }
      const multiBlock = data.subarray(offset, offset + multiBytesSize); offset += multiBytesSize;
      const multi: string[] = new Array(multiCount);
      let prev = ''; let mOff = 0; const decoder = new TextDecoder();
      for (let i = 0; i < multiCount; i++) {
        const prefix = multiBlock[mOff++];
        const remLen = multiBlock[mOff++];
        const remBytes = multiBlock.subarray(mOff, mOff + remLen); mOff += remLen;
        const rem = decoder.decode(remBytes);
        const full = prev.slice(0, prefix) + rem;
        multi[i] = full; prev = full;
      }
      mappings = new Array(mappingCount);
      let idx = 0;
      while (idx < mappingCount) {
        const flags = data[offset++];
        const sIsMulti = (flags & 0x01) !== 0; const tIsMulti = (flags & 0x02) !== 0;
        const sSmall = (flags & 0x04) !== 0; const tSmall = (flags & 0x08) !== 0;
        let sIdx: number; let tIdx: number;
        if (sSmall) { sIdx = data[offset++]; } else { sIdx = data[offset] | (data[offset+1] << 8); offset += 2; }
        if (tSmall) { tIdx = data[offset++]; } else { tIdx = data[offset] | (data[offset+1] << 8); offset += 2; }
        const source = sIsMulti ? multi[sIdx] : single[sIdx];
        const target = tIsMulti ? multi[tIdx] : single[tIdx];
        if (!source || !target) throw new Error('Confusables mapping index out of bounds');
        mappings[idx++] = { source, target };
      }
    }
    dataCache.set(cacheKey, mappings);
    return mappings;
  } catch (error) {
    console.warn(\`Failed to load Unicode confusables for profile \${profile}:\`, error);
    return [];
  }
}

/**
 * Get Unicode identifier validation ranges for the configured profile
 */
export function getIdentifierRanges(): UnicodeRangeEntry[] {
  const config = getUnicodeSecurityConfig();
  return loadIdentifierRanges(config.dataProfile);
}

/**
 * Get Unicode confusables mappings for the configured profile  
 */
export function getConfusables(): UnicodeConfusableEntry[] {
  const config = getUnicodeSecurityConfig();
  return loadConfusables(config.dataProfile);
}

/**
 * Check if a code point has a specific identifier status
 */
export function getIdentifierStatus(codePoint: number): IdentifierStatus | undefined {
  const ranges = getIdentifierRanges();
  
  for (const range of ranges) {
    if (codePoint >= range.start && codePoint <= range.end) {
      return range.status;
    }
  }
  
  return undefined;
}

/**
 * Find confusable targets for a given character
 */
function normalizeInputChar(c: string): string { return c ? c.normalize('NFC') : ''; }
export function getConfusableTargets(char: string): readonly string[] {
  const norm = normalizeInputChar(char);
  const confusables = getConfusables();
  return confusables.filter(e => e.source === norm).map(e => e.target);
}

/**
 * Check if a character is confusable with another
 */
export function isConfusable(char1: string, char2: string): boolean {
  const a = normalizeInputChar(char1); const b = normalizeInputChar(char2); if (!a || !b) return false;
  const confusables = getConfusables();
  return confusables.some(entry => (entry.source === a && entry.target === b) || (entry.source === b && entry.target === a));
}

/**
 * Get data size statistics for the current profile
 */
export interface UnicodeDataStats { readonly ranges: number; readonly confusables: number; readonly totalBytes: number; }
export function getDataStats(): UnicodeDataStats {
  const ranges = getIdentifierRanges();
  const confusables = getConfusables();
  const rangeBytes = ranges.length * 12;
  const confusableBytes = confusables.reduce((sum, e) => sum + e.source.length * 2 + e.target.length * 2, 0);
  return Object.freeze({ ranges: ranges.length, confusables: confusables.length, totalBytes: rangeBytes + confusableBytes });
}
`;
  
  writeFileSync(join(outputDir, 'unicode-optimized-loader.ts'), loaderCode);
  
  // SECURITY ENHANCEMENT: Generate embedded data with BLAKE3/SHA-256 integrity verification
  await generateEmbeddedDataWithIntegrity(outputDir, rangesDataV2, confusableEntries);
  
  console.log('✅ Generated optimized Unicode data loader');
  console.log('\nProfile sizes:');
  console.log(`  📱 minimal v2 ranges: ~${rangesDataV2.length} bytes (delta encoded)`);
  console.log(`  🖥️ standard total (approx): ~${rangesDataV2.length + compressConfusables(confusableEntries, 'standard').length} bytes`);
  console.log(`  🔬 complete total (approx): ~${rangesDataV2.length + compressConfusables(confusableEntries, 'complete').length} bytes`);
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  generateOptimizedUnicodeData().catch(console.error);
}