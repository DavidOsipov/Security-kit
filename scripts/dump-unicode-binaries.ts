// SPDX-License-Identifier: LGPL-3.0-or-later
// Dumps the full decoded Unicode identifier ranges and confusables for all profiles
// into JSON files for manual auditing.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

type UnicodeProfile = 'minimal' | 'standard' | 'complete';

interface RangeEntry { start: number; end: number; status: 'Allowed'; }
interface ConfusableEntry { source: string; target: string; }

function loadIdentifierRanges(baseDir: string, profile: UnicodeProfile): RangeEntry[] {
  const file = join(baseDir, `unicode-identifier-ranges-${profile}.bin`);
  const data = readFileSync(file);
  if (data.length === 0) return [];
  const isV2 = data.length >= 12 && data[0] === 0x55 && data[1] === 0x31 && data[2] === 0x36 && data[3] === 0x52; // U16R
  const ranges: RangeEntry[] = [];
  if (!isV2) {
    if (data.length % 8 !== 0) throw new Error(`Identifier range file corrupt: ${file}`);
    for (let o = 0; o < data.length; o += 8) {
      const start = data.readUInt32LE(o);
      const end = data.readUInt32LE(o + 4);
      if (start > end || end > 0x10FFFF) throw new Error(`Invalid range ${start}-${end}`);
      ranges.push({ start, end, status: 'Allowed' });
    }
    return ranges;
  }
  const version = data[4];
  if (version !== 2) throw new Error(`Unsupported ranges version ${version}`);
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint32(8, true);
  let offset = 12;
  const readVarint = () => {
    let shift = 0; let result = 0; for (let i = 0; i < 5; i++) { if (offset >= data.length) throw new Error('Truncated varint'); const b = data[offset++]; result |= (b & 0x7F) << shift; if ((b & 0x80) === 0) return result; shift += 7; } throw new Error('Varint too long'); };
  if (count === 0) return [];
  let start = readVarint();
  let length = readVarint();
  let end = start + length;
  ranges.push({ start, end, status: 'Allowed' });
  for (let i = 1; i < count; i++) {
    const delta = readVarint();
    start = start + delta;
    length = readVarint();
    end = start + length;
    ranges.push({ start, end, status: 'Allowed' });
  }
  return ranges;
}

function loadConfusables(baseDir: string, profile: UnicodeProfile): ConfusableEntry[] {
  const file = join(baseDir, `unicode-confusables-${profile}.bin`);
  try {
    const data = readFileSync(file);
    if (data.length === 0) return [];
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const magicV2 = data.length >= 32 && data[0] === 0x55 && data[1] === 0x31 && data[2] === 0x36 && data[3] === 0x43 && data[4] === 2;
    if (!magicV2) {
      // Fallback v1 logic
      let offset = 0;
      let stringTableSize: number; let mappingsCount: number;
      if (data.length < 8) throw new Error('Confusables legacy file too small');
      stringTableSize = dv.getUint32(0, true);
      mappingsCount = dv.getUint32(4, true);
      offset = 8;
      if (offset + stringTableSize + mappingsCount * 4 > data.length) throw new Error('Legacy confusables truncated');
      const tableBytes = data.subarray(offset, offset + stringTableSize);
      const table = new TextDecoder().decode(tableBytes).split('\0').filter(Boolean);
      offset += stringTableSize;
      const out: ConfusableEntry[] = [];
      for (let i = 0; i < mappingsCount; i++) {
        const sIdx = dv.getUint16(offset, true); const tIdx = dv.getUint16(offset + 2, true); offset += 4;
        if (sIdx >= table.length || tIdx >= table.length) throw new Error('Index OOB');
        out.push({ source: table[sIdx]!, target: table[tIdx]! });
      }
      return out;
    }
    // v2 decode
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
      const prefix = multiBlock[mOff++]; const remLen = multiBlock[mOff++];
      const remBytes = multiBlock.subarray(mOff, mOff + remLen); mOff += remLen;
      const rem = decoder.decode(remBytes);
      const s = prev.slice(0, prefix) + rem; multi[i] = s; prev = s;
    }
    const out: ConfusableEntry[] = new Array(mappingCount);
    let idx = 0;
    while (idx < mappingCount) {
      const flags = data[offset++];
      const sIsMulti = (flags & 0x01) !== 0; const tIsMulti = (flags & 0x02) !== 0;
      const sSmall = (flags & 0x04) !== 0; const tSmall = (flags & 0x08) !== 0;
      let sIndex: number; let tIndex: number;
      if (sSmall) { sIndex = data[offset++]; } else { sIndex = data[offset] | (data[offset+1] << 8); offset += 2; }
      if (tSmall) { tIndex = data[offset++]; } else { tIndex = data[offset] | (data[offset+1] << 8); offset += 2; }
      const source = sIsMulti ? multi[sIndex] : single[sIndex];
      const target = tIsMulti ? multi[tIndex] : single[tIndex];
      if (!source || !target) throw new Error('Confusable index OOB');
      out[idx++] = { source, target };
    }
    return out;
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw e;
  }
}

function dumpAll() {
  const baseDir = join(process.cwd(), 'src/generated');
  const outDir = join(process.cwd(), 'tests/unicode-audit/dump-full');
  mkdirSync(outDir, { recursive: true });
  const profiles: UnicodeProfile[] = ['minimal', 'standard', 'complete'];
  for (const p of profiles) {
    const ranges = loadIdentifierRanges(baseDir, p);
    const confusables = loadConfusables(baseDir, p);
    const payload = {
      profile: p,
      stats: {
        identifierRangeCount: ranges.length,
        totalAllowedCodePoints: ranges.reduce((sum, r) => sum + (r.end - r.start + 1), 0),
        confusableCount: confusables.length
      },
      identifierRanges: ranges,
      confusables
    };
    writeFileSync(join(outDir, `${p}.json`), JSON.stringify(payload, null, 2));
    console.log(`Wrote ${p} dump: ranges=${ranges.length} confusables=${confusables.length}`);
  }
  console.log(`✅ Full dumps written to: ${outDir}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  dumpAll();
}

export { dumpAll };
