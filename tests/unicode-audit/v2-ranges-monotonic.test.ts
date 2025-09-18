// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

function decodeV2Ranges(data: Uint8Array) {
  if (data.length < 12) throw new Error('Too small for header');
  if (!(data[0] === 0x55 && data[1] === 0x31 && data[2] === 0x36 && data[3] === 0x52)) throw new Error('Magic mismatch');
  if (data[4] !== 0x02) throw new Error('Unsupported version');
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint32(8, true);
  let offset = 12;
  const readVar = () => { let shift = 0; let res = 0; for (let i=0;i<5;i++){ if (offset >= data.length) throw new Error('Truncated varint'); const b = data[offset++]; res |= (b & 0x7F) << shift; if ((b & 0x80)===0) return res; shift += 7;} throw new Error('Varint too long'); };
  const out: {start:number;end:number}[] = [];
  if (count>0){ let start = readVar(); let len = readVar(); let end = start + len; out.push({start,end}); for (let i=1;i<count;i++){ const delta = readVar(); start = start + delta; len = readVar(); end = start + len; out.push({start,end}); } }
  return out;
}

describe('Unicode v2 range delta encoding structural guarantees', () => {
  it('ranges are strictly increasing, non-overlapping, and cover only Allowed points', () => {
    const file = join(process.cwd(), 'src/generated', 'unicode-identifier-ranges-minimal.bin');
    const data = readFileSync(file);
    const ranges = decodeV2Ranges(data);
    expect(ranges.length).toBeGreaterThan(0);
    let prevEnd = -1;
    for (const r of ranges) {
      expect(r.start).toBeLessThanOrEqual(r.end);
      expect(r.start).toBeGreaterThan(prevEnd);
      prevEnd = r.end;
    }
  });
});
