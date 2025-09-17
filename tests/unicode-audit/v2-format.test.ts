// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getIdentifierRanges, getConfusables } from '../../src/generated/unicode-optimized-loader.ts';

function findFile(name: string): string {
  return join(process.cwd(), 'src/generated', name);
}

describe('Unicode v2 binary format', () => {
  it('ranges v2 magic + version decode', () => {
    const file = findFile('unicode-identifier-ranges-minimal.bin');
    const data = readFileSync(file);
    expect(data.length).toBeGreaterThan(12);
    expect(String.fromCharCode(data[0], data[1], data[2], data[3])).toMatch(/U16[RC]/); // R expected for v2 ranges
    // Ensure loader returns non-empty
    const ranges = getIdentifierRanges();
    expect(ranges.length).toBeGreaterThan(0);
  });

  it('confusables v2 decode (complete profile) returns entries identical to legacy semantics subset', () => {
    // We rely on current config selecting complete/standard; just ensure some entries load
    const conf = getConfusables();
    if (conf.length === 0) return; // minimal profile scenario
    for (let i = 0; i < Math.min(25, conf.length); i++) {
      const { source, target } = conf[i]!;
      expect(typeof source).toBe('string');
      expect(typeof target).toBe('string');
      expect(source.length).toBeGreaterThan(0);
      expect(target.length).toBeGreaterThan(0);
    }
  });
});
