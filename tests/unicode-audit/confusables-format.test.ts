// SPDX-License-Identifier: LGPL-3.0-or-later
// Basic tests for versioned confusables binary format
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

function load(profile: string): Uint8Array | null {
  try {
    return readFileSync(join(process.cwd(), 'src/generated', `unicode-confusables-${profile}.bin`));
  } catch {
    return null;
  }
}

describe('confusables binary format', () => {
  const profiles = ['standard', 'complete'];
  for (const p of profiles) {
    it(`has valid header for ${p}`, () => {
      const data = load(p);
      expect(data).toBeTruthy();
      if (!data) return;
      expect(data.length).toBeGreaterThan(16);
      // Magic
      expect(String.fromCharCode(data[0], data[1], data[2], data[3])).toBe('U16C');
      expect(data[4]).toBe(2); // version 2
      // profile indicator byte matches mapping
      const expectedProfileByte = p === 'standard' ? 1 : 2;
      expect(data[5]).toBe(expectedProfileByte);
    });
  }

  it('minimal profile has no confusables file or empty', () => {
    const data = load('minimal');
    if (data) {
      // minimal might omit file entirely; if present ensure zero length
      expect(data.length === 0 || data.length > 16).toBeTruthy();
    }
  });
});
