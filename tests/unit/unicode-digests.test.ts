// SPDX-License-Identifier: LGPL-3.0-or-later
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';

// Hardcoded expected SHA-384 digests (must match script & build constants)
const EXPECTED = {
  'IdentifierStatus.txt': '5b23e5998a5a08261923fc364c6ae43c0f729116362b43740ed1eb3473a5c224cec5a27035e6660c5b2c652ccb35e297',
  'confusablesSummary.txt': '50f6a163e9741c0ce50a965a448191a463eb79df96494ad795c367df471ca3de73643216374774ed85f71fdd29cc1abc'
} as const;

function sha384(buf: Uint8Array): string {
  return createHash('sha384').update(buf).digest('hex');
}

describe('Unicode source digest invariants (SHA-384)', () => {
  const root = process.cwd();
  const base = join(root, 'docs/Additional security guidelines/Specifications and RFC/Unicode 16.0.0');
  for (const file of Object.keys(EXPECTED) as (keyof typeof EXPECTED)[]) {
    it(`matches expected digest for ${file}`, () => {
      const raw = readFileSync(join(base, file));
      const actual = sha384(raw);
      expect(actual.toLowerCase()).toBe(EXPECTED[file]);
    });
  }
});
