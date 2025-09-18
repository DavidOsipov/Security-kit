// SPDX-License-Identifier: LGPL-3.0-or-later
// Independent verification of hardcoded Unicode SHA-384 digests
// Defense-in-depth: cross-check Node 'crypto' and Web Crypto implementations.
// Fails non-zero on mismatch. Safe to run in CI before generation.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const ROOT = process.cwd();
const UNICODE_DIR = join(ROOT, 'docs/Additional security guidelines/Specifications and RFC/Unicode 16.0.0');

interface TargetFile { name: string; expected: string; }
const FILES: TargetFile[] = [
  { name: 'IdentifierStatus.txt', expected: '5b23e5998a5a08261923fc364c6ae43c0f729116362b43740ed1eb3473a5c224cec5a27035e6660c5b2c652ccb35e297' },
  { name: 'confusablesSummary.txt', expected: '50f6a163e9741c0ce50a965a448191a463eb79df96494ad795c367df471ca3de73643216374774ed85f71fdd29cc1abc' }
];

function sha384Node(buf: Uint8Array): string {
  return createHash('sha384').update(buf).digest('hex');
}

async function sha384Web(buf: Uint8Array): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    return 'webcrypto-unavailable';
  }
  const digest = await crypto.subtle.digest('SHA-384', buf);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function main(): Promise<number> {
  let failures = 0;
  for (const f of FILES) {
    const path = join(UNICODE_DIR, f.name);
    const raw = readFileSync(path);
    const nodeHash = sha384Node(raw);
    const webHash = await sha384Web(raw);
    const okNode = nodeHash.toLowerCase() === f.expected.toLowerCase();
    const okWeb = webHash === 'webcrypto-unavailable' ? true : webHash.toLowerCase() === f.expected.toLowerCase();
    const status = okNode && okWeb ? '✅' : '❌';
    console.log(`${status} ${f.name}`);
    if (!okNode) {
      console.error(`   Node hash mismatch. Expected ${f.expected} got ${nodeHash}`);
      failures++;
    }
    if (!okWeb && webHash !== 'webcrypto-unavailable') {
      console.error(`   WebCrypto hash mismatch. Expected ${f.expected} got ${webHash}`);
      failures++;
    }
  }
  if (failures > 0) {
    console.error(`Digest verification failed for ${failures} file(s).`);
    return 1;
  }
  console.log('All Unicode source digests verified (SHA-384).');
  return 0;
}

main().then(code => { if (code) process.exit(code); }).catch(err => { console.error('Verification script error:', err); process.exit(1); });
