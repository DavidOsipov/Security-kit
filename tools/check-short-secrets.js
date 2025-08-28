#!/usr/bin/env node
// Quick CI helper: scan repository for likely secret literals shorter than 32 bytes.
// This is a heuristic scanner to catch accidental short test secrets like "test-key-123"
// or hex strings under 32 bytes. It intentionally errs on the side of warning;
// projects may tune or replace with a more strict eslint rule.

const fs = require('fs');
const path = require('path');

const MIN_BYTES = 32;
const repoRoot = path.resolve(__dirname, '..');

function isLikelySecretLiteral(s) {
  // heuristics: letters/digits and -_ only, length between 8 and 64 characters
  return typeof s === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(s);
}

function bytesLengthOfString(s) {
  return Buffer.from(s, 'utf8').length;
}

function walk(dir, cb) {
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      if (name === 'node_modules' || name === '.git' || name === 'dist') continue;
      walk(full, cb);
    } else if (stat.isFile()) {
      cb(full);
    }
  }
}

const matches = [];
walk(repoRoot, (file) => {
  if (!file.endsWith('.ts') && !file.endsWith('.js') && !file.endsWith('.spec.ts') && !file.endsWith('.md')) return;
  const data = fs.readFileSync(file, 'utf8');
  // naive: find quoted strings
  const re = /(['\"])([A-Za-z0-9_-]{8,64})\1/g;
  let m;
  while ((m = re.exec(data)) !== null) {
    const literal = m[2];
    if (isLikelySecretLiteral(literal)) {
      const bytes = bytesLengthOfString(literal);
      if (bytes < MIN_BYTES) {
        matches.push({ file, literal, bytes });
      }
    }
  }
});

if (matches.length === 0) {
  console.log('No short secret literals detected.');
  process.exit(0);
}

console.error('Detected short secret literals (< 32 bytes):');
for (const m of matches) {
  console.error(`  ${m.file}: "${m.literal}" (${m.bytes} bytes)`);
}
process.exit(2);
