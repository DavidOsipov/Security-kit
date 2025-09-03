#!/usr/bin/env node
// TypeScript CI helper: scan repository for likely secret literals shorter than 32 bytes.
// Heuristic scanner that looks for quoted strings containing alphanumerics, - or _,
// with length between 8 and 64 characters. Exits non-zero if any likely short secrets
// are found. This is intended as a simple, opt-in CI guard — projects can replace
// it with a stricter eslint rule if desired.

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const MIN_BYTES = 32;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");

function isLikelySecretLiteral(s: string): boolean {
  return /^[A-Za-z0-9_-]{8,64}$/.test(s);
}

function bytesLengthOfString(s: string): number {
  return Buffer.from(s, "utf8").length;
}

function walk(dir: string, cb: (file: string) => void) {
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      if (name === "node_modules" || name === ".git" || name === "dist")
        continue;
      walk(full, cb);
    } else if (stat.isFile()) {
      cb(full);
    }
  }
}

const matches: Array<{ file: string; literal: string; bytes: number }> = [];
walk(repoRoot, (file) => {
  if (!file.endsWith(".ts") && !file.endsWith(".md")) return;
  const data = fs.readFileSync(file, "utf8");
  const re = /(['\"])([A-Za-z0-9_-]{8,64})\1/g;
  let m: RegExpExecArray | null;
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
  console.log("No short secret literals detected.");
  process.exit(0);
}

console.error("Detected short secret literals (< 32 bytes):");
for (const m of matches) {
  console.error(`  ${m.file}: "${m.literal}" (${m.bytes} bytes)`);
}
process.exit(2);
