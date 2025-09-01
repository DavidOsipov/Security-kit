#!/usr/bin/env node

import { execSync } from 'child_process';

// Simple guard that allows blob usage in secure contexts
const forbidden = [
  /\ballowEmbeddedFallback\b/,
  /\bembedded-blob\b/
];

function check() {
  const found = [];

  for (const patt of forbidden) {
    try {
      const patternStr = patt.source.replace(/"/g, '\\"');
      const command = `git grep -nP "${patternStr}" -- src`;

      const out = execSync(command, {
        encoding: 'utf8',
        maxBuffer: 1024 * 1024
      });

      if (out && out.trim()) {
        const lines = out.trim().split(/\r?\n/);
        for (const ln of lines) {
          const m = ln.match(/^([^:]+):(\d+):(.*)$/);
          if (m) {
            found.push({
              file: m[1],
              pattern: patt.source,
              line: `${m[2]}: ${m[3].trim()}`
            });
          }
        }
      }
    } catch (err) {
      const e = err as any;
      if (e && typeof e.status === 'number' && e.status !== 1) {
        console.error('Failed to run git grep. Ensure this is a git repository and git is installed.');
        process.exit(1);
      }
    }
  }

  if (found.length > 0) {
    console.error('Forbidden patterns found in src/:');
    for (const x of found) {
      console.error(`${x.file}: contains /${x.pattern}/`);
      console.error(`  ${x.line}`);
    }
    process.exit(2);
  }
  console.log('No forbidden patterns found in src/.');
}

check();
