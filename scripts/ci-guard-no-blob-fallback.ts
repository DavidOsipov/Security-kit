#!/usr/bin/env node
import path from 'path';
import { execSync } from 'child_process';

// Code-level patterns that must not appear in source files under src/.
const forbidden: Array<RegExp> = [
  /\ballowEmbeddedFallback\b/,
  /\bURL\.createObjectURL\b/,
  /\bcreateObjectURL\s*\(/,
  /\bnew\s+Blob\s*\(/,
  /\bembedded-blob\b/,
];

async function check() {
  // Use `git grep -nP` per forbidden pattern to search tracked files under
  // `src/` without materializing file contents via fs APIs. This avoids
  // triggering internal Node deprecation warnings while being robust and
  // fast in CI environments.
  const repoRoot = path.resolve(new URL('..', import.meta.url).pathname);
  const found: { file: string; pattern: string }[] = [];

  for (const patt of forbidden) {
    // Use the raw pattern source; run git grep with PCRE (-P) and show
    // filename and line number. If git is not available or the command fails
    // the try/catch below will surface a helpful message.
    try {
      const out = execSync(`git grep -nP -- "${patt.source}" -- src`, { encoding: 'utf8' });
      if (out && out.trim()) {
        const lines = out.trim().split(/\r?\n/);
        for (const ln of lines) {
          // git grep output: path:line:match
          const m = ln.match(/^([^:]+):\d+:/);
          const filePath = m ? path.join(repoRoot, m[1]) : path.join(repoRoot, ln.split(':')[0]);
          found.push({ file: filePath, pattern: patt.source });
        }
      }
    } catch (err) {
      // git grep returns non-zero when no matches are found; ignore that.
      // For other errors (e.g., not a git repo) surface a clear message.
      const e = err as any;
      if (e && typeof e.status === 'number' && e.status !== 1) {
        console.error('Failed to run git grep. Ensure this is a git repository and git is installed.');
        process.exit(1);
      }
    }
  }

  if (found.length > 0) {
    console.error('Forbidden patterns found in src/:');
    for (const x of found) console.error(`${x.file}: contains /${x.pattern}/`);
    process.exit(2);
  }
  console.log('No forbidden patterns found in src/.');
}

check().catch((err) => {
  console.error('Guard failed:', err);
  process.exit(3);
});
