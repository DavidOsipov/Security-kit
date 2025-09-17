// SPDX-License-Identifier: LGPL-3.0-or-later
/**
 * Fast fail scanner for bidirectional and invisible control characters in source files.
 * Exits with non-zero status if any are found outside approved allowlist files.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

const ROOT = process.cwd();
const TARGET_DIRS = ['src','tests','scripts'];
// Allow listing files known to deliberately embed these ranges (adjust as needed)
const ALLOWLIST = new Set<string>([
  'src/config.ts', // may contain static regex patterns
  'src/canonical.ts'
]);

// Same patterns as runtime (kept small here to avoid dependency loops)
const BIDI = /[\u200E\u200F\u202A-\u202E\u2066-\u2069\u061C\u2028\u2029]/u;
const INVIS = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFFF]/u;

function collectFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...collectFiles(full));
    } else if (st.isFile()) {
      const ext = extname(full);
      if (['.ts','.js','.mjs','.cjs'].includes(ext)) out.push(full);
    }
  }
  return out;
}

function main(): void {
  let violations = 0;
  for (const d of TARGET_DIRS) {
    const base = join(ROOT, d);
    try {
      for (const file of collectFiles(base)) {
        const rel = file.substring(ROOT.length + 1);
        const text = readFileSync(file, 'utf8');
        if (!BIDI.test(text) && !INVIS.test(text)) continue;
        if (ALLOWLIST.has(rel)) continue; // allowed
        const matches: string[] = [];
        for (const re of [BIDI, INVIS]) {
          re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = re.exec(text)) !== null && matches.length < 10) {
            matches.push(`U+${m[0]!.codePointAt(0)!.toString(16).toUpperCase().padStart(4,'0')}`);
          }
        }
        // Report and count
        // eslint-disable-next-line no-console -- intentional security reporting
        console.error(`[unicode-scan] Disallowed control chars in ${rel}: ${matches.join(', ')}`);
        violations++;
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn(`[unicode-scan] Skipping ${d}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (violations > 0) {
    // eslint-disable-next-line no-console
    console.error(`[unicode-scan] Found ${violations} file(s) with disallowed control characters.`);
    process.exit(1);
  }
  // eslint-disable-next-line no-console
  console.log('[unicode-scan] No disallowed Unicode control characters detected.');
}

if (require.main === module) {
  main();
}
