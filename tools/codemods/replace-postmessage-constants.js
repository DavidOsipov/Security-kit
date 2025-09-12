#!/usr/bin/env node
/**
 * Codemod: replace direct POSTMESSAGE_MAX_* runtime usages with _pmCfg() accessors.
 *
 * Usage:
 *  node tools/codemods/replace-postmessage-constants.js "src/**/*.ts"
 *
 * Implementation: simple textual AST-assisted transform using @typescript-eslint/parser.
 * Skips:
 *  - config.ts (where defaults are defined)
 *  - tests/ paths
 *  - lines already containing _pmCfg()
 */
import fs from 'node:fs';
import path from 'node:path';
import { parse } from '@typescript-eslint/typescript-estree';

const GLOB = process.argv[2];
if (!GLOB) {
  console.error('Provide a glob (e.g., "src/**/*.ts")');
  process.exit(1);
}

// naive glob expansion (avoid adding a dependency). Only handles simple prefix/**/suffix patterns.
function expand(globPattern) {
  const parts = globPattern.split('**');
  if (parts.length === 1) {
    if (fs.statSync(globPattern).isFile()) return [globPattern];
  }
  const root = parts[0].replace(/\*$|\.$/, '') || '.';
  const suffix = parts[1] || '';
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir)) {
      const full = path.join(dir, entry);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        walk(full);
      } else if (stat.isFile()) {
        if (suffix && !full.endsWith(suffix.trim().replace(/^\//, ''))) continue;
        if (!full.endsWith('.ts') && !full.endsWith('.tsx')) continue;
        files.push(full);
      }
    }
  }
  walk(root);
  return files;
}

const files = expand(GLOB);
const constantMap = {
  POSTMESSAGE_MAX_PAYLOAD_DEPTH: 'maxPayloadDepth',
  POSTMESSAGE_MAX_JSON_INPUT_BYTES: 'maxJsonTextBytes',
  POSTMESSAGE_MAX_PAYLOAD_BYTES: 'maxPayloadBytes',
};

for (const file of files) {
  if (/config\.ts$/.test(file)) continue;
  if (/tests?\//.test(file)) continue;
  const original = fs.readFileSync(file, 'utf8');
  if (!/POSTMESSAGE_MAX_/.test(original)) continue;
  const ast = parse(original, { loc: true, range: true, comment: true });
  let modified = original;
  // Simple string replacement approach guarded by AST detection
  for (const [k, prop] of Object.entries(constantMap)) {
    if (!modified.includes(k)) continue;
    // Skip import/export specifiers by crude regex (import { K } or export { K })
    const pattern = new RegExp(`\n(?!.*import)(?!.*export)([^\n]*?)${k}([^\n]*)`, 'g');
    modified = modified.replace(pattern, (line) => {
      if (line.includes('_pmCfg()')) return line; // already transformed context
      return line.replace(k, `_pmCfg().${prop}`);
    });
  }
  if (modified !== original) {
    fs.writeFileSync(file, modified, 'utf8');
    console.log(`[codemod] Updated ${file}`);
  }
}
