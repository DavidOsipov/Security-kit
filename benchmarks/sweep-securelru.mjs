/* eslint-env node, es2022 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

function listResultFiles() {
  const dir = 'benchmarks';
  return fs.readdirSync(dir)
    .filter(f => /^results-compare-lru-\d+\.json$/.test(f))
    .map(f => path.join(dir, f))
    .sort((a, b) => fs.statSync(a).mtimeMs - fs.statSync(b).mtimeMs);
}

function latestResultFile() {
  const files = listResultFiles();
  return files.length ? files[files.length - 1] : null;
}

function runHarnessOnce(env) {
  execFileSync('node', ['benchmarks/compare-lru-harness.mjs'], { stdio: 'inherit', env });
  const file = latestResultFile();
  if (!file) throw new Error('No result file found after harness run');
  return file;
}

function pickSecureLRUVariant(json) {
  return json['SecureLRU (tuned)'] || json['SecureLRU'] || null;
}

function main() {
  const recencyModes = ['lru', 'segmented'];
  const promoteRates = [2, 4, 8];
  const ttlResolutions = [200, 500, 1000];

  const baseEnv = {
    ...process.env,
    TTL_AUTOPURGE: 'true',
    WIPE_FLUSH_MAX: '256',
    WIPE_SCHED: 'auto',
    WIPE_TIMEOUT_MS: '1',
    WIPE_AUTO_THRESH: '256',
    WIPE_AUTO_BYTES: String(1024 * 1024),
    KEYSPACE: '20000',
    BENCH_RUNS: '1',
    PROMOTE_MODE: 'sampled',
  };

  const runs = [];
  for (const RECENCY_MODE of recencyModes) {
    for (const PROMOTE_RATE of promoteRates) {
      for (const TTL_RES_MS of ttlResolutions) {
        const env = { ...baseEnv, RECENCY_MODE, PROMOTE_RATE: String(PROMOTE_RATE), TTL_RES_MS: String(TTL_RES_MS) };
        console.log('RUN', JSON.stringify({ RECENCY_MODE, PROMOTE_RATE, TTL_RES_MS }));
        const file = runHarnessOnce(env);
        const json = JSON.parse(fs.readFileSync(file, 'utf8'));
        const tuned = pickSecureLRUVariant(json);
        const entry = { cfg: { RECENCY_MODE, PROMOTE_RATE, TTL_RES_MS }, file: path.basename(file), results: tuned };
        runs.push(entry);
      }
    }
  }

  const best = { SET: null, GET: null, UPDATE: null, DELETE: null };
  for (const r of runs) {
    const tuned = r.results || {};
    for (const op of Object.keys(best)) {
      const v = tuned[op];
      if (!v || !v.opsPerSec) continue;
      if (!best[op] || v.opsPerSec > best[op].ops) {
        best[op] = { ops: v.opsPerSec, cfg: r.cfg, file: r.file };
      }
    }
  }

  const summary = { best, runs };
  const out = path.join('benchmarks', `sweep-summary-${Date.now()}.json`);
  fs.writeFileSync(out, JSON.stringify(summary, null, 2), 'utf8');
  console.log('Wrote', out);
  console.log(JSON.stringify(summary.best, null, 2));
}

main();
