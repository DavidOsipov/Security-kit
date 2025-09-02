/* eslint-env node, es2022 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

function listResultFiles() {
  const dir = 'benchmarks';
  return fs
    .readdirSync(dir)
    .filter((f) => /^results-compare-lru-\d+\.json$/.test(f))
    .map((f) => path.join(dir, f))
    .sort((a, b) => fs.statSync(a).mtimeMs - fs.statSync(b).mtimeMs);
}

function latestResultFile() {
  const files = listResultFiles();
  return files.length ? files[files.length - 1] : null;
}

function runHarnessOnce(env) {
  execFileSync('node', ['benchmarks/compare-lru-harness.mjs', 'throughput-segmented-aggressive'], { stdio: 'inherit', env });
  const file = latestResultFile();
  if (!file) throw new Error('No result file found after harness run');
  return file;
}

function pick(json) { return json['SecureLRU (tuned)'] || json['SecureLRU'] || null; }

function main() {
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
    PROMOTE_RATE: '2',
    RECENCY_MODE: 'segmented',
    TTL_RES_MS: '200',
  };

  const scans = [4, 8, 12, 16];
  const rotates = [2000, 5000, 10000, 20000];
  const runs = [];
  const iterations = Number(process.env.ITERATIONS_PER_POINT || 1);
  for (const SEG_SCAN of scans) {
    for (const SEG_ROTATE_OPS of rotates) {
      const cfgResults = [];
      for (let it = 0; it < iterations; it++) {
        const env = { ...baseEnv, SEG_SCAN: String(SEG_SCAN), SEG_ROTATE_OPS: String(SEG_ROTATE_OPS) };
        console.log('RUN', JSON.stringify({ SEG_SCAN, SEG_ROTATE_OPS, iteration: it + 1 }));
        const file = runHarnessOnce(env);
        const json = JSON.parse(fs.readFileSync(file, 'utf8'));
        const tuned = pick(json);
        cfgResults.push({ cfg: { SEG_SCAN, SEG_ROTATE_OPS }, file: path.basename(file), results: tuned });
      }
      // average across iterations for this cfg
      const merged = { cfg: { SEG_SCAN, SEG_ROTATE_OPS }, results: {} };
      const ops = ['SET','GET','UPDATE','DELETE'];
      for (const op of ops) {
        const vals = cfgResults.map(r => r.results && r.results[op] && r.results[op].opsPerSec).filter(Boolean);
        merged.results[op] = vals.length ? Math.round(vals.reduce((a,b)=>a+b,0)/vals.length) : null;
      }
      runs.push(merged);
    }
  }

  // Produce top-k per op
  const ops = ['SET','GET','UPDATE','DELETE'];
  const perOp = {};
  for (const op of ops) {
    const entries = runs.map(r => ({ cfg: r.cfg, value: r.results[op] })).filter(e => e.value != null).sort((a,b) => b.value - a.value);
    perOp[op] = entries;
  }

  const summary = { runs, perOp };
  const out = path.join('benchmarks', `segmented-micro-sweep-${Date.now()}.json`);
  fs.writeFileSync(out, JSON.stringify(summary, null, 2), 'utf8');
  console.log('Wrote', out);
  // Print top-3 per op
  for (const op of Object.keys(perOp)) {
    console.log('\nTop configs for', op);
    perOp[op].slice(0,3).forEach((e, i) => console.log(`#${i+1}: ${e.value} ops/s  cfg=${JSON.stringify(e.cfg)}`));
  }
}

main();
