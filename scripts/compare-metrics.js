#!/usr/bin/env node
// Lightweight metric comparison tool
// Usage: node scripts/compare-metrics.js <testMetrics.json> <benchResult.json>

import { readFileSync } from 'fs';
import path from 'path';

function loadJson(p) {
  const txt = readFileSync(p, 'utf8');
  return JSON.parse(txt);
}

function normalizeMean(val) {
  // If mean looks like microseconds (large integer > 1000), convert to ms
  if (val == null) return null;
  if (typeof val !== 'number') return Number(val);
  if (val > 1000) return val / 1000; // assume µs -> ms
  return val; // already ms
}

function fmt(n, unit = 'ms') {
  if (n == null) return '-';
  if (unit === 'ms') return `${(n).toFixed(6)} ms`;
  return String(n);
}

function percentDiff(a, b) {
  if (a == null || b == null) return null;
  if (b === 0) return a === 0 ? 0 : Infinity;
  return ((a - b) / b) * 100;
}

const argv = process.argv.slice(2);
if (argv.length < 2) {
  console.error('Usage: compare-metrics.js <testMetrics.json> <benchResult.json>');
  process.exit(2);
}

const testPath = path.resolve(argv[0]);
const benchPath = path.resolve(argv[1]);

const test = loadJson(testPath);
const bench = loadJson(benchPath);

// Attempt to find the SecureLRU (sieve tuned) entry in bench results
const benchKeyCandidates = ['SecureLRU (sieve tuned)', 'SecureLRU', 'SecureLRU (tuned)'];
let benchEntry = null;
for (const k of benchKeyCandidates) {
  if (bench[k]) { benchEntry = bench[k]; break; }
}
if (!benchEntry) {
  // try first non-meta key
  const keys = Object.keys(bench).filter(k => !k.startsWith('_'));
  if (keys.length) benchEntry = bench[keys[0]];
}
if (!benchEntry) {
  console.error('Could not locate a bench entry in', benchPath);
  process.exit(2);
}

console.log('\nComparing metrics:');
console.log(' Test metrics:', testPath);
console.log(' Bench metrics:', benchPath, '\n');

const ops = ['SET','GET','DELETE'];
for (const op of ops) {
  const t = test[op] || test[op.toLowerCase()] || {};
  const b = benchEntry[op] || benchEntry[op.toUpperCase()] || {};
  const tMean = normalizeMean(t.mom ?? t.mean ?? t.p50 ?? null);
  const bMean = normalizeMean(b.mean ?? null);
  const diff = percentDiff(tMean, bMean);
  console.log(`- ${op}`);
  console.log(`  test : ${fmt(tMean)}  (samples: ${t.samples ?? t.samples})`);
  console.log(`  bench: ${fmt(bMean)}  (samples: ${b.samples ?? '-'})`);
  if (diff == null) console.log('  delta: -');
  else console.log(`  delta: ${diff.toFixed(1)}% ${Math.abs(diff) > 25 ? '<< SIGNIFICANT' : ''}`);
  console.log('');
}

// Throughput compare (if available)
if (test.throughput && test.throughput.opsPerSec && benchEntry.SET && benchEntry.SET.opsPerSec) {
  const ttp = test.throughput.opsPerSec;
  const btp = benchEntry.SET.opsPerSec;
  const pd = percentDiff(ttp, btp);
  console.log(`Throughput: test ${Math.round(ttp).toLocaleString()} ops/sec vs bench ${Math.round(btp).toLocaleString()} ops/sec`);
  console.log(` delta: ${pd.toFixed(1)}% ${Math.abs(pd) > 25 ? '<< SIGNIFICANT' : ''}`);
}

// Debug counters
if (benchEntry._debug || test._debug) {
  const bd = benchEntry._debug || {};
  const td = test._debug || {};
  console.log('\nDebug counters:');
  console.log(' bench:', bd);
  console.log(' test :', td);
  if ((bd.sieveScans || 0) + (bd.sieveRotations || 0) === 0 && ((td.sieveScans || 0) + (td.sieveRotations || 0) > 0)) {
    console.log('\n Note: bench debug shows zero SIEVE activity while test shows activity; this is likely due to different cache sizing/workload (evictions vs no-evictions).');
  }
}

console.log('\nDone.');
