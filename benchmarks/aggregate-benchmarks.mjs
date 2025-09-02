import fs from 'fs';
import path from 'path';

function loadResultsFiles(dir, pattern = /^results-secure-lru-cache-\d+\.json$/) {
  return fs.readdirSync(dir)
    .filter(f => pattern.test(f))
    .map(f => path.join(dir, f))
    .sort((a, b) => fs.statSync(a).mtimeMs - fs.statSync(b).mtimeMs);
}

function stats(values) {
  if (!values || values.length === 0) return null;
  const n = values.length;
  const sum = values.reduce((s, v) => s + v, 0);
  const mean = sum / n;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / n;
  const stddev = Math.sqrt(variance);
  return { n, mean, min, max, stddev };
}

function aggregate(files, lastN = 5) {
  const sel = files.slice(-lastN);
  const runs = sel.map(f => JSON.parse(fs.readFileSync(f, 'utf8')));
  const names = ['SET', 'GET', 'UPDATE', 'DELETE'];
  const out = {};
  for (const name of names) {
    const values = runs.map(r => (r[name] && r[name].opsPerSec) || null).filter(Boolean);
    const s = stats(values);
    out[name] = { runs: values, stats: s };
  }
  return { files: sel, aggregated: out };
}

const dir = path.join(process.cwd(), 'benchmarks');
const files = loadResultsFiles(dir);
if (files.length === 0) {
  console.error('No results files found');
  process.exit(1);
}
const agg = aggregate(files, 5);
// Print JSON first
console.log(JSON.stringify(agg, null, 2));

// Also print a small markdown table for easy viewing
function fmt(n) {
  return n == null ? '-' : (Math.round(n * 100) / 100).toLocaleString();
}

console.log('\n# Aggregated benchmark stats (last 5 runs)\n');
console.log('| Task | runs | count | mean (ops/s) | min | max | stddev | CV |');
console.log('|---|---:|---:|---:|---:|---:|---:|---:|');
for (const [task, data] of Object.entries(agg.aggregated)) {
  const runs = data.runs || [];
  const s = data.stats;
  const cv = s ? (s.stddev / s.mean) : null;
  console.log(`| ${task} | ${runs.join(', ')} | ${s ? s.n : 0} | ${s ? Math.round(s.mean) : '-'} | ${s ? Math.round(s.min) : '-'} | ${s ? Math.round(s.max) : '-'} | ${s ? Math.round(s.stddev) : '-'} | ${s ? (Math.round(cv * 10000) / 100) + '%' : '-'} |`);
}

