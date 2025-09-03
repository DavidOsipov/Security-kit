/* eslint-env node, es2022 */
import fs from 'fs';
import path from 'path';

function listResultFiles(dir = 'benchmarks') {
  return fs
    .readdirSync(dir)
    .filter((f) => /^results-compare-lru-\d+\.json$/.test(f))
    .map((f) => path.join(dir, f))
    .sort((a, b) => fs.statSync(a).mtimeMs - fs.statSync(b).mtimeMs);
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function summarize(files, lastN = 10) {
  const sel = files.slice(-lastN);
  const rows = sel.map((f) => ({ file: f, json: JSON.parse(fs.readFileSync(f, 'utf8')) }));

  const groups = new Map(); // profileName => [{file,json}]
  for (const r of rows) {
    const prof = (r.json && r.json._meta && r.json._meta.profile) || 'unlabeled';
    if (!groups.has(prof)) groups.set(prof, []);
    groups.get(prof).push(r);
  }

  function avgOps(entries, libName, op) {
    const vals = entries
      .map((e) => e.json && e.json[libName] && e.json[libName][op] && e.json[libName][op].opsPerSec)
      .map(num)
      .filter((x) => x != null);
    if (!vals.length) return { n: 0, mean: null, min: null, max: null };
    const n = vals.length;
    const sum = vals.reduce((a, b) => a + b, 0);
    const mean = sum / n;
    const min = Math.min(...vals);
    const max = Math.max(...vals);
    return { n, mean, min, max };
  }

  const perProfile = {};
  for (const [profile, entries] of groups.entries()) {
    perProfile[profile] = {
      SecureLRU: {
        SET: avgOps(entries, 'SecureLRU', 'SET'),
        GET: avgOps(entries, 'SecureLRU', 'GET'),
        UPDATE: avgOps(entries, 'SecureLRU', 'UPDATE'),
        DELETE: avgOps(entries, 'SecureLRU', 'DELETE'),
      },
      'SecureLRU (tuned)': {
        SET: avgOps(entries, 'SecureLRU (tuned)', 'SET'),
        GET: avgOps(entries, 'SecureLRU (tuned)', 'GET'),
        UPDATE: avgOps(entries, 'SecureLRU (tuned)', 'UPDATE'),
        DELETE: avgOps(entries, 'SecureLRU (tuned)', 'DELETE'),
      },
      count: entries.length,
      sampleFiles: entries.map((e) => path.basename(e.file)),
      envSummary: (entries.length > 0 && entries[entries.length - 1].json && entries[entries.length - 1].json._meta)
        ? (entries[entries.length - 1].json._meta.env || null)
        : null,
    };
  }

  const globalSummary = { perProfile, totalFiles: sel.length, files: sel.map((f) => path.basename(f)) };
  return globalSummary;
}

function writeSummaries(summary, dir = 'benchmarks') {
  const ts = Date.now();
  const outGlobal = path.join(dir, `summary-${ts}.json`);
  fs.writeFileSync(outGlobal, JSON.stringify(summary, null, 2), 'utf8');

  // Also write per-profile files for CI scraping convenience
  const per = summary.perProfile || {};
  for (const [profile, data] of Object.entries(per)) {
    const safe = String(profile).replace(/[^\w-]+/g, '-');
    const fn = path.join(dir, `summary-${safe}-${ts}.json`);
    fs.writeFileSync(fn, JSON.stringify(data, null, 2), 'utf8');
  }
  return outGlobal;
}

function printTable(summary) {
  console.log('\n# SecureLRU profile summary (last N runs)\n');
  console.log('| Profile | Lib | SET | GET | UPDATE | DELETE | n |');
  console.log('|---|---|---:|---:|---:|---:|---:|');
  for (const [profile, data] of Object.entries(summary.perProfile)) {
    const libs = ['SecureLRU', 'SecureLRU (tuned)'];
    for (const lib of libs) {
      const s = data[lib];
      const fmt = (x) => (x && x.mean != null ? Math.round(x.mean).toLocaleString() : '-');
      console.log(`| ${profile} | ${lib} | ${fmt(s.SET)} | ${fmt(s.GET)} | ${fmt(s.UPDATE)} | ${fmt(s.DELETE)} | ${data.count} |`);
    }
  }
}

function main() {
  const dir = process.argv[2] || 'benchmarks';
  const lastN = Number(process.argv[3] || process.env.SUMMARY_LAST || 10);
  const files = listResultFiles(dir);
  if (!files.length) {
    console.error('No compare-lru result files found.');
    process.exit(1);
  }
  const summary = summarize(files, lastN);
  const out = writeSummaries(summary, dir);
  console.log('Wrote summary to', out);
  printTable(summary);
}

main();
