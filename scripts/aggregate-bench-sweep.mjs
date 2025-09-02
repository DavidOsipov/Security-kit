#!/usr/bin/env node
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dir = path.join(__dirname, '..', 'benchmarks');
const all = await fs.readdir(dir);
const files = all.filter(f => /^results-compare-lru-\d+\.json$/.test(f)).sort();

const targetFiles = files.filter(f => f.includes('1756837'));
if (!targetFiles.length) {
  console.error('No matching benchmark files found');
  process.exit(1);
}

const rows = [];
for (const f of targetFiles) {
  const full = path.join(dir, f);
  const content = await fs.readFile(full, 'utf8');
  const j = JSON.parse(content);
  const env = j._meta && j._meta.env || {};
  const ts = j._meta && j._meta.timestamp;

  const extract = (key) => {
    const obj = j[key];
    if (!obj) return null;
    const getMean = (op) => (obj[op] && obj[op].mean != null) ? obj[op].mean : null;
    return {
      file: f,
      timestamp: ts,
      recencyMode: env.RECENCY_MODE || null,
      segRotateOps: env.SEG_ROTATE_OPS || null,
      scMaxRot: env.SC_MAX_ROT || null,
      setMean: getMean('SET'),
      getMean: getMean('GET'),
      deleteMean: getMean('DELETE'),
      debug: obj._debug || null
    };
  };

  const sieveKey = 'SecureLRU (sieve tuned)';
  const scKey = 'SecureLRU (second-chance tuned)';

  if (j[sieveKey]) rows.push(extract(sieveKey));
  if (j[scKey]) rows.push(extract(scKey));
}

const csvLines = ['file,timestamp,recencyMode,segRotateOps,scMaxRot,setMean_ms,getMean_ms,deleteMean_ms,sieveScans,sieveRotations,evictions,expired'];
for (const r of rows) {
  const d = r.debug || {};
  csvLines.push([r.file, r.timestamp, r.recencyMode, r.segRotateOps, r.scMaxRot, r.setMean, r.getMean, r.deleteMean, d.sieveScans, d.sieveRotations, d.evictions, d.expired].join(','));
}

const outCsv = path.join(dir, 'sweep-summary-1756837.csv');
await fs.writeFile(outCsv, csvLines.join('\n'));
await fs.writeFile(path.join(dir, 'sweep-summary-1756837.json'), JSON.stringify(rows, null, 2));
console.log('Wrote', outCsv);