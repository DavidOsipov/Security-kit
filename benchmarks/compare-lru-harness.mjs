/* eslint-env node, es2022 */
/* eslint-disable */
import { Bench } from 'tinybench';
import { promises as fs } from 'fs';
import path from 'path';

function nowMs() { return (typeof performance !== 'undefined') ? performance.now() : Date.now(); }

function createBenchLogger() {
  const quiet = String(process.env.QUIET_SECURELRU_WARN || '') === '1';
  return {
    warn: quiet ? function () {} : function (...data) { try { console.warn('[security-kit:cache]', ...data); } catch (_) {} },
    error: function (...data) { try { console.error('[security-kit:cache]', ...data); } catch (_) {} },
  };
}

async function tryImport(spec) {
  try {
    // Try indirect dynamic import first (avoid parser seeing 'import' token)
    const dynImport = new Function('s', 'return import(s)');
    return await dynImport(spec);
  } catch (err) {
    // Try CommonJS require fallback (for cjs builds)
    try {
  const dynImport = new Function('s', 'return import(s)');
  const mod = await dynImport('module');
  const createRequire = mod.createRequire;
  // Compute a base path for createRequire without using import.meta.url to keep parser happy
  const base = (process.argv && process.argv[1]) ? `file://${process.cwd()}/${process.argv[1]}` : `file://${process.cwd()}/`;
  const req = createRequire(base);
  return req(spec);
    } catch (err2) {
      // Log both errors for diagnostics and return null like original helper
      // (harness will skip gracefully if a module isn't available)
      console.error('tryImport failed for', spec, err && err.message, err2 && err2.message);
      return null;
    }
  }
}

function getEnvInt(name, def) {
  const v = process.env[name];
  if (!v) return def;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : def;
}

function getEnvBool(name, def) {
  const v = process.env[name];
  if (v == null) return def;
  if (v === '1' || v.toLowerCase() === 'true') return true;
  if (v === '0' || v.toLowerCase() === 'false') return false;
  return def;
}

function buildSecureOptions(base = {}) {
  // Base options for SecureLRU; allow env overrides to sweep
  const opts = {
    ...base,
  };
  const ttlRes = getEnvInt('TTL_RES_MS', undefined);
  if (ttlRes != null) opts.ttlResolutionMs = ttlRes;
  const ttlAutopurge = process.env.TTL_AUTOPURGE;
  if (ttlAutopurge != null) opts.ttlAutopurge = getEnvBool('TTL_AUTOPURGE', false);
  const wipeFlush = getEnvInt('WIPE_FLUSH_MAX', undefined);
  if (wipeFlush != null) opts.maxDeferredWipesPerFlush = wipeFlush;
  const wipeSched = process.env.WIPE_SCHED;
  if (wipeSched) opts.deferredWipeScheduler = wipeSched;
  const wipeTimeout = getEnvInt('WIPE_TIMEOUT_MS', undefined);
  if (wipeTimeout != null) opts.deferredWipeTimeoutMs = wipeTimeout;
  const wipeAutoThresh = getEnvInt('WIPE_AUTO_THRESH', undefined);
  if (wipeAutoThresh != null) opts.deferredWipeAutoThreshold = wipeAutoThresh;
  const wipeAutoBytes = getEnvInt('WIPE_AUTO_BYTES', undefined);
  if (wipeAutoBytes != null) opts.deferredWipeAutoBytesThreshold = wipeAutoBytes;
  const promoteMode = process.env.PROMOTE_MODE;
  if (promoteMode) opts.promoteOnGet = promoteMode;
  const promoteRate = getEnvInt('PROMOTE_RATE', undefined);
  if (promoteRate != null) opts.promoteOnGetSampleRate = promoteRate;
  const maxEntryBytes = getEnvInt('MAX_ENTRY_BYTES', undefined);
  if (maxEntryBytes != null) opts.maxEntryBytes = maxEntryBytes;
  const maxBytes = getEnvInt('MAX_BYTES', undefined);
  if (maxBytes != null) opts.maxBytes = maxBytes;
  const maxEntries = getEnvInt('MAX_ENTRIES', undefined);
  if (maxEntries != null) opts.maxEntries = maxEntries;
  const recencyMode = process.env.RECENCY_MODE;
  // Do not override an explicitly provided recencyMode in base options
  if (recencyMode && (opts.recencyMode == null)) opts.recencyMode = recencyMode;
  const segScan = getEnvInt('SEG_SCAN', undefined);
  if (segScan != null) opts.segmentedEvictScan = segScan;
  const segRotate = getEnvInt('SEG_ROTATE_OPS', undefined);
  if (segRotate != null) opts.segmentRotateEveryOps = segRotate;
  const scMaxRot = getEnvInt('SC_MAX_ROT', undefined);
  if (scMaxRot != null) opts.secondChanceMaxRotationsPerEvict = scMaxRot;
  const copyOnSet = process.env.COPY_ON_SET;
  if (copyOnSet != null) opts.copyOnSet = getEnvBool('COPY_ON_SET', true);
  const copyOnGet = process.env.COPY_ON_GET;
  if (copyOnGet != null) opts.copyOnGet = getEnvBool('COPY_ON_GET', true);
  return opts;
}

// Map PROFILE name to environment knobs for reproducible runs
function applyProfileEnv(profileName) {
  const p = (profileName || '').toLowerCase();
  const env = {};
  if (!p) return env;
  switch (p) {
    case 'sieve-microtask':
      // Canonical SIEVE defaults but force microtask wipe scheduling for low jitter
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'microtask';
      env.WIPE_TIMEOUT_MS = '0';
      env.WIPE_AUTO_THRESH = '512';
      env.WIPE_AUTO_BYTES = String(2 * 1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'sieve';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      break;
    case 'write8k-sieve':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'sieve';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      env.VALUE_BYTES = String(8 * 1024);
      env.BENCH_ITER = '2000';
      break;
    case 'write64k-sieve':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'sieve';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
  env.VALUE_BYTES = String(64 * 1024);
  env.BENCH_ITER = '1500';
  env.KEYSPACE = '1000';
  env.MAX_ENTRY_BYTES = String(128 * 1024);
  env.MAX_BYTES = String(128 * 1024 * 1024);
      break;
    case 'write8k-2nd':
    case 'write8k-second-chance':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'second-chance';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      env.SC_MAX_ROT = '8';
      env.VALUE_BYTES = String(8 * 1024);
      env.BENCH_ITER = '2000';
      break;
    case 'write64k-2nd':
    case 'write64k-second-chance':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'second-chance';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      env.SC_MAX_ROT = '8';
  env.VALUE_BYTES = String(64 * 1024);
  env.BENCH_ITER = '1500';
  env.KEYSPACE = '1000';
  env.MAX_ENTRY_BYTES = String(128 * 1024);
  env.MAX_BYTES = String(128 * 1024 * 1024);
      break;
    case 'write8k-segmented':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'segmented';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      env.VALUE_BYTES = String(8 * 1024);
      env.BENCH_ITER = '2000';
      break;
    case 'nocopy8k-sieve':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'sieve';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      env.VALUE_BYTES = String(8 * 1024);
      env.BENCH_ITER = '2000';
      env.COPY_ON_SET = 'false';
      env.COPY_ON_GET = 'false';
      break;
    case 'nocopy8k-second-chance':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'second-chance';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SC_MAX_ROT = '8';
      env.SEG_ROTATE_OPS = '10000';
      env.VALUE_BYTES = String(8 * 1024);
      env.BENCH_ITER = '2000';
      env.COPY_ON_SET = 'false';
      env.COPY_ON_GET = 'false';
      break;
    case 'nocopy64k-sieve':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'sieve';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      env.VALUE_BYTES = String(64 * 1024);
      env.BENCH_ITER = '1500';
      env.KEYSPACE = '1000';
      env.MAX_ENTRY_BYTES = String(128 * 1024);
      env.MAX_BYTES = String(128 * 1024 * 1024);
      env.COPY_ON_SET = 'false';
      env.COPY_ON_GET = 'false';
      break;
    case 'write64k-segmented':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'segmented';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
  env.VALUE_BYTES = String(64 * 1024);
  env.BENCH_ITER = '1500';
  env.KEYSPACE = '1000';
  env.MAX_ENTRY_BYTES = String(128 * 1024);
  env.MAX_BYTES = String(128 * 1024 * 1024);
      break;
    case 'throughput-segmented-aggressive':
    case 'segmented-aggressive':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '2';
      env.RECENCY_MODE = 'segmented';
      env.TTL_RES_MS = '200';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      break;
    case 'throughput-segmented':
    case 'segmented':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'segmented';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      break;
    case 'experimental-sieve':
    case 'sieve':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'sieve';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      break;
    case 'second-chance':
    case '2nd':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'second-chance';
      env.TTL_RES_MS = '500';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      env.SC_MAX_ROT = '8';
      break;
    case 'read-heavy-lru-coarse':
    case 'lru-coarse':
      env.TTL_AUTOPURGE = 'true';
      env.WIPE_FLUSH_MAX = '256';
      env.WIPE_SCHED = 'auto';
      env.WIPE_TIMEOUT_MS = '1';
      env.WIPE_AUTO_THRESH = '256';
      env.WIPE_AUTO_BYTES = String(1024 * 1024);
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '8';
      env.RECENCY_MODE = 'lru';
      env.TTL_RES_MS = '1000';
      env.SEG_SCAN = '8';
      env.SEG_ROTATE_OPS = '10000';
      break;
    case 'balanced':
      env.TTL_AUTOPURGE = 'true';
      env.TTL_RES_MS = '500';
      env.PROMOTE_MODE = 'sampled';
      env.PROMOTE_RATE = '4';
      env.RECENCY_MODE = 'lru';
      break;
    case 'low-latency-lru':
      env.TTL_AUTOPURGE = 'true';
      env.TTL_RES_MS = '200';
      env.PROMOTE_MODE = 'always';
      env.RECENCY_MODE = 'lru';
      break;
    default:
      // unknown, leave as-is
      break;
  }
  return env;
}

async function buildCacheInstances() {
  const instances = [];
  const Secure = await tryImport('../dist/index.mjs');
  // Prefer local built SecureLRUCache if available; otherwise load source
  let SecureLRU;
  if (Secure && Secure.SecureLRUCache) {
    SecureLRU = Secure.SecureLRUCache;
  } else {
    const s = await tryImport('./secure-lru-cache-bench-loader.mjs');
    if (s && s.SecureLRUCache) SecureLRU = s.SecureLRUCache;
  }
  if (SecureLRU) {
    const base = { maxEntries: 1000, maxBytes: 1024 * 1024, maxEntryBytes: 32 * 1024 };
    const logger = createBenchLogger();
    // Default configuration (no aggressive tuning), env can still override
    instances.push({
      name: 'SecureLRU',
      Factory: () => new SecureLRU(buildSecureOptions({ ...base, logger })),
    });
    // Tuned configuration; env can override further
    const tunedBase = {
      ...base,
      ttlAutopurge: true,
      ttlResolutionMs: 500,
      maxDeferredWipesPerFlush: 256,
      deferredWipeScheduler: 'auto',
      deferredWipeTimeoutMs: 1,
      deferredWipeAutoThreshold: 256,
      deferredWipeAutoBytesThreshold: 1024 * 1024,
      promoteOnGet: 'sampled',
      promoteOnGetSampleRate: 4,
      // Increase wipe queue caps in bench to avoid sync fallback noise under load
      maxWipeQueueBytes: 64 * 1024 * 1024,
      maxWipeQueueEntries: 100000,
      logger,
    };
    instances.push({
      name: 'SecureLRU (tuned)',
      Factory: () => new SecureLRU(buildSecureOptions(tunedBase)),
    });

    // Second-chance tuned variant
  const scMaxRot = getEnvInt('SC_MAX_ROT', 8);
  const tunedSegScan = getEnvInt('SEG_SCAN', 8);
    const tunedSecondChance = {
      ...tunedBase,
      recencyMode: 'second-chance',
      segmentedEvictScan: tunedSegScan,
      secondChanceMaxRotationsPerEvict: scMaxRot,
    };
    instances.push({
      name: 'SecureLRU (second-chance tuned)',
      Factory: () => new SecureLRU(buildSecureOptions(tunedSecondChance)),
    });

    // SIEVE tuned variant (canonical SIEVE)
    const tunedSieve = {
      ...tunedBase,
      recencyMode: 'sieve',
      segmentedEvictScan: tunedSegScan,
    };
    instances.push({
      name: 'SecureLRU (sieve tuned)',
      Factory: () => new SecureLRU(buildSecureOptions(tunedSieve)),
    });
  }

  // tiny-lru exports named `lru` and `LRU` (ESM). Prefer factory `lru(max)`.
  const maybeTiny = await tryImport('tiny-lru');
  if (maybeTiny) {
    if (typeof maybeTiny.lru === 'function') {
      instances.push({ name: 'tiny-lru', Factory: () => maybeTiny.lru(1000) });
    } else if (typeof maybeTiny.LRU === 'function') {
      instances.push({ name: 'tiny-lru', Factory: () => new maybeTiny.LRU(1000) });
    } else if (maybeTiny.default) {
      instances.push({ name: 'tiny-lru', Factory: () => new maybeTiny.default(1000) });
    }
  }

  // js-sieve: modern SIEVE implementation (optional)
  const maybeJsSieve = await tryImport('js-sieve');
  if (maybeJsSieve) {
    // The package exports a Sieve class constructor; support default and named exports
    const SieveClass = maybeJsSieve.Sieve || maybeJsSieve.default || maybeJsSieve;
    if (typeof SieveClass === 'function') {
      // js-sieve API: new Sieve(maxEntries)
      instances.push({ name: 'js-sieve', Factory: () => new SieveClass(1000) });
    }
  }

  // lru-cache exports class LRUCache (named). Constructor takes options object.
  const maybeLRU = await tryImport('lru-cache');
  if (maybeLRU) {
    const LRUClass = maybeLRU.LRUCache || maybeLRU.default || maybeLRU;
    if (typeof LRUClass === 'function') {
      instances.push({ name: 'lru-cache', Factory: () => new LRUClass({ max: 1000 }) });
    }
  }

  // quick-lru exports default constructor
  const maybeQuick = await tryImport('quick-lru');
  if (maybeQuick) {
    const Quick = maybeQuick.default || maybeQuick;
    if (typeof Quick === 'function') {
      instances.push({ name: 'quick-lru', Factory: () => new Quick({ maxSize: 1000 }) });
    }
  }

  // mnemonist exports LRUMap and LRUCache
  const maybeMnemo = await tryImport('mnemonist');
  if (maybeMnemo) {
    if (typeof maybeMnemo.LRUMap === 'function') {
      instances.push({ name: 'mnemonist', Factory: () => new maybeMnemo.LRUMap(1000) });
    } else if (typeof maybeMnemo.LRUCache === 'function') {
      instances.push({ name: 'mnemonist', Factory: () => new maybeMnemo.LRUCache(1000) });
    }
  }

  return instances;
}

async function singleRun() {
  // Optional profile name via env or argv[2]
  const argvProfile = process.argv[2] && !process.argv[2].startsWith('-') ? process.argv[2] : '';
  const PROFILE = process.env.PROFILE || argvProfile || '';
  const profileEnv = applyProfileEnv(PROFILE);
  // Apply computed profile env defaults if not already set
  for (const [k, v] of Object.entries(profileEnv)) {
    if (process.env[k] == null) process.env[k] = v;
  }

  const instances = await buildCacheInstances();
  if (!instances.length) {
    console.error('No cache libraries available to benchmark. Install tiny-lru, lru-cache, quick-lru, mnemonist, or build SecureLRU.');
    process.exit(1);
  }

  const allResults = {};
  // Allow value size to be tuned via env for more realistic workloads
  const VALUE_BYTES = Math.max(1, getEnvInt('VALUE_BYTES', 1024));
  const value = new Uint8Array(VALUE_BYTES);
  for (let i = 0; i < value.length; i++) value[i] = i & 0xff;

  for (const inst of instances) {
  console.log('Benchmarking', inst.name);
  const benchIterations = getEnvInt('BENCH_ITER', 2000);
  const bench = new Bench({ name: `${inst.name}-bench`, now: nowMs, iterations: benchIterations, warmup: true });
    const factory = inst.Factory;

    // Create one persistent cache per task for steady-state behavior
    const caches = {
      SET: factory(),
      GET: factory(),
      UPDATE: factory(),
      DELETE: factory(),
    };
    // Detect operation support to avoid adding tasks that would error
    const supports = {
      SET: caches.SET && typeof caches.SET.set === 'function',
      GET: caches.GET && typeof caches.GET.get === 'function',
      UPDATE: caches.UPDATE && typeof caches.UPDATE.set === 'function',
      DELETE:
        caches.DELETE && (typeof caches.DELETE.delete === 'function' || typeof caches.DELETE.remove === 'function'),
    };
  const KEYSPACE = getEnvInt('KEYSPACE', 10000);

    // Pre-populate GET/UPDATE/DELETE caches to stable occupancy with keys that match each task's prefix
    // This ensures GET/UPDATE/DELETE do not need to perform a SET inside the measured loop.
    for (let i = 0; i < Math.min(KEYSPACE, 20000); i++) {
      const gk = 'g' + i;
      const uk = 'u' + i;
      const dk = 'd' + i;
      try { caches.GET.set(gk, value); } catch (_e) {}
      try { caches.UPDATE.set(uk, value); } catch (_e) {}
      try { caches.DELETE.set(dk, value); } catch (_e) {}
    }

    // Best-effort: flush deferred wipes before timing to avoid background work skewing results
    try {
      for (const c of [caches.SET, caches.GET, caches.UPDATE, caches.DELETE]) {
        if (c && typeof c.flushWipesSync === 'function') {
          try { c.flushWipesSync(); } catch (_) {}
        }
      }
    } catch (_) {}

    if (supports.SET) {
      bench.add('SET', async () => {
        const cache = caches.SET;
        const k = 's' + Math.floor(Math.random() * KEYSPACE);
        const t0 = nowMs();
        cache.set(k, value);
        const t1 = nowMs();
        return { overriddenDuration: t1 - t0 };
      });
    }

    if (supports.GET) {
      bench.add('GET', async () => {
        const cache = caches.GET;
        const k = 'g' + Math.floor(Math.random() * KEYSPACE);
        const t0 = nowMs();
        cache.get(k);
        const t1 = nowMs();
        return { overriddenDuration: t1 - t0 };
      });
    }

    if (supports.UPDATE) {
      bench.add('UPDATE', async () => {
        const cache = caches.UPDATE;
        const k = 'u' + Math.floor(Math.random() * KEYSPACE);
        const t0 = nowMs();
        cache.set(k, value);
        const t1 = nowMs();
        return { overriddenDuration: t1 - t0 };
      });
    }

    if (supports.DELETE) {
      bench.add('DELETE', async () => {
        const cache = caches.DELETE;
        const k = 'd' + Math.floor(Math.random() * KEYSPACE);
        const t0 = nowMs();
        if (typeof cache.delete === 'function') cache.delete(k);
        else if (typeof cache.remove === 'function') cache.remove(k);
        const t1 = nowMs();
        // Re-insert to maintain steady occupancy after delete
        try { caches.DELETE.set(k, value); } catch (_e) {}
        return { overriddenDuration: t1 - t0 };
      });
    }

    await bench.run();

  const results = {};
    const benchTasks = bench.tasks || [];
    for (const bt of benchTasks) {
      const name = (bt && bt.name) || (bt && bt.id) || 'unknown';
      const r = (bt && (bt.result || bt.stats || bt.latency)) || null;
      const mean = r && (r.mean || (r.latency && r.latency.mean)) || null;
      const samples = Array.isArray(r && r.samples) ? r.samples : (Array.isArray(r && r.latency && r.latency.samples) ? r.latency.samples : []);
      const opsPerSec = (typeof mean === 'number' && mean > 0) ? Math.round(1000 / mean) : null;
      results[name] = { mean, samples: samples.length, opsPerSec };
      console.log(`  ${name} — mean: ${typeof mean === 'number' ? mean.toFixed(6) : '-'} ms  ops/sec: ${opsPerSec ? opsPerSec.toLocaleString() : '-'}  samples: ${samples.length}`);
    }
    // Mark unsupported tasks as skipped explicitly for clarity
    const taskNames = ['SET','GET','UPDATE','DELETE'];
    for (const tn of taskNames) {
      const already = Object.prototype.hasOwnProperty.call(results, tn);
      const isSupported = supports[tn];
      if (!already && !isSupported) {
        results[tn] = { mean: null, samples: 0, opsPerSec: null, skipped: true };
        console.log(`  ${tn} — skipped (unsupported)`);
      }
    }

    // Aggregate optional debug stats from SecureLRU instances (if available)
    try {
      const cachesArr = [caches.SET, caches.GET, caches.UPDATE, caches.DELETE].filter(Boolean);
      let sieveScans = 0, sieveRotations = 0, evictions = 0, expired = 0;
      let hadDebug = false;
      for (const c of cachesArr) {
        if (c && typeof c.getDebugStats === 'function') {
          const ds = c.getDebugStats();
          if (ds && typeof ds === 'object') {
            hadDebug = true;
            if (typeof ds.sieveScans === 'number') sieveScans += ds.sieveScans;
            if (typeof ds.sieveRotations === 'number') sieveRotations += ds.sieveRotations;
            if (typeof ds.evictions === 'number') evictions += ds.evictions;
            if (typeof ds.expired === 'number') expired += ds.expired;
          }
        } else if (c && typeof c.getStats === 'function') {
          // Fallback: try basic stats if debug not exposed
          const s = c.getStats();
          if (s && typeof s === 'object') {
            if (typeof s.evictions === 'number') evictions += s.evictions;
            if (typeof s.expired === 'number') expired += s.expired;
          }
        }
      }
      if (hadDebug || evictions || expired) {
        results._debug = { sieveScans, sieveRotations, evictions, expired };
      }
    } catch (_e) {
      // best-effort; ignore if third-party caches don't support stats
    }

    allResults[inst.name] = results;
    // small delay between libraries to reduce interference
    await new Promise(r => setTimeout(r, 250));
  }

  const _meta = {
    profile: PROFILE || null,
    env: {
      TTL_AUTOPURGE: (process.env.TTL_AUTOPURGE != null ? process.env.TTL_AUTOPURGE : null),
      TTL_RES_MS: (process.env.TTL_RES_MS != null ? process.env.TTL_RES_MS : null),
      PROMOTE_MODE: (process.env.PROMOTE_MODE != null ? process.env.PROMOTE_MODE : null),
      PROMOTE_RATE: (process.env.PROMOTE_RATE != null ? process.env.PROMOTE_RATE : null),
      RECENCY_MODE: (process.env.RECENCY_MODE != null ? process.env.RECENCY_MODE : null),
      SEG_SCAN: (process.env.SEG_SCAN != null ? process.env.SEG_SCAN : null),
      SEG_ROTATE_OPS: (process.env.SEG_ROTATE_OPS != null ? process.env.SEG_ROTATE_OPS : null),
      SC_MAX_ROT: (process.env.SC_MAX_ROT != null ? process.env.SC_MAX_ROT : null),
      // Wipe/deferred wipe knobs
      WIPE_FLUSH_MAX: (process.env.WIPE_FLUSH_MAX != null ? process.env.WIPE_FLUSH_MAX : null),
      WIPE_SCHED: (process.env.WIPE_SCHED != null ? process.env.WIPE_SCHED : null),
      WIPE_TIMEOUT_MS: (process.env.WIPE_TIMEOUT_MS != null ? process.env.WIPE_TIMEOUT_MS : null),
      WIPE_AUTO_THRESH: (process.env.WIPE_AUTO_THRESH != null ? process.env.WIPE_AUTO_THRESH : null),
      WIPE_AUTO_BYTES: (process.env.WIPE_AUTO_BYTES != null ? process.env.WIPE_AUTO_BYTES : null),
      // Copy-on-{get,set}
      COPY_ON_SET: (process.env.COPY_ON_SET != null ? process.env.COPY_ON_SET : null),
      COPY_ON_GET: (process.env.COPY_ON_GET != null ? process.env.COPY_ON_GET : null),
      // Cache sizing
      MAX_ENTRIES: (process.env.MAX_ENTRIES != null ? process.env.MAX_ENTRIES : null),
      MAX_BYTES: (process.env.MAX_BYTES != null ? process.env.MAX_BYTES : null),
      MAX_ENTRY_BYTES: (process.env.MAX_ENTRY_BYTES != null ? process.env.MAX_ENTRY_BYTES : null),
      VALUE_BYTES: (process.env.VALUE_BYTES != null ? process.env.VALUE_BYTES : null),
      KEYSPACE: (process.env.KEYSPACE != null ? process.env.KEYSPACE : null),
      // Bench control
      BENCH_ITER: (process.env.BENCH_ITER != null ? process.env.BENCH_ITER : null),
      BENCH_RUNS: (process.env.BENCH_RUNS != null ? process.env.BENCH_RUNS : null),
    },
    timestamp: new Date().toISOString(),
  };
  const payload = { _meta, ...allResults };
  const fn = path.join('benchmarks', `results-compare-lru-${Date.now()}.json`);
  await fs.writeFile(fn, JSON.stringify(payload, null, 2), 'utf8');
  console.log('Wrote', fn);
  return fn;
}

async function main() {
  const runs = Number(process.env.BENCH_RUNS || '5');
  const outFiles = [];
  for (let i = 0; i < runs; i++) {
    console.log(`\n=== Run ${i+1}/${runs} ===`);
    const fn = await singleRun();
    outFiles.push(fn);
    // pause to give system a moment
    await new Promise(r => setTimeout(r, 500));
  }
  console.log('Done runs. Files:', outFiles.join(', '));
}

main().catch(err => { console.error(err); process.exit(2); });
