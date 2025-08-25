#!/usr/bin/env node
/*
 SPDX-License-Identifier: MIT
 SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

 Hardened TypeScript SBOM generator.
 - Uses strong typing
 - Atomic writes (temp file + rename)
 - Uses crypto.randomUUID() when available, falls back to secure RNG
 - Validates package.json shape before use
 - Explicit exit codes and error messages
*/

// NOSONAR: This script performs explicit, conservative path validation and containment
// checks (see `resolveAndValidateUserPath` and `assertPathAllowed`) before any
// filesystem operations. Static analyzers may report path-traversal false positives
// because arguments are non-literal at call sites; those findings are intentional
// false positives here. See `docs/sbom-suppressions.md` for a full explanation.

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { fileURLToPath } from "url";

type PackageJSON = {
  name?: string;
  version?: string;
  description?: string;
  license?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

type SBOMComponent = {
  type: "library";
  "bom-ref": string;
  name: string;
  version: string;
  purl?: string;
  scope?: "required" | "optional";
  hashes?: Array<{ alg: string; content: string }>;
  externalReferences?: Array<{ type: string; url: string }>;
};

type SBOM = {
  bomFormat: "CycloneDX";
  specVersion: "1.4";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component: {
      type: "library";
      "bom-ref": string;
      name: string;
      version: string;
      description: string;
      licenses: Array<{ license: { id: string } }>;
      purl: string;
    };
  };
  components: SBOMComponent[];
};

function logInfo(...args: unknown[]) {
  // Small wrapper so it can be replaced with structured logging in future
  // Avoid printing secrets
  console.log(...args);
}

function logError(...args: unknown[]) {
  console.error(...args);
}

function exit(code: number): never {
  process.exit(code);
}

function safeReadJSON<T>(filePath: string, allowedBase?: string): T {
  // Synchronously read small JSON file with path validation
  const base = allowedBase || process.cwd();
  const safePath = resolveAndValidateUserPath(filePath, base, "json file path");
  // Make the validation explicit for static analyzers
  assertPathAllowed(safePath, base);
  // safePath is validated above to reside inside allowedBase
  // Explicitly allowed: reading a validated path inside repository root
   
  // NOSONAR: safePath was resolved and containment-checked via resolveAndValidateUserPath + assertPathAllowed
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- safePath validated above
  const raw = fs.readFileSync(safePath, { encoding: "utf8" });
  try {
    // JSON.parse is acceptable here inside a controlled script
    return JSON.parse(raw) as T;
  } catch (e) {
    throw new Error(
      `Invalid JSON in ${filePath}: ${e && (e as Error).message}`,
    );
  }
}

/**
 * Collect files recursively under a directory, returning sorted relative paths
 */
function collectFilesRecursively(root: string, allowedBase?: string): string[] {
  // Validate root is inside allowedBase to avoid traversal/symlink escapes
  const base = allowedBase || process.cwd();
  const safeRoot = resolveAndValidateUserPath(root, base, "collect root");
  assertPathAllowed(safeRoot, base);
  const files: string[] = [];
  const walk = (dir: string) => {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    for (const name of fs.readdirSync(dir)) {
      const pth = path.join(dir, name);
      if (isDirSync(pth)) {
        walk(pth);
      } else if (isFileSync(pth)) {
        const rel = path.relative(safeRoot, pth).replace(/\\/g, "/");
        files.push(rel);
      }
    }
  };
  walk(safeRoot);
  files.sort();
  return files;
}

function generateUUID(): string {
  // Prefer crypto.randomUUID when available (Node 14.17+/16+)
  if (typeof (crypto as any).randomUUID === "function") {
    try {
      return (crypto as any).randomUUID();
    } catch (e) {
      // fall through to deterministic path below
      logError(
        "crypto.randomUUID failed, falling back to secure RNG",
        (e as Error).message,
      );
    }
  }

  // Fallback: use randomFillSync to generate v4 UUID
  const buf = Buffer.alloc(16);
  crypto.randomFillSync(buf);
  buf[6] = (buf[6] & 0x0f) | 0x40;
  buf[8] = (buf[8] & 0x3f) | 0x80;
  const hex = buf.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function isSafeToken(s: unknown): s is string {
  return typeof s === "string" && s.length > 0 && !/\s/.test(s);
}

function assertNoNullBytes(s: string, name = "path") {
  if (s.indexOf("\0") !== -1)
    throw new Error(`Invalid ${name}: contains null byte`);
}

function isSafeRelativeFilename(s: unknown): s is string {
  // Allow simple filenames like sbom.json, package.json, no path separators or traversal
  // use \w to include letters/digits/underscore and allow dot/hyphen
  return typeof s === "string" && /^[\w.-]+$/.test(s) && !s.includes("..");
}

/**
 * Resolve a user-supplied path and ensure it resides within the repository root.
 * This defends against path traversal and symlink escapes by resolving real paths.
 */
export function resolveAndValidateUserPath(
  userPath: string,
  repoRoot: string,
  purpose = "user-supplied path",
) {
  if (!isSafeToken(userPath) && !path.isAbsolute(userPath)) {
    throw new Error(`Invalid ${purpose}: must be a non-empty path`);
  }
  assertNoNullBytes(userPath, purpose);

  // Make absolute relative to current working directory when needed
  const abs = path.isAbsolute(userPath)
    ? path.normalize(userPath)
    : path.resolve(process.cwd(), userPath);

  // Resolve symlinks to their real locations before checking containment
  let realAbs: string;
  let realRepo: string;
  try {
    // abs is derived from userPath and normalized above; resolve symlinks
   
  // NOSONAR: realpathSync on an already-normalized path; we validate containment below.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  realAbs = fs.realpathSync(abs);
  } catch (e: any) {
    // If realpath fails because the path doesn't exist, attempt to resolve the parent directory.
    // Only handle ENOENT; other errors should be rethrown to avoid hiding unexpected failures.
    const dir = path.dirname(abs);
    if (e && typeof e === "object" && (e as any).code === "ENOENT") {
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      realAbs = fs.existsSync(dir) ? fs.realpathSync(dir) : path.resolve(dir);
    } else {
      throw e;
    }
  }

  try {
   
  // NOSONAR: realpathSync on repository root; used only for containment checks.
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    realRepo = fs.realpathSync(repoRoot);
  } catch {
    realRepo = path.resolve(repoRoot);
  }

  const sep = path.sep;
  if (!(realAbs === realRepo || realAbs.startsWith(realRepo + sep))) {
    throw new Error(
      `Refusing to operate on ${purpose} outside of repository root`,
    );
  }

  // Recreate the absolute path under the repo root to avoid ../ style references
  return path.join(realRepo, path.relative(realRepo, path.resolve(abs)));
}

function buildPurl(name: string, version: string) {
  // npm package URL (purl) basic encoding
  // Keep minimal escaping: replace @ with %40 for scoped packages
  const safeName = name.replace(/^@/, "%40");
  return `pkg:npm/${safeName}@${version}`;
}

export function atomicWriteFileSync(
  targetPath: string,
  data: string,
  allowedBase?: string,
) {
  // Ensure we only write inside the allowed base (repository root by default)
  const base = allowedBase || path.join(getScriptDir(), "..");
  const safeTarget = resolveAndValidateUserPath(
    targetPath,
    base,
    "output path",
  );

  // Extra realpath containment check for static analyzers: ensure base real path
  let realBase: string;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    realBase = fs.realpathSync(base);
  } catch {
    realBase = path.resolve(base);
  }
  const realSafeTarget = path.resolve(safeTarget);
  if (
    !(
      realSafeTarget === realBase ||
      realSafeTarget.startsWith(realBase + path.sep)
    )
  ) {
    throw new Error("Refusing to write outside of repository root");
  }

  const dir = path.dirname(safeTarget);
  const name = path.basename(safeTarget);
  const tmpName = `${name}.${process.pid}.${Date.now()}.tmp`;
  const tmpPath = path.join(dir, tmpName);

  // Ensure directory exists inside repo root
  // Ensure directory exists inside repo root
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- dir derived from validated safeTarget
  fs.mkdirSync(dir, { recursive: true });

  // Controlled write to a repository path; use temp file then rename for atomicity.
  // Ensure tmpPath is inside realBase as well
  const realTmp = path.resolve(tmpPath);
  if (!(realTmp === realBase || realTmp.startsWith(realBase + path.sep))) {
    throw new Error("Temporary file path escapes repository root");
  }
  // Make checks explicit before writing to satisfy static analyzers
  assertPathAllowed(tmpPath, realBase);
   
  // NOSONAR: tmpPath is validated to be inside the repository root (assertPathAllowed + realpath checks).
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- tmpPath validated above
  fs.writeFileSync(tmpPath, data, { encoding: "utf8", mode: 0o600 });
   
  // NOSONAR: renaming a temp file to a validated destination inside the repository root is intentional and safe.
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- tmpPath and safeTarget validated above
  fs.renameSync(tmpPath, safeTarget);
}

function getScriptDir(): string {
  // Attempt to derive script directory in both ESM and CJS contexts.
  // ESM: import.meta.url is available
  try {
    // @ts-ignore runtime-only
    if (
      typeof import.meta !== "undefined" &&
      typeof (import.meta.url as string) === "string"
    ) {
      // @ts-ignore runtime-only
      return path.dirname(fileURLToPath(import.meta.url));
    }
  } catch {
    // fall through to CJS-like fallback
  }

  // Fallbacks: __dirname (if present) or derive from process.argv[1]
  if (typeof (globalThis as any).__dirname === "string")
    return (globalThis as any).__dirname;
  if (typeof process !== "undefined" && process.argv && process.argv[1])
    return path.dirname(process.argv[1]);
  return process.cwd();
}

function validatePackage(pkg: PackageJSON) {
  if (!pkg || typeof pkg !== "object")
    throw new Error("package.json content is not an object");
  if (!isSafeToken(pkg.name))
    throw new Error('package.json missing or invalid "name"');
  if (!isSafeToken(pkg.version))
    throw new Error('package.json missing or invalid "version"');
}

function parseArgs(argv: string[]) {
  const args = new Map<string, string | boolean>();
  // Use module-scoped flag sets to make the function body smaller.
  const argsLen = argv.length;
  let i = 0;
  while (i < argsLen) {
    /* eslint-disable-next-line security/detect-object-injection -- argv element is validated and only known flags are accepted below */
    const aRaw = argv[i];
    if (typeof aRaw !== "string") {
      i++;
      continue;
    }
    // Only accept explicit flags that begin with -- and are known to us.
    if (!aRaw.startsWith("--")) {
      i++;
      continue;
    }
    if (!isKnownFlag(aRaw)) {
      i++;
      continue;
    }
    const a = aRaw;
    if (MODULE_BOOLEAN_FLAGS.has(a)) {
      args.set(a.replace(/^--/, ""), true);
      i++;
      continue;
    }
    if (isValueFlag(a)) {
      const v = getNextValue(argv, i);
      if (v) {
        args.set(a.replace(/^--/, ""), v);
        i += 2;
        continue;
      }
    }
    i++;
  }
  return args;
}

function getNextValue(argv: string[], idx: number): string | undefined {
  const v = argv[idx + 1];
  if (typeof v === "string" && !v.startsWith("--")) return v;
  return undefined;
}

function safeVersionLookup(
  versionsObj: Record<string, any> | null,
  version: string,
) {
  if (!versionsObj || !isSafeRegistryToken(version)) return null;
  // Iterate entries and return the matching value without direct indexing
  for (const [k, v] of Object.entries(versionsObj)) {
    if (k === version) return v;
  }
  return null;
}

function extractRegistryMeta(body: any, version: string) {
  if (!body || typeof body !== "object") return null;
  const versions =
    body.versions && typeof body.versions === "object"
      ? (body.versions as Record<string, any>)
      : null;
  if (!isSafeRegistryToken(version)) return null;
  const ver = safeVersionLookup(versions, version);
  if (!ver || typeof ver !== "object") return null;
  const dist =
    ver.dist && typeof ver.dist === "object" ? (ver.dist as any) : {};
  let repo: string | undefined = undefined;
  if (
    ver.repository &&
    typeof ver.repository === "object" &&
    typeof (ver.repository as any).url === "string"
  )
    repo = (ver.repository as any).url;
  if (
    !repo &&
    body.repository &&
    typeof body.repository === "object" &&
    typeof (body.repository as any).url === "string"
  )
    repo = (body.repository as any).url;
  return {
    tarball: dist.tarball as string | undefined,
    shasum: dist.shasum as string | undefined,
    integrity: dist.integrity as string | undefined,
    repository: repo as string | undefined,
  };
}

function isSafeRegistryToken(s: unknown): s is string {
  return (
    typeof s === "string" &&
    s.length > 0 &&
    !/\s/.test(s) &&
    s.indexOf("\0") === -1
  );
}

// Module-scoped known flags
const MODULE_BOOLEAN_FLAGS = new Set(["--no-write", "--package-lock-only"]);
const MODULE_VALUE_FLAGS = new Set([
  "--package",
  "--out",
  "--provenance-commit",
  "--provenance-run-url",
  "--provenance-run-id",
  "--provenance-builder",
  "--tool-version",
  "--sbom-format",
]);

function isKnownFlag(s: string) {
  return MODULE_BOOLEAN_FLAGS.has(s) || MODULE_VALUE_FLAGS.has(s);
}

function isValueFlag(s: string) {
  return MODULE_VALUE_FLAGS.has(s);
}

/**
 * Assert that a candidate path resides inside allowedBase (or cwd by default).
 * This helper is intentionally conservative and tolerant of non-existing targets
 * (it resolves the parent directory when the target does not exist) so it can
 * be used before creating temp files.
 */
export function assertPathAllowed(candidate: string, allowedBase?: string) {
  const base = allowedBase || process.cwd();
  const abs = path.resolve(candidate);
  // Resolve base realpath if possible
  let realBase: string;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- base is repository-root derived
    realBase = fs.realpathSync(base);
  } catch {
    realBase = path.resolve(base);
  }

  // If candidate exists, resolve it; otherwise resolve its parent directory.
  let realCandidate: string;
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- candidate cleaned above
    realCandidate = fs.realpathSync(abs);
  } catch {
    // Parent directory resolution may succeed even if candidate does not exist
    const parent = path.dirname(abs);
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- parent is derived from candidate
      realCandidate = fs.realpathSync(parent);
    } catch {
      realCandidate = path.resolve(parent);
    }
  }

  const sep = path.sep;
  if (
    !(realCandidate === realBase || realCandidate.startsWith(realBase + sep))
  ) {
    throw new Error(
      `Refusing to operate on path outside of allowed base: ${candidate}`,
    );
  }
}

async function enrichComponentsInChunks(comps: SBOMComponent[], limit = 6) {
  for (let i = 0; i < comps.length; i += limit) {
    const chunk = comps.slice(i, i + limit);
    await Promise.all(
      chunk.map(async (c) => {
        try {
          const nameVer = c.purl!.replace(/^pkg:npm\//, "");
          const at = nameVer.lastIndexOf("@");
          const name =
            at > 0
              ? decodeURIComponent(nameVer.slice(0, at))
              : decodeURIComponent(nameVer);
          const ver = at > 0 ? nameVer.slice(at + 1) || c.version : c.version;
          if (!isSafeRegistryToken(name) || !isSafeRegistryToken(ver)) return;
          const meta = await fetchRegistryMetadata(name, ver);
          if (!meta) return;
          c.externalReferences = c.externalReferences || [];
          if (meta.tarball)
            c.externalReferences.push({
              type: "distribution",
              url: meta.tarball,
            });
          if (meta.repository)
            c.externalReferences.push({ type: "vcs", url: meta.repository });
          if (meta.shasum)
            c.externalReferences.push({ type: "shasum", url: meta.shasum });
          if (meta.integrity)
            c.externalReferences.push({
              type: "integrity",
              url: meta.integrity,
            });
        } catch {
          // best-effort
        }
      }),
    );
  }
}

/**
 * Process dependency map (Record<string,string>) or list of pairs and add components to sbom
 */
function processDependencies(
  sbom: SBOM,
  repoRoot: string,
  deps: Record<string, string> | Array<[string, string]> | undefined,
  scope: "required" | "optional",
  options?: CreateSBOMOptions,
) {
  if (!deps) return;
  const entries: Array<[string, string]> = Array.isArray(deps)
    ? deps
    : Object.entries(deps);
  for (const [name, version] of entries) {
    if (!isSafeToken(name) || !isSafeToken(version)) continue;
    const nameParts = name.split("/");
    const nmPath = path.join(repoRoot, "node_modules", ...nameParts);
    let hashes: Array<{ alg: string; content: string }> | undefined;
    if (!options?.packageLockOnly && isDirSync(nmPath)) {
      hashes = computeHashesForPath(nmPath, repoRoot);
    } else {
      hashes = [
        { alg: "SHA-512", content: sha512Hex(`${name}@${version}`) },
        { alg: "SHA-256", content: sha256Hex(`${name}@${version}`) },
      ];
      logInfo(
        `WARN: ${scope === "required" ? "package" : "dev package"} ${name} not found in node_modules or lock-only mode; falling back to name@version hash`,
      );
    }
    sbom.components.push(componentFromEntry(name, version, scope, hashes));
  }
}

function componentFromEntry(
  name: string,
  version: string,
  scope: "required" | "optional",
  hashes?: Array<{ alg: string; content: string }>,
): SBOMComponent {
  const bomRef = `${name}@${version}`;
  return {
    type: "library",
    "bom-ref": bomRef,
    name,
    version,
    purl: buildPurl(name, version),
    scope,
    hashes,
  };
}

function sha512Hex(data: Buffer | string) {
  return crypto.createHash("sha512").update(data).digest("hex");
}

function sha256Hex(data: Buffer | string) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function computeHashesForPath(targetPath: string, allowedBase?: string) {
  // Validate and resolve the target path to operate only within allowedBase
  const base = allowedBase || process.cwd();
  const p = resolveAndValidateUserPath(targetPath, base, "hash target path");
  assertPathAllowed(p, base);
  if (isFileSync(p)) {
    // Explicitly assert path is allowed for static analyzers
    assertPathAllowed(p, base);
   
  // NOSONAR: p is validated and contained within allowedBase by helpers above.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const content = fs.readFileSync(p);
    return [
      { alg: "SHA-512", content: sha512Hex(content) },
      { alg: "SHA-256", content: sha256Hex(content) },
    ];
  }

  if (isDirSync(p)) {
    const files = collectFilesRecursively(p, base);
    const h512 = crypto.createHash("sha512");
    const h256 = crypto.createHash("sha256");
    for (const rel of files) {
      h512.update(rel);
      h512.update("\0");
      h256.update(rel);
      h256.update("\0");
      const fpath = path.join(p, rel);
      // Make explicit to static analyzers that fpath is under allowed base
      assertPathAllowed(fpath, base);
   
  // NOSONAR: fpath is validated by assertPathAllowed to be inside allowedBase.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const data = fs.readFileSync(fpath);
      h512.update(data);
      h512.update("\0");
      h256.update(data);
      h256.update("\0");
    }
    return [
      { alg: "SHA-512", content: h512.digest("hex") },
      { alg: "SHA-256", content: h256.digest("hex") },
    ];
  }

  // Not found: return hashes of path string (deterministic fallback)
  return [
    { alg: "SHA-512", content: sha512Hex(targetPath) },
    { alg: "SHA-256", content: sha256Hex(targetPath) },
  ];
}

function isFileSync(p: string) {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function isDirSync(p: string) {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function computeHashForPath(targetPath: string, allowedBase?: string): string {
  const base = allowedBase || process.cwd();
  const p = resolveAndValidateUserPath(targetPath, base, "hash target path");
  assertPathAllowed(p, base);
  if (isFileSync(p)) {
   
  // NOSONAR: p validated above via resolveAndValidateUserPath + assertPathAllowed
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const content = fs.readFileSync(p);
    return sha512Hex(content);
  }

  if (isDirSync(p)) {
    const files = collectFilesRecursively(p, base);
    files.sort();
    const h = crypto.createHash("sha512");
    for (const rel of files) {
      h.update(rel);
      h.update("\0");
      // read file content
      const fpath = path.join(p, rel);
      assertPathAllowed(fpath, base);
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      h.update(fs.readFileSync(fpath));
      h.update("\0");
    }
    return h.digest("hex");
  }

  // Not found: return hash of path string (deterministic fallback)
  return sha512Hex(targetPath);
}

function main() {
  logInfo("📋 Generating Software Bill of Materials (SBOM)...");

  try {
    // Parse CLI args using a simple queue to avoid index reassignments
    const args = parseArgs(process.argv.slice(2));

    const scriptDir = getScriptDir();
    const repoRoot = path.join(scriptDir, "..");

    // Validate user-supplied package path to avoid path traversal
    const packagePathRaw = (args.get("package") as string) || "package.json";
    if (
      args.get("package") &&
      !isSafeRelativeFilename(args.get("package") as string)
    )
      throw new Error(
        "--package must be a simple filename (no path traversal)",
      );
    const packagePath = path.join(repoRoot, packagePathRaw);
    const packageData = safeReadJSON<PackageJSON>(packagePath, repoRoot);
    validatePackage(packageData);

    const prov: Provenance = {
      commit:
        (args.get("provenance-commit") as string) || process.env.GITHUB_SHA,
      runUrl:
        (args.get("provenance-run-url") as string) ||
        (process.env.GITHUB_SERVER_URL && process.env.GITHUB_RUN_ID
          ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
          : undefined),
      runId:
        (args.get("provenance-run-id") as string) || process.env.GITHUB_RUN_ID,
      builder:
        (args.get("provenance-builder") as string) || process.env.GITHUB_ACTOR,
      toolVersion: (args.get("tool-version") as string) || undefined,
    };

    const sbom = createSBOMWithOptions(packagePath, undefined, false, prov, {
      packageLockOnly: Boolean(args.get("package-lock-only")),
    });

    const outputPathRaw = (args.get("out") as string) || "sbom.json";
    if (args.get("out") && !isSafeRelativeFilename(args.get("out") as string))
      throw new Error("--out must be a simple filename (no path traversal)");
    const outputPath = path.join(repoRoot, outputPathRaw);

    // Write SBOM according to requested format
    // Default to writing all outputs (cyclonedx JSON + SPDX JSON + XML) when not specified
    const fmt = (args.get("sbom-format") as string) || "both";
    if (!Boolean(args.get("no-write"))) {
      const wantBoth =
        fmt.toLowerCase() === "both" || fmt.toLowerCase() === "all";
      if (fmt.toLowerCase() === "spdx") {
        const spdx = convertToSPDX(sbom);
        const outRaw =
          (args.get("out") as string) ||
          path.join(scriptDir, "..", "sbom.spdx.json");
        const out = resolveAndValidateUserPath(
          outRaw,
          repoRoot,
          "spdx output path",
        );
        atomicWriteFileSync(out, JSON.stringify(spdx, null, 2), repoRoot);
        logInfo(`✅ SPDX SBOM generated successfully at ${out}`);
      } else {
        // default: cyclonedx JSON
        const writeXml = wantBoth || fmt.toLowerCase() === "cyclonedx-xml";
        const writeSpdx = wantBoth;
        writeSBOMOutputs(sbom, outputPath, { writeSpdx, writeXml });
      }
    } else {
      logInfo("SKIP WRITE: --no-write provided; not writing sbom");
    }

    // Summary and exit
    logInfo(`📊 Components: ${sbom.components.length}`);
    logInfo(`🏷️  Package: ${packageData.name}@${packageData.version}`);
    exit(0);
  } catch (error) {
    logError(
      "❌ Failed to generate SBOM:",
      (error as Error).message || String(error),
    );
    exit(2);
  }
}
export type Provenance = {
  commit?: string;
  runUrl?: string;
  runId?: string;
  builder?: string;
  toolVersion?: string;
};

export function createSBOM(
  packagePath?: string,
  outPath?: string,
  write = false,
  provenance?: Provenance,
): SBOM {
  // NOTE: old signature supported no options; keep compatibility by overloading via any
  return createSBOMWithOptions(
    packagePath,
    outPath,
    write,
    provenance,
    undefined as any,
  );
}

export type CreateSBOMOptions = {
  packageLockOnly?: boolean;
  enrich?: boolean;
};

export function createSBOMWithOptions(
  packagePath?: string,
  outPath?: string,
  write = false,
  provenance?: Provenance,
  options?: CreateSBOMOptions,
): SBOM {
  const scriptDir = getScriptDir();
  const defaultRepoBase = path.join(scriptDir, "..");
  const pkgPathRaw = packagePath || path.join(defaultRepoBase, "package.json");

  // If the caller provided an explicit packagePath, validate it against its
  // own directory (tests create temporary repos outside of the workspace).
  // When no packagePath is provided, keep the strict check relative to the
  // repository root to avoid accidental traversal.
  let pkgPath: string;
  if (packagePath) {
    const abs = path.isAbsolute(pkgPathRaw)
      ? path.normalize(pkgPathRaw)
      : path.resolve(process.cwd(), pkgPathRaw);
    const pkgDir = path.dirname(abs);
    pkgPath = resolveAndValidateUserPath(abs, pkgDir, "package path");
  } else {
    pkgPath = resolveAndValidateUserPath(
      pkgPathRaw,
      defaultRepoBase,
      "package path",
    );
  }

  const packageData = safeReadJSON<PackageJSON>(pkgPath, path.dirname(pkgPath));
  validatePackage(packageData);

  const serialNumber = `urn:uuid:${generateUUID()}`;

  const sbom: SBOM = {
    bomFormat: "CycloneDX",
    specVersion: "1.4",
    serialNumber,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: "security-kit",
          name: "generate-sbom",
          version: provenance?.toolVersion || "1.0.0",
        },
      ],
      component: {
        type: "library",
        "bom-ref": `${packageData.name}@${packageData.version}`,
        name: packageData.name as string,
        version: packageData.version as string,
        description: packageData.description || "",
        licenses: packageData.license
          ? [{ license: { id: packageData.license } }]
          : [],
        purl: buildPurl(
          packageData.name as string,
          packageData.version as string,
        ),
      },
    },
    components: [],
  };

  if (provenance) {
    // Attach provenance under metadata.provenance for traceability
    // @ts-ignore - attach optional best-effort metadata
    (sbom as any).metadata.provenance = provenance;
  }

  const repoRoot = path.dirname(pkgPath);

  // If package-lock-only mode is requested, read package-lock.json and derive dependencies
  const lockDeps = options?.packageLockOnly
    ? parseLockfileDeps(repoRoot)
    : undefined;
  // Use helper to process both regular and dev dependencies
  processDependencies(
    sbom,
    repoRoot,
    lockDeps ?? packageData.dependencies,
    "required",
    options,
  );
  processDependencies(
    sbom,
    repoRoot,
    lockDeps ?? packageData.devDependencies,
    "optional",
    options,
  );

  addLocalFileHashes(sbom, repoRoot, packageData.version as string);

  if (write && outPath) {
    const safeOut = resolveAndValidateUserPath(outPath, repoRoot, "out path");
    atomicWriteFileSync(safeOut, JSON.stringify(sbom, null, 2), repoRoot);
  }

  return sbom;
}

function parseLockfileDeps(
  repoRoot: string,
): Array<[string, string]> | undefined {
  const lockPath = resolveAndValidateUserPath(
    path.join(repoRoot, "package-lock.json"),
    repoRoot,
    "package-lock path",
  );
  if (!isFileSync(lockPath)) return undefined;
  try {
    assertPathAllowed(lockPath, repoRoot);
   
  // NOSONAR: lockPath is resolved and containment-checked before reading.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8")) as any;
    const pairs: Array<[string, string]> = [];
    const traverse = (obj: any) => {
      if (!obj || typeof obj !== "object") return;
      if (obj.dependencies && typeof obj.dependencies === "object") {
        for (const [k, v] of Object.entries(obj.dependencies)) {
          if (
            isSafeToken(k) &&
            v &&
            typeof v === "object" &&
            typeof (v as any).version === "string" &&
            isSafeToken((v as any).version)
          ) {
            pairs.push([k, (v as any).version]);
          }
          traverse(v);
        }
      }
    };
    traverse(lock);
    return pairs;
  } catch (e) {
    logError(
      "Failed to parse package-lock.json for package-lock-only mode:",
      (e as Error).message,
    );
    return undefined;
  }
}

function addLocalFileHashes(sbom: SBOM, repoRoot: string, version: string) {
  const localFiles = [
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
  ];
  for (const f of localFiles) {
    const p = path.join(repoRoot, f);
    if (isFileSync(p)) {
      const hashes = computeHashesForPath(p, repoRoot);
      sbom.components.push({
        type: "library",
        "bom-ref": `file:${f}`,
        name: f,
        version,
        purl: `pkg:local/${f}`,
        scope: "required",
        hashes,
      });
    }
  }
}

/** Convert a CycloneDX-style SBOM produced by createSBOM into a basic SPDX-JSON document */
export function convertToSPDX(sbom: SBOM) {
  const created = sbom.metadata.timestamp;
  const tool = sbom.metadata.tools && sbom.metadata.tools[0];
  const doc: any = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `${sbom.metadata.component.name}@${sbom.metadata.component.version}`,
    documentNamespace: `http://spdx.org/spdxdocs/${sbom.metadata.component.name}-${sbom.metadata.component.version}-${generateUUID()}`,
    creationInfo: {
      created: created,
      creators: tool
        ? [`Tool: ${tool.vendor}/${tool.name}-${tool.version}`]
        : ["Tool: generate-sbom"],
    },
    documentDescribes: [
      `SPDXRef-Package-${sbom.metadata.component.name}-${sbom.metadata.component.version}`,
    ],
    packages: [] as any[],
    relationships: [] as any[],
  };

  // Root package
  doc.packages.push({
    name: sbom.metadata.component.name,
    SPDXID: `SPDXRef-Package-${sbom.metadata.component.name}-${sbom.metadata.component.version}`,
    versionInfo: sbom.metadata.component.version,
    packageFileName: "",
    description: sbom.metadata.component.description || "",
    primaryPackagePurpose: "LIBRARY",
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    homepage: "NOASSERTION",
    licenseDeclared:
      sbom.metadata.component.licenses && sbom.metadata.component.licenses[0]
        ? sbom.metadata.component.licenses[0].license.id
        : "NOASSERTION",
    externalRefs: [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: sbom.metadata.component.purl,
      },
    ],
  });

  // Components
  for (const c of sbom.components) {
    const pkgId = `SPDXRef-Package-${c.name}-${c.version}`;
    doc.packages.push({
      name: c.name,
      SPDXID: pkgId,
      versionInfo: c.version,
      packageFileName: c.purl?.startsWith("pkg:local/")
        ? c.purl.replace("pkg:local/", "")
        : c.purl || `node_modules/${c.name}`,
      description: "",
      primaryPackagePurpose: "LIBRARY",
      downloadLocation: c.purl
        ? `https://registry.npmjs.org/${c.name}/-/`
        : "NOASSERTION",
      filesAnalyzed: false,
      homepage: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: c.purl || "",
        },
      ],
      checksums: Array.isArray(c.hashes)
        ? c.hashes.map((h) => ({
            algorithm: h.alg.replace("-", "").toUpperCase(),
            checksumValue: h.content,
          }))
        : [],
    });

    // Relationship from root to this dep
    doc.relationships.push({
      spdxElementId:
        "SPDXRef-Package-" +
        sbom.metadata.component.name +
        "-" +
        sbom.metadata.component.version,
      relatedSpdxElement: pkgId,
      relationshipType: "DEPENDS_ON",
    });
  }

  return doc;
}

/**
 * Fetch metadata from npm registry for a package@version with a short timeout.
 * Returns object with tarball, shasum/integrity and repository URL when available.
 */
async function fetchRegistryMetadata(
  name: string,
  version: string,
  timeoutMs = 20000,
) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
  const body = await fetchJsonWithTimeout(url, timeoutMs);
  if (!body) return null;
  if (!isSafeRegistryToken(version)) return null;
  return extractRegistryMeta(body, version);
}

async function fetchJsonWithTimeout(url: string, timeoutMs: number) {
  const ac = new AbortController();
  const id = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ac.signal });
    if (!res.ok) return null;
    const body = await res.json();
    if (!body || typeof body !== "object") return null;
    return body;
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

/**
 * Asynchronously create SBOM and optionally enrich components from npm registry.
 */
export async function createSBOMAsync(
  packagePath?: string,
  outPath?: string,
  write = false,
  provenance?: Provenance,
  options?: CreateSBOMOptions,
): Promise<SBOM> {
  const sbom = createSBOMWithOptions(
    packagePath,
    outPath,
    write,
    provenance,
    options,
  );

  if (options?.enrich) {
    // Enrich components concurrently with a small concurrency limit
    const comps = sbom.components.filter(
      (c) => c.purl && c.purl.startsWith("pkg:npm/"),
    );
    const limit = 6;
    // process in chunks to limit concurrency without mutating in-flight queues
    for (let i = 0; i < comps.length; i += limit) {
      const chunk = comps.slice(i, i + limit);
      await Promise.all(
        chunk.map(async (c) => {
          try {
            const nameVer = c.purl!.replace(/^pkg:npm\//, "");
            const at = nameVer.lastIndexOf("@");
            const name =
              at > 0
                ? decodeURIComponent(nameVer.slice(0, at))
                : decodeURIComponent(nameVer);
            const ver = at > 0 ? nameVer.slice(at + 1) || c.version : c.version;
            const meta = await fetchRegistryMetadata(name, ver);
            if (meta) {
              c.externalReferences = c.externalReferences || [];
              if (meta.tarball)
                c.externalReferences.push({
                  type: "distribution",
                  url: meta.tarball,
                });
              if (meta.repository)
                c.externalReferences.push({
                  type: "vcs",
                  url: meta.repository,
                });
              if (meta.shasum)
                c.externalReferences.push({ type: "shasum", url: meta.shasum });
              if (meta.integrity)
                c.externalReferences.push({
                  type: "integrity",
                  url: meta.integrity,
                });
            }
          } catch {
            // Best-effort enrichment; ignore errors
          }
        }),
      );
    }
  }

  if (write && outPath) {
    atomicWriteFileSync(outPath, JSON.stringify(sbom, null, 2));
  }

  return sbom;
}

/** Convert CycloneDX SBOM to simple CycloneDX 1.4 XML string (basic mapping). */
export function convertToCycloneDxXml(sbom: SBOM): string {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const lines: string[] = [];
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push('<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">');
  lines.push("  <metadata>");
  lines.push(`    <timestamp>${esc(sbom.metadata.timestamp)}</timestamp>`);
  const tool = sbom.metadata.tools && sbom.metadata.tools[0];
  if (tool) {
    lines.push("    <tools>");
    lines.push(`      <tool>`);
    lines.push(`        <vendor>${esc(tool.vendor)}</vendor>`);
    lines.push(`        <name>${esc(tool.name)}</name>`);
    lines.push(`        <version>${esc(tool.version)}</version>`);
    lines.push("      </tool>");
    lines.push("    </tools>");
  }
  lines.push('    <component type="library">');
  lines.push(`      <name>${esc(sbom.metadata.component.name)}</name>`);
  lines.push(
    `      <version>${esc(sbom.metadata.component.version)}</version>`,
  );
  lines.push("    </component>");
  lines.push("  </metadata>");
  lines.push("  <components>");
  for (const c of sbom.components) {
    lines.push('    <component type="library">');
    lines.push(`      <name>${esc(c.name)}</name>`);
    lines.push(`      <version>${esc(c.version)}</version>`);
    if (Array.isArray(c.hashes) && c.hashes.length) {
      lines.push("      <hashes>");
      for (const h of c.hashes) {
        lines.push(
          `        <hash alg="${esc(h.alg)}">${esc(h.content)}</hash>`,
        );
      }
      lines.push("      </hashes>");
    }
    if (Array.isArray(c.externalReferences) && c.externalReferences.length) {
      lines.push("      <externalReferences>");
      for (const r of c.externalReferences) {
        lines.push("        <reference>");
        lines.push(`          <type>${esc(r.type)}</type>`);
        lines.push(`          <url>${esc(r.url)}</url>`);
        lines.push("        </reference>");
      }
      lines.push("      </externalReferences>");
    }
    lines.push("    </component>");
  }
  lines.push("  </components>");
  lines.push("</bom>");
  return lines.join("\n");
}

/**
 * Write SBOM outputs based on requested formats. Supports CycloneDX JSON (primary),
 * SPDX JSON, and CycloneDX XML. Uses atomic writes for safety.
 */
export function writeSBOMOutputs(
  sbom: SBOM,
  outPath: string,
  options?: { writeSpdx?: boolean; writeXml?: boolean },
) {
  // Always write CycloneDX JSON to outPath
  // Determine allowed base as repository root relative to script
  const base = path.join(getScriptDir(), "..");
  atomicWriteFileSync(outPath, JSON.stringify(sbom, null, 2), base);
  logInfo(`✅ CycloneDX SBOM generated successfully at ${outPath}`);

  if (options?.writeSpdx) {
    try {
      const spdx = convertToSPDX(sbom);
      const spdxOut = outPath.endsWith(".json")
        ? outPath.replace(/\.json$/, ".spdx.json")
        : outPath + ".spdx.json";
      atomicWriteFileSync(spdxOut, JSON.stringify(spdx, null, 2), base);
      logInfo(`✅ SPDX SBOM generated successfully at ${spdxOut}`);
    } catch (e) {
      logError("Failed to write SPDX SBOM:", (e as Error).message);
    }
  }

  if (options?.writeXml) {
    try {
      const xml = convertToCycloneDxXml(sbom);
      const xmlOut = outPath.endsWith(".json")
        ? outPath.replace(/\.json$/, ".xml")
        : outPath + ".xml";
      atomicWriteFileSync(xmlOut, xml, base);
      logInfo(`✅ CycloneDX XML SBOM generated successfully at ${xmlOut}`);
    } catch (e) {
      logError("Failed to write CycloneDX XML SBOM:", (e as Error).message);
    }
  }
}

// Execute main when run directly in both CJS and ESM contexts.
let runDirect = false;
// ESM environment has import.meta
try {
  if (typeof (globalThis as any).importMetaUrl !== "undefined") {
    // nothing: prefer import.meta check below
  }
} catch {
  // noop
}
// Check common cases: ESM (import.meta.url) or argv pointing to this script
if (
  typeof (globalThis as any).process !== "undefined" &&
  Array.isArray(process.argv)
) {
  const scriptArg = process.argv[1] || "";
  if (
    scriptArg.endsWith("scripts/generate-sbom.ts") ||
    scriptArg.endsWith("scripts/generate-sbom.js")
  )
    runDirect = true;
}

// In ESM, import.meta.url provides the current file URL; compare it with process.argv when present
try {
  if (
    typeof (globalThis as any).importMetaUrl !== "undefined" ||
    typeof (globalThis as any).process?.env?.NODE_OPTIONS !== "undefined"
  ) {
    // Best-effort: attempt to read import.meta.url when available (ESM)
    // @ts-ignore runtime-only check
    const meta = (globalThis as any).importMetaUrl ?? undefined;
    if (
      typeof meta === "string" &&
      (meta.endsWith("/scripts/generate-sbom.ts") ||
        meta.endsWith("/scripts/generate-sbom.js"))
    )
      runDirect = true;
  }
} catch {
  // ignore - best-effort only
}

if (runDirect) main();
