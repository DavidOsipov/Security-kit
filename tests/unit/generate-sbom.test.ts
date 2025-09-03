import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import {
  resolveAndValidateUserPath,
  atomicWriteFileSync,
  assertPathAllowed,
} from "../../scripts/generate-sbom";

const tmpDir = path.join(os.tmpdir(), `security-kit-test-${process.pid}`);

beforeEach(() => {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {}
  fs.mkdirSync(tmpDir, { recursive: true });
});

afterEach(() => {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {}
});

describe("generate-sbom helpers", () => {
  it("resolveAndValidateUserPath allows paths inside repo root and rejects outside", () => {
    const repoRoot = tmpDir;
    const inside = path.join(tmpDir, "file.txt");
    fs.writeFileSync(inside, "ok");
    const resolved = resolveAndValidateUserPath(inside, repoRoot, "test");
    expect(resolved).toContain(path.normalize(tmpDir));

    const outside = path.resolve("/etc/passwd");
    expect(() =>
      resolveAndValidateUserPath(outside, repoRoot, "test"),
    ).toThrow();
  });

  it("atomicWriteFileSync writes file atomically inside allowed base and rejects outside", () => {
    const repoRoot = tmpDir;
    const target = path.join(repoRoot, "out.json");
    atomicWriteFileSync(target, JSON.stringify({ ok: true }), repoRoot);
    const got = fs.readFileSync(target, "utf8");
    expect(got).toContain("ok");

    // Attempt to write outside base should throw
    const outside = path.join(path.sep, "tmp", `evil-${Date.now()}.json`);
    expect(() => atomicWriteFileSync(outside, "x", repoRoot)).toThrow();
  });

  it("assertPathAllowed throws for paths outside allowed base", () => {
    const base = tmpDir;
    const allowed = path.join(tmpDir, "a.txt");
    fs.writeFileSync(allowed, "x");
    expect(() => assertPathAllowed(allowed, base)).not.toThrow();
    expect(() =>
      assertPathAllowed(path.resolve("/etc/passwd"), base),
    ).toThrow();
  });
});
