import fs from "fs";
import path from "path";
import os from "os";
import { describe, it, expect, beforeEach, afterEach } from "vitest";

let tmpDir: string;
let repoRoot: string;

let resolveAndValidateUserPath: any;
let assertPathAllowed: any;
let atomicWriteFileSync: any;

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-test-"));
  // create a fake repo structure
  repoRoot = path.join(tmpDir, "repo");
  fs.mkdirSync(repoRoot, { recursive: true });

  // dynamic import of the script module exports
  const mod = await import("../../scripts/generate-sbom.ts");
  resolveAndValidateUserPath = mod.resolveAndValidateUserPath;
  assertPathAllowed = mod.assertPathAllowed;
  atomicWriteFileSync = mod.atomicWriteFileSync;
});

afterEach(() => {
  // recursive remove
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (e) {
    // ignore
  }
});

describe("generate-sbom path validation", () => {
  it("rejects paths that escape repository root via ..", () => {
    const outside = path.join(repoRoot, "..", "outside.txt");
    expect(() => resolveAndValidateUserPath(outside, repoRoot, "test")).toThrow(/outside of repository root|Refusing to operate/);
  });

  it("rejects symlink that points outside repo", () => {
    const outsideDir = path.join(tmpDir, "outside");
    fs.mkdirSync(outsideDir);
    const secretFile = path.join(outsideDir, "secret.txt");
    fs.writeFileSync(secretFile, "secret");

    const link = path.join(repoRoot, "linkdir");
    fs.symlinkSync(outsideDir, link, "dir");

    const candidate = path.join(link, "secret.txt");
    expect(() => resolveAndValidateUserPath(candidate, repoRoot, "test")).toThrow(/outside of repository root|Refusing to operate/);
  });

  it("allows files inside repo and atomicWriteFileSync writes safely", () => {
    const target = path.join(repoRoot, "out.txt");
    expect(() => atomicWriteFileSync(target, "data", repoRoot)).not.toThrow();
    expect(fs.readFileSync(target, "utf8")).toBe("data");
  });

  it("prevents atomic write when tmp path would escape repo", () => {
    // Create a dir outside and make the repo dir a symlink to it so tmp path constructed might escape
    const outsideDir = path.join(tmpDir, "outside2");
    fs.mkdirSync(outsideDir);
    const realRepo = path.join(outsideDir, "repo");
    fs.mkdirSync(realRepo);
    // make repoRoot point to a symlink that resolves outside
    const linkRepo = path.join(tmpDir, "linkrepo");
    fs.symlinkSync(realRepo, linkRepo, "dir");

    const target = path.join(linkRepo, "out.txt");
    // calling atomicWriteFileSync with allowedBase = linkRepo's parent should fail
    expect(() => atomicWriteFileSync(target, "data", path.join(tmpDir, "doesnotexist"))).toThrow(/outside of repository root|Refusing to write outside/);
  });
});
