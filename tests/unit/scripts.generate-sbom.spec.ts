import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import {
  resolveAndValidateUserPath,
  atomicWriteFileSync,
} from "../../scripts/generate-sbom";

describe("scripts/generate-sbom helpers", () => {
  it("resolveAndValidateUserPath accepts paths inside repo root and rejects outside paths", () => {
    const repoTmp = fs.mkdtempSync(path.join(process.cwd(), "tmp-gensbom-"));
    try {
      const filePath = path.join(repoTmp, "pkg.json");
      fs.writeFileSync(
        filePath,
        JSON.stringify({ name: "x", version: "1.0.0" }),
      );

      // Absolute path inside repo root should resolve cleanly
      const resolved = resolveAndValidateUserPath(
        filePath,
        repoTmp,
        "test-path",
      );
      expect(path.resolve(resolved)).toBe(path.resolve(filePath));

      // A path outside the provided repo root must be rejected
      const outside = path.join(os.tmpdir(), `outside-${Date.now()}.txt`);
      expect(() => resolveAndValidateUserPath(outside, repoTmp)).toThrow();
    } finally {
      fs.rmSync(repoTmp, { recursive: true, force: true });
    }
  });

  it("atomicWriteFileSync writes atomically inside allowed base and refuses outside writes", () => {
    const repoTmp = fs.mkdtempSync(path.join(process.cwd(), "tmp-gensbom-"));
    try {
      const outPath = path.join(repoTmp, "out.txt");
      atomicWriteFileSync(outPath, "hello world", repoTmp);
      const read = fs.readFileSync(outPath, "utf8");
      expect(read).toBe("hello world");

      // Attempting to write outside the allowed base should throw
      const outside = path.join(os.tmpdir(), `evil-${Date.now()}.txt`);
      expect(() => atomicWriteFileSync(outside, "x", repoTmp)).toThrow();
    } finally {
      fs.rmSync(repoTmp, { recursive: true, force: true });
    }
  });
});
