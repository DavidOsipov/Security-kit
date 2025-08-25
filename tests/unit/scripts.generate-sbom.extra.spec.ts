import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import { __test_helpers as _genHelpers } from "../../scripts/generate-sbom";
const helpers = _genHelpers as any;
const { generateUUID, collectFilesRecursively, safeVersionLookup, extractRegistryMeta } = helpers;

// The module exports internal helpers via __test_helpers for unit tests.

describe("scripts/generate-sbom extra helpers", () => {
  it("generateUUID returns string with hyphens", () => {
    const id = (generateUUID as any)();
    expect(typeof id).toBe("string");
    expect(id.includes("-")).toBeTruthy();
  });

  it("collectFilesRecursively returns files under a directory", () => {
    const repoTmp = fs.mkdtempSync(path.join(process.cwd(), "tmp-gensbom2-"));
    try {
      const sub = path.join(repoTmp, "a", "b");
      fs.mkdirSync(sub, { recursive: true });
      fs.writeFileSync(path.join(repoTmp, "root.txt"), "x");
      fs.writeFileSync(path.join(sub, "child.txt"), "y");

      const files = (collectFilesRecursively as any)(repoTmp, repoTmp);
      expect(files).toContain("root.txt");
      expect(files).toContain("a/b/child.txt");
    } finally {
      fs.rmSync(repoTmp, { recursive: true, force: true });
    }
  });

  it("safeVersionLookup and extractRegistryMeta handle missing inputs safely", () => {
    expect((safeVersionLookup as any)(null, "1.0.0")).toBeNull();
    expect((safeVersionLookup as any)({}, "")).toBeNull();
    expect((extractRegistryMeta as any)(null, "1.0.0")).toBeNull();
  });
});
