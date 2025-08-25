import { describe, it, expect } from "vitest";
import { createSBOM, convertToSPDX } from "../../scripts/generate-sbom";
import path from "path";
import fs from "fs";
import os from "os";

describe("spdx conversion", () => {
  it("converts a generated SBOM to SPDX JSON with checksums", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-spdx-"));
    try {
      const pkg = {
        name: "spdx-test",
        version: "0.1.0",
        dependencies: { "fake-dep": "1.0.0" },
      };
      fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify(pkg));
      const dep = path.join(tmp, "node_modules", "fake-dep");
      fs.mkdirSync(dep, { recursive: true });
      fs.writeFileSync(path.join(dep, "index.js"), "console.log('x')\n");

      const sbom = createSBOM(
        path.join(tmp, "package.json"),
        undefined,
        false,
        { commit: "abc" },
      );
      const spdx = convertToSPDX(sbom);
      expect(spdx).toBeDefined();
      expect(spdx.packages).toBeInstanceOf(Array);
      // find the fake-dep package
      const found = spdx.packages.find((p: any) => p.name === "fake-dep");
      expect(found).toBeDefined();
      expect(Array.isArray(found.checksums)).toBe(true);
      expect(found.checksums[0].checksumValue).toMatch(/^[0-9a-f]{128}$/i);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
