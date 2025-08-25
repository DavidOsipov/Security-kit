import { describe, it, expect } from "vitest";
import { createSBOM } from "../../scripts/generate-sbom";
import path from "path";
import fs from "fs";
import os from "os";

describe("generate-sbom", () => {
  it("creates an SBOM object with SHA-512 hashes for components and files (small repo)", () => {
    // Create temporary repo layout to avoid hashing entire workspace
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-test-"));
    try {
      // minimal package.json
      const pkg = {
        name: "sbom-test-pkg",
        version: "0.0.1",
        dependencies: {
          "fake-dep": "1.2.3",
        },
      } as const;
      fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify(pkg));

      // create small node_modules/fake-dep/index.js
      const depDir = path.join(tmp, "node_modules", "fake-dep");
      fs.mkdirSync(depDir, { recursive: true });
      fs.writeFileSync(
        path.join(depDir, "index.js"),
        "console.log('hello');\n",
      );

      const sbom = createSBOM(path.join(tmp, "package.json"), undefined, false);
      expect(sbom).toBeDefined();
      expect(sbom.components).toBeInstanceOf(Array);

      const withHashes = sbom.components.filter(
        (c) => Array.isArray((c as any).hashes) && (c as any).hashes.length > 0,
      );
      expect(withHashes.length).toBeGreaterThan(0);

      for (const comp of withHashes) {
        const hashes = (comp as any).hashes as Array<{
          alg: string;
          content: string;
        }>;
        expect(hashes[0].alg).toBe("SHA-512");
        expect(hashes[0].content).toMatch(/^[0-9a-f]{128}$/i);
      }
    } finally {
      // cleanup
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }, 20000);
});
