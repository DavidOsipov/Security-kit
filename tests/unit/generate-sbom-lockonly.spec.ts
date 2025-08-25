import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { createSBOMWithOptions } from "../../scripts/generate-sbom";

describe("generate-sbom package-lock-only mode", () => {
  it("uses package-lock.json to build dependency list when node_modules absent", () => {
    const tmp = fs.mkdtempSync(path.join(process.cwd(), "tmp-lockonly-"));
    const pkg = {
      name: "tmp-lockonly-test",
      version: "0.1.0",
    };
    const lock = {
      name: pkg.name,
      version: pkg.version,
      lockfileVersion: 2,
      dependencies: {
        leftpad: { version: "1.3.0" },
        subdep: {
          version: "0.0.1",
          dependencies: { nested: { version: "2.2.2" } },
        },
      },
    };

    fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify(pkg));
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify(lock));

    const sbom = createSBOMWithOptions(
      path.join(tmp, "package.json"),
      undefined,
      false,
      undefined,
      { packageLockOnly: true },
    );
    // Expect components include leftpad and subdep and nested
    const names = sbom.components.map((c) => c.name);
    expect(names).toContain("leftpad");
    expect(names).toContain("subdep");
    expect(names).toContain("nested");

    // Ensure their hashes are SHA-512 hex (fallback name@version hashed)
    for (const c of sbom.components) {
      if (["leftpad", "subdep", "nested"].includes(c.name)) {
        expect(c.hashes && c.hashes[0].alg).toBe("SHA-512");
        expect(typeof c.hashes![0].content).toBe("string");
        expect(c.hashes![0].content.length).toBeGreaterThan(10);
      }
    }
  });
});
