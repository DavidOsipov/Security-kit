import { describe, it, expect, vi } from "vitest";
import * as fs from "fs";
import * as path from "path";
// dynamic import to avoid static type/tsconfig resolution issues in tests
const modPromise = import("../../scripts/generate-sbom");

describe("createSBOMAsync enrichment", () => {
  it("enriches components from npm registry (mocked)", async () => {
    // Mock global.fetch
    const fakeResp = {
      ok: true,
      json: async () => ({
        versions: {
          "1.0.0": {
            dist: { tarball: "https://example/t.tgz", shasum: "deadbeef" },
            repository: { url: "git+https://github.com/example/repo.git" },
          },
        },
      }),
    };
    // @ts-ignore
    global.fetch = vi.fn().mockResolvedValue(fakeResp);

    const tmp = fs.mkdtempSync(path.join(process.cwd(), "tmp-enrich-"));
    const pkg = {
      name: "tmp-enrich",
      version: "0.0.1",
      dependencies: { dep: "1.0.0" },
    };
    fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify(pkg));

    const mod: any = await modPromise;
    const sbom = await mod.createSBOMAsync(
      path.join(tmp, "package.json"),
      undefined,
      false,
      undefined,
      { enrich: true },
    );
    const dep: any = sbom.components.find((c: any) => c.name === "dep");
    expect(dep).toBeDefined();
    expect(dep!.externalReferences).toBeDefined();
    expect(
      dep!.externalReferences!.some((r: any) => r.type === "distribution"),
    ).toBe(true);
    expect(dep!.externalReferences!.some((r: any) => r.type === "vcs")).toBe(
      true,
    );
  }, 20000);
});
