import * as fs from "fs";
import * as path from "path";
import { describe, it, expect } from "vitest";
import {
  createSBOMWithOptions,
  writeSBOMOutputs,
} from "../../scripts/generate-sbom";

describe("generate-sbom CLI outputs", () => {
  it("writes cyclonedx JSON, SPDX JSON and CycloneDX XML when requested", () => {
    const tmp = fs.mkdtempSync(path.join(process.cwd(), "tmp-sbom-"));
    const outPath = path.join(tmp, "sbom.json");
    const sbom = createSBOMWithOptions(undefined, undefined, false, undefined, {
      packageLockOnly: true,
    });
    writeSBOMOutputs(sbom, outPath, { writeSpdx: true, writeXml: true });

    expect(fs.existsSync(outPath)).toBe(true);
    expect(fs.existsSync(outPath.replace(/\.json$/, ".spdx.json"))).toBe(true);
    expect(fs.existsSync(outPath.replace(/\.json$/, ".xml"))).toBe(true);

    // cleanup
    fs.rmSync(tmp, { recursive: true, force: true });
  });
});
