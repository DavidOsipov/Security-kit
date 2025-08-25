import { describe, it, expect } from "vitest";
import { convertToCycloneDxXml } from "../../scripts/generate-sbom";

describe("convertToCycloneDxXml", () => {
  it("converts a minimal SBOM to CycloneDX XML", () => {
    const sbom: any = {
      metadata: {
        timestamp: "2025-08-25T00:00:00Z",
        tools: [{ vendor: "sec", name: "gen", version: "1.0" }],
        component: { name: "pkg", version: "1.2.3" },
      },
      components: [
        {
          name: "a",
          version: "0.1.0",
          hashes: [{ alg: "SHA-512", content: "abc" }],
        },
      ],
    };

    const xml = convertToCycloneDxXml(sbom);
    expect(xml).toContain("<bom");
    expect(xml).toContain("<components>");
    expect(xml).toContain("<name>a</name>");
    expect(xml).toContain('<hash alg="SHA-512">abc</hash>');
  });
});
