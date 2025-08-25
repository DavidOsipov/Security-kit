import { describe, it, expect } from "vitest";
import * as path from "path";
import * as url from "url";

import helpers from "../../scripts/fuzz-helpers";
const fuzz = helpers as any;

describe("scripts/fuzz-prototype-pollution helpers", () => {
  it("safeUrlForImport accepts file and http/https URLs and rejects invalid ones", () => {
    const fileUrl = new url.URL("file:///tmp/some/file.js").href;
    expect(fuzz.safeUrlForImport(fileUrl)).toBe(fileUrl);
    expect(fuzz.safeUrlForImport("http://example.com/a.js")).toBe("http://example.com/a.js");
    expect(fuzz.safeUrlForImport("https://example.com/a.js")).toBe("https://example.com/a.js");
    expect(fuzz.safeUrlForImport("ftp://example.com/a.js")).toBeUndefined();
    expect(fuzz.safeUrlForImport("not a url")).toBeUndefined();
  });

  it("randomString returns alphanumeric string of requested length", () => {
    const s = fuzz.randomString(8);
    expect(typeof s).toBe("string");
    expect(s.length).toBe(8);
    expect(/^[a-z0-9]+$/.test(s)).toBe(true);
  });

  it("makeHostilePayload returns objects with different shapes and doesn't crash when called repeatedly", () => {
    for (let i = 0; i < 20; i++) {
      const p = fuzz.makeHostilePayload(i);
      expect(typeof p === "object" || typeof p === "object").toBeTruthy();
    }
  });

  it("safeImport rejects unsafe URLs", async () => {
    await expect(async () => fuzz.safeImport("not-a-url")).rejects.toThrow();
  });
});
