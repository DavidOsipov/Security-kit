import { describe, it, expect, beforeEach } from "vitest";
import { _redact } from "../../src/utils";
import { environment } from "../../src/environment";

describe("_redact breadth limits", () => {
  beforeEach(() => {
    environment.setExplicitEnv("development");
    environment.clearCache();
  });

  it("truncates large arrays and object keys", () => {
    const bigArray = Array.from({ length: 500 }, (_, i) => i);
    const out = _redact({ bigArray });
    const s = JSON.stringify(out);
    expect(s).toContain("__truncated");
  });

  it("counts symbol keys and limits object keys", () => {
    const obj: Record<string | symbol, unknown> = {};
    for (let i = 0; i < 200; i++) obj[`k${i}`] = i;
    const s = JSON.stringify(_redact(obj));
    expect(s).toContain("__additional_keys__");
  });
});
