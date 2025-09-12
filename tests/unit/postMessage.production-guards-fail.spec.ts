import { test, expect } from "vitest";
import loadPostMessageInternals from "../../tests/helpers/vmPostMessageHelper.ts";
import path from "path";

test(
  "internals remain undefined in production when guard module missing even with flags set",
  async () => {
    const pm = loadPostMessageInternals({
      production: true,
      allowTestApisFlag: true,
      mockGuardModule: "missing",
    });
    expect(pm.__test_internals).toBeUndefined();
  },
  10000,
);
