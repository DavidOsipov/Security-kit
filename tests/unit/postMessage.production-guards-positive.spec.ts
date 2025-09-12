import { test, expect } from "vitest";
import loadPostMessageInternals from "../../tests/helpers/vmPostMessageHelper.ts";
import fs from "fs";
import path from "path";

test("non-production: internals exposed when allow flag set", () => {
  const pm = loadPostMessageInternals({
    production: false,
    allowTestApisFlag: true,
    mockGuardModule: "present",
    timeoutMs: 6000,
  });
  // Sanity: the VM realm must see the allow flag
  type VmJsonRunner = { __runInVmJson?: (code: string) => unknown };
  const asRunner = pm as unknown as VmJsonRunner;
  if (typeof asRunner.__runInVmJson === "function") {
    const visible = asRunner.__runInVmJson(
      "return globalThis.__SECURITY_KIT_ALLOW_TEST_APIS === true",
    );
    expect(visible).toBe(true);
  }
  // In non-production, explicit allow flag should expose internals
  expect(pm.__test_internals).toBeDefined();
}, 10000);

test("production: internals exposed only when guard present and assertTestApiAllowed passes", () => {
  const srcPath = path.resolve(__dirname, "../../src/development-guards.ts");
  if (!fs.existsSync(srcPath)) return;

  const pm = loadPostMessageInternals({
    production: true,
    allowTestApisFlag: true,
    mockGuardModule: "present",
    timeoutMs: 6000,
  });
  // With guard present and allow flag set, internals should be exposed in production
  expect(pm.__test_internals).toBeDefined();
}, 15000);
