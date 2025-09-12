import { it, expect } from "vitest";
import loadPostMessageInternals from "../helpers/vmPostMessageHelper.ts";

it("surfaces VM timeouts as explicit errors from __runInVmJson", () => {
  // Use an intentionally tiny timeout so the synchronous busy-loop inside the
  // VM will exceed it reliably on CI and local machines.
  const pm = loadPostMessageInternals({ timeoutMs: 5 });
  const res = pm.__runInVmJson(`
    // Busy loop to exceed VM timeout
    const start = Date.now();
    while (Date.now() - start < 100) {}
    return 'done';
  `);

  // The helper returns an error marker string when the VM throws; ensure we
  // got an error marker rather than a normal result.
  expect(
    typeof res === "string" &&
      (res.startsWith("__RUN_ERROR__") || /timed out/i.test(res)),
  ).toBe(true);
}, 30_000);
