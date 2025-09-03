// SPDX-License-Identifier: MIT
import { describe, test, expect } from "vitest";
import DOMPurify from "isomorphic-dompurify";
import { Sanitizer, STRICT_HTML_POLICY_CONFIG } from "../../src/sanitizer";

function now() {
  return typeof performance !== "undefined" && performance.now
    ? performance.now()
    : Date.now();
}
function median(a: number[]) {
  const s = [...a].sort((x, y) => x - y);
  const m = Math.floor(s.length / 2);
  return s.length % 2 === 0 ? (s[m - 1] + s[m]) / 2 : s[m];
}

describe("sanitizer perf", () => {
  test("sanitize large payload repeatedly", { timeout: 60000 }, () => {
    const policies = { strict: STRICT_HTML_POLICY_CONFIG } as const;
    const s = new Sanitizer(DOMPurify as any, policies);
    const big =
      "<div>" +
      Array(0 | 1000)
        .fill("<p>safe</p>")
        .join("") +
      "</div>";
    const samples: number[] = [];
    // warmup first call
    s.getSanitizedString(big, "strict");
    // Keep sample count moderate to avoid noisy environments skewing results
    for (let i = 0; i < 120; i++) {
      const t0 = now();
      s.getSanitizedString(big, "strict");
      const t1 = now();
      samples.push(t1 - t0);
      if ((i & 31) === 0 && typeof (global as any).gc === "function")
        (global as any).gc();
    }
    const med = median(samples);
    // Relaxed threshold acknowledging DOMPurify cost on JS runtimes and shared CI hosts; median used
    // NOTE: Actual budget is enforced in E2E; this unit-level perf check is a guardrail only.
    expect(med).toBeLessThan(450);
  });
});
