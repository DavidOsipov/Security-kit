import { describe, it, expect } from "vitest";
import { runStandaloneFuzzHarness } from "../../src/scripts/fuzz-harness";

describe("fuzz harness smoke (deterministic)", () => {
  it("runs a small deterministic harness with seed", async () => {
    const code = await runStandaloneFuzzHarness(20);
    expect(code).toBe(0);
  });
});
