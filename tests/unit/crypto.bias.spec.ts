import { describe, it, expect } from "vitest";
import * as cryptoModule from "../../src/crypto";

// Simple chi-squared uniformity test helpers
function chiSquared(observed: number[], expected: number): number {
  let sum = 0;
  for (let i = 0; i < observed.length; i++) {
    const diff = observed[i] - expected;
    sum += (diff * diff) / expected;
  }
  return sum;
}

describe("crypto bias / uniformity checks (light)", () => {
  const RUN_HEAVY = process.env.RUN_BIAS === "1";

  it(
    "generateSecureStringSync: small-sample uniformity on 10-digit alphabet",
    { timeout: RUN_HEAVY ? 10 * 60 * 1000 : 60 * 1000 },
    () => {
      const alphabet = "0123456789"; // 10 symbols
      const samples = RUN_HEAVY ? 200000 : 20000; // heavy is gated
      const length = 8;
      const counts = new Array(alphabet.length).fill(0);
      for (let i = 0; i < samples; i++) {
        const s = cryptoModule.generateSecureStringSync(alphabet, length);
        // sample first character to simplify independence approx
        const ch = s[0];
        const idx = alphabet.indexOf(ch);
        if (idx >= 0) counts[idx]++;
      }
      const expected = samples / alphabet.length;
      const chi2 = chiSquared(counts, expected);
      // degrees of freedom = k-1 = 9; 99.9% critical value ~ 27.88
      // Use a conservative threshold for false positives in CI
      const threshold = 60;
      expect(chi2).toBeLessThan(threshold);
    },
  );

  it(
    "getSecureRandomInt: small-sample uniformity in [0,9]",
    { timeout: RUN_HEAVY ? 10 * 60 * 1000 : 60 * 1000 },
    async () => {
      const samples = RUN_HEAVY ? 200000 : 20000;
      const counts = new Array(10).fill(0);
      for (let i = 0; i < samples; i++) {
        const v = await cryptoModule.getSecureRandomInt(0, 9);
        counts[v]++;
      }
      const expected = samples / 10;
      const chi2 = chiSquared(counts, expected);
      const threshold = 60;
      expect(chi2).toBeLessThan(threshold);
    },
  );
});
