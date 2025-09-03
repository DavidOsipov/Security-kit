// SPDX-License-Identifier: MIT
import { describe, expect, test } from "vitest";
import { getSecureRandomBytesSync, getSecureRandomInt } from "../../src/crypto";
import { secureWipe } from "../../src/utils";

function now() {
  return typeof performance !== "undefined" && performance.now
    ? performance.now()
    : Date.now();
}

function run(fn: () => void, samples = 200) {
  const out: number[] = [];
  for (let i = 0; i < samples; i++) {
    const t0 = now();
    fn();
    const t1 = now();
    out.push(t1 - t0);
  }
  return out;
}

function median(a: number[]) {
  const s = [...a].sort((x, y) => x - y);
  const m = Math.floor(s.length / 2);
  return s.length % 2 === 0 ? (s[m - 1] + s[m]) / 2 : s[m];
}

describe("crypto security perf", () => {
  test("getSecureRandomBytesSync throughput", () => {
    const samples = run(() => {
      getSecureRandomBytesSync(256);
    }, 300);
    const med = median(samples);
    expect(med).toBeLessThan(2);
  });

  test("getSecureRandomInt stress", async () => {
    const out: number[] = [];
    for (let i = 0; i < 200; i++) {
      const t0 = now();
      await getSecureRandomInt(0, 1000000);
      const t1 = now();
      out.push(t1 - t0);
    }
    const med = median(out);
    expect(med).toBeLessThan(10);
  }, 20000);

  test("secureWipe cost", () => {
    const buf = getSecureRandomBytesSync(1024);
    const samples = run(() => {
      secureWipe(buf);
    }, 200);
    const med = median(samples);
    expect(med).toBeLessThan(2);
  });
});
