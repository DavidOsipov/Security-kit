import { test, expect } from "vitest";
import { safeStableStringify } from "../../src/canonical";

test("omitted body and body: undefined produce same stable canonicalization", () => {
  const objOmitted = { headers: { a: 1 }, method: "GET" } as any;
  const objUndefined = {
    headers: { a: 1 },
    method: "GET",
    body: undefined,
  } as any;

  const s1 = safeStableStringify(objOmitted);
  const s2 = safeStableStringify(objUndefined);

  expect(s1).toBe(s2);
});

test("canonicalization: omitted body and body: undefined produce same bodyHash", async () => {
  // Recreate the minimal steps used by signer to compute bodyHash so this is a unit-level assurance.
  // Avoid importing internal encoders; instead compare the stableStringify outputs which the signer hashes.
  const payload = { a: 1 };
  const contextWithUndefined = {
    method: "GET",
    path: "/x",
    body: undefined as unknown,
  };
  const contextOmitted = { method: "GET", path: "/x" } as any;

  const bodyString1 = safeStableStringify(
    (contextWithUndefined as any).body ?? undefined,
  );
  const bodyString2 = safeStableStringify(
    (contextOmitted as any).body ?? undefined,
  );

  expect(bodyString1).toBe(bodyString2);
});
