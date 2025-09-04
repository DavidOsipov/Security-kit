// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  SecureLRUCache,
  asReadOnlyCache,
  type ReadOnlyCache,
} from "../../src/secure-cache";

describe("asReadOnlyCache", () => {
  it("exposes only read operations and hides mutators", () => {
    const c = new SecureLRUCache<string, Uint8Array>({ maxEntries: 4 });
    const ro: ReadOnlyCache<string, Uint8Array> = asReadOnlyCache(c);

    expect((ro as any).set).toBeUndefined();
    expect((ro as any).delete).toBeUndefined();

    const v = new Uint8Array([1, 2, 3]);
    c.set("k1", v);
    expect(ro.has("k1")).toBe(true);
    const got = ro.get("k1");
    expect(got).toBeInstanceOf(Uint8Array);
    expect(got && got[0]).toBe(1);

    const peeked = ro.peek("k1");
    expect(peeked && peeked[2]).toBe(3);
  });
});
