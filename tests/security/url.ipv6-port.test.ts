// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { validateURL, normalizeOrigin } from "../../src/url";

// Ensures IPv6 bracketed hosts preserve port numbers across parsing and normalization.

describe("URL IPv6 + port handling", () => {
  it("preserves :port for bracketed IPv6 hosts", () => {
    const { ok, url } = validateURL("https://[2001:db8::1]:8443/path?q=1");
    expect(ok).toBe(true);
    expect(url!.host).toBe("[2001:db8::1]:8443");
    expect(url!.port).toBe("8443");
    const origin = normalizeOrigin("https://[2001:db8::1]:8443");
    expect(origin).toBe("https://[2001:db8::1]:8443");
  });

  it("handles IPv6 without port", () => {
    const { ok, url } = validateURL("https://[::1]/");
    expect(ok).toBe(true);
    expect(url!.host).toBe("[::1]");
    expect(url!.port).toBe("");
    const origin = normalizeOrigin("https://[::1]");
    expect(origin).toBe("https://[::1]");
  });
});
