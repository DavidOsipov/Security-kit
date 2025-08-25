import { describe, it, expect } from "vitest";
import { setupDOMPurify } from "../setup/domPurify";
import { Sanitizer, STRICT_HTML_POLICY_CONFIG } from "../../src/sanitizer";

describe("Sanitizer integration (jsdom + dompurify)", () => {
  it("creates a Trusted Types policy when window.trustedTypes is available and sanitizes", () => {
    const { DOMPurify, cleanup } = setupDOMPurify();
    const sanitizer = new Sanitizer(DOMPurify, {
      strict: STRICT_HTML_POLICY_CONFIG,
    });

    const policy = sanitizer.createPolicy("strict");
    expect(policy).toHaveProperty("createHTML");

    const dirty = "<img src=x onerror=alert(1)//>";
    const sanitized = sanitizer.sanitizeForNonTTBrowsers(dirty, "strict");
    expect(typeof sanitized).toBe("string");
    expect(sanitized).not.toContain("onerror");

    cleanup();
  });
});
