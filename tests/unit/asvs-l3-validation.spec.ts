import { normalizeInputString } from "../../src/canonical";
import { InvalidParameterError } from "../../src/errors";
import { describe, it, expect } from "vitest";

// NOTE: Option A refactor narrowed scope: normalizeInputString no longer performs
// multi-pass URL decoding or generic WAF tasks (e.g., <script> detection). Callers
// must decode percent-encoded input BEFORE passing it into normalization.

describe("Unicode Security: Direct Control / Bidi / Invisible Detection", () => {
  it("rejects raw Bidi + invisible control sequence", () => {
    const direct = "\u202Eabc\u200Bdef\u202C"; // RLO + ZERO WIDTH SPACE + PDF
    expect(() => normalizeInputString(direct, "direct-bidi"))
      .toThrow(InvalidParameterError);
  });

  it("rejects excessive combining marks", () => {
    const combining = "a" + "\u0301".repeat(10); // acute accents; limit enforced
    expect(() => normalizeInputString(combining, "combining"))
      .toThrow(InvalidParameterError);
  });

  it("allows benign ASCII", () => {
    expect(normalizeInputString("Hello-World_123", "benign")).toBe("Hello-World_123");
  });
});

describe("Unicode Security: Percent-Encoded Attack Handling (caller-decoded)", () => {
  it("detects controls AFTER caller decoding (recommended usage)", () => {
    const encoded = "%E2%80%AEs%E2%80%8Bcr%E2%80%8Bi%E2%80%8Bpt%E2%80%AC"; // contains RLO, ZWSP, PDF
    const decoded = decodeURIComponent(encoded);
    expect(() => normalizeInputString(decoded, "decoded-bidi"))
      .toThrow(/bidirectional|invisible|control/i);
  });

  it("does NOT decode URL encoding implicitly (defense-in-depth clarity)", () => {
    const encoded = "%E2%80%AE"; // RLO percent-encoded
    // Should treat as literal percent signs; no error
    expect(normalizeInputString(encoded, "encoded-literal")).toBe(encoded.normalize("NFKC"));
  });
});

describe("Unicode Security: Detection Metrics", () => {
  it("achieves 100% detection on curated Unicode-only malicious set", () => {
    const malicious = [
      "\u202Eabc\u202C", // Bidi override + PDF
      "\u200Ba\u200B", // zero-width surrounds
      decodeURIComponent("%E2%80%AEs%E2%80%8Bcr%E2%80%8Bi%E2%80%8Bpt%E2%80%AC"),
    ];
    let detected = 0;
    for (const attack of malicious) {
      try {
        normalizeInputString(attack, "metric");
      } catch {
        detected++;
      }
    }
    expect(detected).toBe(malicious.length);
  });
});