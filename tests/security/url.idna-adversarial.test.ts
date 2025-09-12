import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { normalizeOrigin, createSecureURL } from "../../src/url";
import { setUrlHardeningConfig, getUrlHardeningConfig } from "../../src/config";

describe("Adversarial IDNA tests (pre-IDNA caps & Bidi)", () => {
  let saved = getUrlHardeningConfig();
  beforeEach(() => {
    saved = getUrlHardeningConfig();
  });
  afterEach(() => {
    setUrlHardeningConfig(saved as any);
  });

  it("rejects authority containing Bidi control characters even when IDNA enabled", () => {
    const provider = {
      toASCII: (s: string) => {
        // Pass config-time smoke tests used by validateIdnaProviderBehavior
        if (s === "пример.рф") return "xn--e1afmkfd.xn--p1ai";
        if (s === "bad host\u0000") return "badhost"; // sanitize control chars for smoke test
        // Default deterministic fallback: strip non-ASCII to 'x' and remove control chars/spaces
        return s.replace(/[\u0000-\u001f\u007f-\u009f\s]/g, "").replace(/[^\x00-\x7f]/g, "x");
      },
    } as any;
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider });
    // Insert RLO (U+202E) into hostname to simulate bidi control
    expect(() => normalizeOrigin("https://exa\u202Emple.com")).toThrow();
  });

  it("rejects authority longer than MAX_AUTHORITY_CHARS_PRE_IDNA", () => {
    const provider = {
      toASCII: (s: string) => {
        if (s === "пример.рф") return "xn--e1afmkfd.xn--p1ai";
        if (s === "bad host\u0000") return "badhost";
        return s.replace(/[\u0000-\u001f\u007f-\u009f\s]/g, "").replace(/[^\x00-\x7f]/g, "x");
      },
    } as any;
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider });
    const longHost = "a".repeat(1100) + ".com"; // exceeds 1024 cap
    expect(() => normalizeOrigin(`https://${longHost}`)).toThrow();
  });

  it("rejects hostname with too many labels (MAX_HOST_LABELS_PRE_IDNA)", () => {
    const provider = {
      toASCII: (s: string) => {
        if (s === "пример.рф") return "xn--e1afmkfd.xn--p1ai";
        if (s === "bad host\u0000") return "badhost";
        return s.replace(/[\u0000-\u001f\u007f-\u009f\s]/g, "").replace(/[^\x00-\x7f]/g, "x");
      },
    } as any;
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider });
    const labels = new Array(130).fill("a").join("."); // 130 > 127 cap
    expect(() => normalizeOrigin(`https://${labels}`)).toThrow();
  });

  it("rejects single label longer than MAX_SINGLE_LABEL_CHARS_PRE_IDNA", () => {
    const provider = {
      toASCII: (s: string) => {
        if (s === "пример.рф") return "xn--e1afmkfd.xn--p1ai";
        if (s === "bad host\u0000") return "badhost";
        return s.replace(/[\u0000-\u001f\u007f-\u009f\s]/g, "").replace(/[^\x00-\x7f]/g, "x");
      },
    } as any;
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider });
    const longLabel = "a".repeat(300); // exceeds 255 cap
    expect(() => normalizeOrigin(`https://${longLabel}.com`)).toThrow();
  });

  it("createSecureURL rejects URLs with authorities that would be pre-IDNA too long", () => {
    const provider = {
      toASCII: (s: string) => {
        if (s === "пример.рф") return "xn--e1afmkfd.xn--p1ai";
        if (s === "bad host\u0000") return "badhost";
        return s.replace(/[\u0000-\u001f\u007f-\u009f\s]/g, "").replace(/[^\x00-\x7f]/g, "x");
      },
    } as any;
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider });
    const longHost = "b".repeat(2000) + ".example";
    expect(() => createSecureURL(`https://${longHost}`)).toThrow();
  });
});
