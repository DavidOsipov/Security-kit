import { normalizeInputString, toCanonicalValue } from "../../src/canonical.ts";
import { describe, it, expect } from "vitest";

describe("URL Decoding Fix Test", () => {
  it("should properly decode URL-encoded bidirectional attacks before normalization", () => {
    // The specific attack payload from handover doc
    const urlEncodedAttack = "%E2%80%AEs%E2%80%8Bcr%E2%80%8Bi%E2%80%8Bpt%E2%80%AC";
    
    console.log("Testing URL-encoded attack:", urlEncodedAttack);
    
    // This should now decode the URL encoding BEFORE normalization and validation,
    // so the bidirectional characters (U+202E, U+202C) and invisible characters (U+200B) 
    // should be detected and cause the function to throw
    expect(() => {
      const result = normalizeInputString(urlEncodedAttack, "url-decode-test");
    }).toThrow();
  });

  it("should handle manual decoding to verify attack contains dangerous characters", () => {
    const urlEncodedAttack = "%E2%80%AEs%E2%80%8Bcr%E2%80%8Bi%E2%80%8Bpt%E2%80%AC";
    const decoded = decodeURIComponent(urlEncodedAttack);
    
    // Should contain bidirectional control characters
    expect(decoded).toContain("\u202E"); // RIGHT-TO-LEFT OVERRIDE
    expect(decoded).toContain("\u202C"); // POP DIRECTIONAL FORMATTING
    expect(decoded).toContain("\u200B"); // ZERO WIDTH SPACE
    
    console.log("Decoded attack characters:");
    for (let i = 0; i < decoded.length; i++) {
      const char = decoded[i];
      const codePoint = char.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0');
      console.log(`  [${i}] "${char}" U+${codePoint}`);
    }
  });

  it("should successfully detect dangerous characters in already decoded form", () => {
    // Test with the already-decoded form to verify our system detects these dangerous chars
    const decodedAttack = "\u202Es\u200Bcr\u200Bi\u200Bpt\u202C"; // Manually decoded form
    
    // This should definitely throw because it contains bidirectional and invisible characters
    expect(() => {
      const result = normalizeInputString(decodedAttack, "direct-attack-test");
    }).toThrow(/bidirectional|invisible|Trojan Source/i);
  });
});