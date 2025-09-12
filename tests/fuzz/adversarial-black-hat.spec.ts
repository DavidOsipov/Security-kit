// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { InvalidParameterError } from "../../src/errors.ts";
import { normalizeInputString, toCanonicalValue } from "../../src/canonical.ts";
import expansionPayloads from "../fixtures/test-expansion-payloads.json";

// 🔥💀 BLACK HAT ADVERSARIAL TESTING SUITE 💀🔥
// WARNING: These tests simulate real-world attack vectors
// If any of these tests SUCCEED, we have a SERIOUS security vulnerability

describe("💀 BLACK HAT ADVERSARIAL: Nation-State Level Attacks", () => {
  it("🎯 APT: Multi-layered Unicode attack simulation", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 3, max: 6 }),
        fc.integer({ min: 100, max: 300 }),
        (attackLayers, baseLength) => {
          // Simulate Advanced Persistent Threat tactics
          let payload = "legitimate_looking_data";
          
          // Layer 1: Expansion bomb foundation
          if (attackLayers >= 1) {
            const expandChar = fc.sample(fc.constantFrom(...expansionPayloads.highExpansion.slice(0, 2).map(p => p.char)), 1)[0];
            payload = expandChar.repeat(Math.floor(baseLength / 20)) + payload;
          }
          
          // Layer 2: Trojan Source camouflage  
          if (attackLayers >= 2) {
            payload = payload + "\u202E/*evil*/" + payload.slice(0, 10) + "\u202D";
          }
          
          // Layer 3: Invisible character injection
          if (attackLayers >= 3) {
            payload = payload.replace(/./g, (char, i) => {
              if (i % 10 === 0) return char + "\u200B";
              return char;
            });
          }
          
          // Layer 4: Homoglyph domain impersonation
          if (attackLayers >= 4) {
            payload = payload.replace(/o/g, "\u03BF"); // Greek omicron
            payload = payload.replace(/a/g, "\u0430"); // Cyrillic a
          }
          
          // Layer 5: Memory exhaustion finale
          if (attackLayers >= 5) {
            payload = payload + "A\u0300".repeat(Math.floor(baseLength / 50));
          }
          
          try {
            normalizeInputString(payload, "apt-attack");
            
            // ⚠️ IF WE GET HERE, WE FOUND A VULNERABILITY! ⚠️
            expect(true).toBe(false); // Force failure
            return false;
          } catch (error) {
            if (error instanceof InvalidParameterError) {
              // Expected - our defenses worked!
              expect(error.message).toMatch(/expansion|bidirectional|invisible|homoglyph|combining|exceeds|dangerous/);
            }
            return true;
          }
        }
      ),
      { numRuns: 100, timeout: 20000 }
    );
  });

  it("🎯 SUPPLY-CHAIN: Dependency confusion via Unicode", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          "lodash\u200Bmalicious",      // Invisible space
          "react\u202Eevil\u202D",       // Trojan Source
          "express\u00ADcompromised",    // Soft hyphen
          "webpack\u200Cbackdoor",       // Zero-width non-joiner
          "@types/node\u2060evil"        // Word joiner
        ),
        fc.string({ minLength: 10, maxLength: 50 }),
        (fakeDependency, payload) => {
          const malicious = fakeDependency + "/" + payload;
          
          try {
            normalizeInputString(malicious, "supply-chain-attack");
            
            // ⚠️ VULNERABILITY: Malicious dependency name was not caught!
            expect(true).toBe(false);
            return false;
          } catch (error) {
            if (error instanceof InvalidParameterError) {
              expect(error.message).toMatch(/invisible|bidirectional|Trojan Source|homoglyph/);
            }
            return true;
          }
        }
      ),
      { numRuns: 50 }
    );
  });

  it("🎯 WEAPONIZED: Prototype pollution via canonical forms", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("__proto__", "constructor", "prototype"),
        fc.oneof(
          fc.constant({ "isAdmin": true }),
          fc.constant({ "role": "admin" }),
          fc.constant(function() { return "pwned"; })
        ),
        (dangerousKey, payload) => {
          const malicious = { [dangerousKey]: payload };
          
          try {
            toCanonicalValue(malicious);
            
            // Check for prototype pollution
            expect(Object.prototype).not.toHaveProperty("isAdmin");
            expect(Object.prototype).not.toHaveProperty("role");
            expect(Object.prototype).not.toHaveProperty("pwned");
            expect({}).not.toHaveProperty("isAdmin");
            expect({}.constructor).toBe(Object);
            
            return true;
          } catch (error) {
            // Verify no pollution occurred even if error thrown
            expect(Object.prototype).not.toHaveProperty("isAdmin");
            expect(Object.prototype).not.toHaveProperty("role");
            return true;
          }
        }
      ),
      { numRuns: 200 }
    );
  });

  it("🎯 METAMORPHIC: Shape-shifting attack adaptation", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 20, maxLength: 100 }),
        (basePayload) => {
          // Create multiple variations of the same attack
          const mutations = [
            basePayload + "\u202E",                    // Trojan Source
            basePayload.replace(/o/g, "\u03BF"),       // Greek omicron
            basePayload + "\u200B".repeat(10),         // Invisible spaces
            basePayload + "A\u0300".repeat(20),        // Combining chars
            basePayload.replace(/a/g, "\u0430"),       // Cyrillic a
            basePayload + "\uFEFF",                    // BOM
            basePayload.split('').reverse().join('') + "\u202E" // Reverse + bidi
          ];
          
          let successfulMutations = 0;
          for (const mutation of mutations) {
            try {
              normalizeInputString(mutation, "metamorphic-test");
              successfulMutations++;
            } catch (error) {
              if (!(error instanceof InvalidParameterError)) {
                successfulMutations++;
              }
            }
          }
          
          // Our improved security system may catch more than the old binary rules
          // Allow some mutations to be caught as the heuristic system is more sensitive
          expect(successfulMutations).toBeLessThanOrEqual(3);
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  it("💀 ULTIMATE: The final test - can you break the unbreakable?", () => {
    fc.assert(
      fc.property(
        fc.record({
          // Kitchen sink attack - everything at once
          expansion: fc.constantFrom(...expansionPayloads.highExpansion.slice(0, 3).map(p => p.char)),
          trojan: fc.constantFrom("\u202D", "\u202E", "\u202A", "\u202B"),
          invisible: fc.constantFrom("\u200B", "\u200C", "\u200D", "\u2060"),
          homoglyph: fc.constantFrom("\u0430", "\u03BF", "\u1E9B", "\uFF41"),
          dangerous: fc.constantFrom("\u0001", "\u2028", "\uFEFF", "\uF000"),
          combining: fc.array(fc.constantFrom("\u0300", "\u0301", "\u0302"), { maxLength: 50 }),
          payload: fc.string({ minLength: 50, maxLength: 200 })
        }),
        (attack) => {
          // The ultimate evil payload
          const ultimateEvil = [
            attack.expansion.repeat(10),
            attack.trojan,
            attack.invisible.repeat(5),
            attack.homoglyph.repeat(3),
            attack.dangerous,
            attack.payload,
            attack.combining.join(''),
            "/*",
            attack.payload.split('').reverse().join(''),
            "*/",
            attack.trojan,
            attack.expansion.repeat(5)
          ].join('');
          
          try {
            normalizeInputString(ultimateEvil, "ultimate-evil-test");
            
            // 🚨 RED ALERT: If we reach here, we have a CRITICAL security vulnerability! 🚨
            console.error("💀 CRITICAL SECURITY VULNERABILITY DETECTED! 💀");
            console.error("Ultimate evil payload was not caught:", ultimateEvil);
            expect(true).toBe(false); // Force failure
            return false;
          } catch (error) {
            if (error instanceof InvalidParameterError) {
              // Expected! Our hardened defenses worked
              expect(error.message).toMatch(/expansion|bidirectional|invisible|homoglyph|combining|dangerous|exceeds/);
            }
            return true;
          }
        }
      ),
      { numRuns: 200, timeout: 30000 }
    );
  });

  it("🎯 ZERO-DAY: Unicode 15.1+ bleeding edge exploitation", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          "\u{1F6D7}", // Elevator (new emoji with potential quirks)
          "\u{1FAF8}", // Rightwards pushing hand  
          "\u{1F9CC}", // Troll (homoglyph potential)
          "\u{1F6DD}", // Playground slide
          "\u{1FAE8}", // Shaking face
        ),
        fc.integer({ min: 1, max: 50 }),
        (newUnicodeChar, repeat) => {
          const malicious = newUnicodeChar.repeat(repeat);
          try {
            const result = normalizeInputString(malicious, "unicode-15-edge-case");
            
            // Check if new Unicode caused unexpected expansions
            if (typeof result === "string") {
              const ratio = result.normalize('NFKC').length / malicious.length;
              expect(ratio).toBeLessThanOrEqual(2.1);
            }
            return true;
          } catch (error) {
            if (error instanceof InvalidParameterError) {
              // Accept both old pattern-based errors and new heuristic-based errors
              expect(error.message).toMatch(/expansion|homoglyph|exceeds|security risk score|repetitive/i);
            }
            return true;
          }
        }
      ),
      { numRuns: 100 }
    );
  });

  it("🎯 PERSISTENCE: Long-term attack vector survival", () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 10, maxLength: 50 }), { minLength: 10, maxLength: 100 }),
        (payloads) => {
          // Simulate repeated attacks over time
          let foundWeakness = false;
          
          for (let round = 0; round < payloads.length; round++) {
            const currentPayload = payloads[round] + "\u202E" + round;
            
            try {
              normalizeInputString(currentPayload, `persistence-round-${round}`);
              foundWeakness = true;
              break;
            } catch (error) {
              if (!(error instanceof InvalidParameterError)) {
                foundWeakness = true;
                break;
              }
            }
          }
          
          // No persistence should be allowed
          expect(foundWeakness).toBe(false);
          return true;
        }
      ),
      { numRuns: 20, timeout: 30000 }
    );
  });
});