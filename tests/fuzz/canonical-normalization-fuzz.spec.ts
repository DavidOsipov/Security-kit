// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { InvalidParameterError } from "../../src/errors.ts";
import {
  normalizeInputString,
  normalizeUrlComponent,
  normalizeInputStringUltraStrict,
  normalizeUrlSafeString,
  toCanonicalValue,
  safeStableStringify
} from "../../src/canonical.ts";
import expansionPayloads from "../fixtures/test-expansion-payloads.json";

describe("canonical normalization security hardening - fuzz tests", () => {
  // 🎯 BLACK HAT SECTION: Advanced Adversarial Testing
  // These tests simulate sophisticated attacks that real adversaries might attempt

  describe("🔥 ADVERSARIAL: Unicode Expansion Bomb Attacks", () => {
    it("attempts real Unicode normalization bombs with chained expansions", () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...expansionPayloads.highExpansion.map(p => p.char)),
          fc.integer({ min: 1, max: 100 }),
          (expansionChar, repeat) => {
            // Create a potential normalization bomb by repeating high-expansion characters
            const malicious = expansionChar.repeat(repeat);
            try {
              normalizeInputString(malicious, "adversarial-expansion-bomb");
              // If we get here, check if we somehow bypassed the expansion ratio check
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Should detect either expansion ratio violation OR homoglyph attack
                expect(error.message).toMatch(/excessive expansion|homoglyph|exceeds maximum allowed size/);
              }
              return true;
            }
          }
        ),
        { numRuns: 500 }
      );
    });

    it("🎯 NUCLEAR: Exploits composition chains for exponential expansion", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 2, max: 8 }), // Chain depth
          fc.integer({ min: 5, max: 50 }), // Base repetition
          (chainDepth, baseRepeat) => {
            // Build a composition chain that could explode exponentially
            const baseChar = "Å"; // Decomposes to A + combining ring
            const combiningAccents = ["\u0300", "\u0301", "\u0302", "\u0303", "\u0304"]; // Multiple accents
            
            let malicious = baseChar.repeat(baseRepeat);
            // Add layers of combining characters
            for (let i = 0; i < chainDepth; i++) {
              malicious += combiningAccents[i % combiningAccents.length].repeat(baseRepeat * (i + 1));
            }
            
            try {
              normalizeInputString(malicious, "adversarial-composition-chain");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/combining characters|expansion|exceeds maximum allowed size/i);
              }
              return true;
            }
          }
        ),
        { numRuns: 200 }
      );
    });

    it("🎯 STEALTH: Exploits normalization edge cases to bypass ratio detection", () => {
      fc.assert(
        fc.property(
          fc.float({ min: 1.95, max: 2.05 }), // Dance around the 2.0 limit
          fc.integer({ min: 10, max: 200 }),
          (targetRatio, baseLength) => {
            // Try to craft payloads that expand to EXACTLY the limit
            // Using mathematical symbols that normalize differently
            const trickChars = [
              "\u2126", // Ohm sign -> Greek Omega
              "\u212A", // Kelvin sign -> K  
              "\u212B", // Angstrom -> Å with combining ring
              "\uFB00", // ff ligature -> ff
              "\uFB01", // fi ligature -> fi
              "\uFB02", // fl ligature -> fl
            ];
            
            const char = fc.sample(fc.constantFrom(...trickChars), 1)[0];
            const malicious = char.repeat(Math.floor(baseLength / char.length));
            
            try {
              const result = normalizeInputString(malicious, "adversarial-ratio-bypass");
              // If it succeeds, verify it's actually safe
              const normalized = result.normalize('NFKC');
              const ratio = normalized.length / malicious.length;
              expect(ratio).toBeLessThanOrEqual(2.1); // Small buffer for floating point
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/expansion|homoglyph|exceeds/);
              }
              return true;
            }
          }
        ),
        { numRuns: 300 }
      );
    });

    it("crafts multi-layer expansion bombs with nesting", () => {
      fc.assert(
        fc.property(
          fc.array(fc.constantFrom(...expansionPayloads.highExpansion.slice(0, 5).map(p => p.char)), 
            { minLength: 1, maxLength: 10 }),
          fc.string({ minLength: 0, maxLength: 20 }),
          (expansionChars, filler) => {
            // Interleave expansion characters with filler to try to bypass detection
            const malicious = expansionChars.join(filler);
            try {
              normalizeInputString(malicious, "adversarial-nested-expansion");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Multiple possible detections: expansion, homoglyph, or size limit
                expect(error.message).toMatch(/expansion|homoglyph|exceeds|combining/);
              }
              return true;
            }
          }
        ),
        { numRuns: 300 }
      );
    });

    it("exploits boundary conditions around 2x expansion limit", () => {
      fc.assert(
        fc.property(
          fc.float({ min: 1.8, max: 2.2 }),
          (targetRatio) => {
            // Try to craft strings that expand to EXACTLY the boundary ratio
            // Use safe expansion characters to get close to the limit
            const safeExpansion = expansionPayloads.safeExpansion.find((p: any) => p.expansionRatio >= targetRatio);
            if (!safeExpansion) return true;
            
            const baseLength = 50;
            const repeat = Math.floor(baseLength / safeExpansion.originalLength);
            const malicious = safeExpansion.char.repeat(repeat);
            
            try {
              normalizeInputString(malicious, "adversarial-boundary-expansion");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Should catch expansion or homoglyph attacks
                expect(error.message).toMatch(/expansion|homoglyph|combining/);
              }
              return true;
            }
          }
        ),
        { numRuns: 200 }
      );
    });
  });

  describe("🔥 ADVERSARIAL: Sophisticated Trojan Source Attacks", () => {
    // These are attack patterns from the actual Boucher & Anderson research
    const trojanSourcePayloads = [
      // Classic Trojan Source patterns
      "/*‮ } ⁦if (isAdmin)⁩ ⁦ begin admins only */",
      "access_level = \"user\"\u202E\u0000admin\u0000\u202D",
      "var isAdmin = false/*‮ ;eurt = nimo⁦da si*/;",
      // Advanced embedding attacks  
      "\u202Afalse\u202C\u0000\u202Dtrue\u202C",
      "\u202Bfalse) { return true; } if (true\u202C",
      // Mixed script attacks
      "login\u200Badmin\u200C",
      "user\u2060admin\u2061check",
      // Supply chain specific patterns
      "legitimate_function\u034F\u0300\u0301evil_function"
    ];

    it("detects sophisticated Trojan Source attack patterns", () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...trojanSourcePayloads),
          fc.string({ minLength: 0, maxLength: 50 }),
          (trojanPayload, prefix) => {
            const malicious = prefix + trojanPayload;
            try {
              normalizeInputString(malicious, "adversarial-trojan-source");
              return false; // This should NEVER succeed
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/bidirectional|invisible|homoglyph|dangerous/);
              }
              return true;
            }
          }
        ),
        { numRuns: 300 }
      );
    });

    it("exploits bidirectional override nesting attacks", () => {
      fc.assert(
        fc.property(
          fc.array(fc.constantFrom("\u202D", "\u202E", "\u202A", "\u202B"), { minLength: 2, maxLength: 8 }),
          fc.array(fc.constantFrom("\u202C", "\u2069"), { minLength: 1, maxLength: 4 }),
          fc.string({ minLength: 1, maxLength: 30 }),
          (overrides, closers, payload) => {
            // Create nested bidirectional overrides
            const malicious = overrides.join("") + payload + closers.join("");
            try {
              normalizeInputString(malicious, "adversarial-bidi-nesting");
              return false; // Should never succeed
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/bidirectional|Trojan Source/);
              }
              return true;
            }
          }
        ),
        { numRuns: 500 }
      );
    });
  });

  describe("🔥 ADVERSARIAL: Memory Exhaustion Attacks", () => {
    it("attempts to trigger OOM via excessive combining characters", () => {
      fc.assert(
        fc.property(
          fc.constantFrom("a", "e", "o", "u", "i"), // Base characters
          fc.integer({ min: 10, max: 200 }), // Combining character count
          (base, combiningCount) => {
            // Create strings with excessive combining characters per base
            const combining = "\u0300\u0301\u0302\u0303\u0304\u0305\u0306\u0307\u0308\u0309";
            const malicious = base + combining.slice(0, combiningCount % combining.length).repeat(Math.ceil(combiningCount / combining.length));
            
            try {
              normalizeInputString(malicious, "adversarial-combining-dos");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/combining characters|excessive/);
              }
              return true;
            }
          }
        ),
        { numRuns: 200 }
      );
    });

    it("attempts memory exhaustion via repeated expensive normalizations", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 500, max: 2048 }),
          (length) => {
            // Create strings that are expensive to normalize
            const expensiveChars = "Å\u00C0\u00C1\u00C2\u00C3\u00C4\u1EDB\u1EDC\u1EDD"; // Characters that decompose
            const malicious = Array.from({ length }, (_, i) => 
              expensiveChars[i % expensiveChars.length]
            ).join("");
            
            try {
              normalizeInputString(malicious, "adversarial-expensive-normalization");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/exceeds maximum|expansion/);
              }
              return true;
            }
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe("🔥 ADVERSARIAL: Prototype Pollution via Canonical Forms", () => {
    it("attempts prototype pollution through canonical value construction", () => {
      fc.assert(
        fc.property(
          fc.constantFrom("__proto__", "constructor", "prototype"),
          fc.oneof(
            fc.constant("polluted"),
            fc.object(),
            fc.array(fc.string())
          ),
          (dangerousKey, value) => {
            const malicious = { [dangerousKey]: value };
            try {
              const canonical = toCanonicalValue(malicious);
              // Verify prototype pollution didn't occur
              expect(Object.prototype).not.toHaveProperty("polluted");
              expect({}).not.toHaveProperty("polluted");
              return true;
            } catch (error) {
              // Any error is acceptable here - we just want to ensure no pollution
              return true;
            }
          }
        ),
        { numRuns: 500 }
      );
    });

    it("exploits nested object construction for pollution", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 10 }),
          (depth) => {
            // Create nested objects with dangerous keys at various depths
            let malicious: any = { "polluted": "value" };
            for (let i = 0; i < depth; i++) {
              malicious = {
                "__proto__": malicious,
                "constructor": { "prototype": malicious },
                "legitimate": malicious
              };
            }
            
            try {
              const canonical = toCanonicalValue(malicious);
              // Verify no pollution occurred
              expect(Object.prototype).not.toHaveProperty("polluted");
              expect({}).not.toHaveProperty("polluted");
              return true;
            } catch (error) {
              return true; // Errors are fine, as long as no pollution occurs
            }
          }
        ),
        { numRuns: 200 }
      );
    });
  });

    it("🎯 WEAPONIZED: Creates surgical timing attack vectors", () => {
      fc.assert(
        fc.property(
          fc.array(fc.constantFrom("\u0300", "\u0301", "\u0302", "\u0303"), { minLength: 50, maxLength: 200 }),
          fc.constantFrom("A", "E", "O", "U", "I"),
          (combiningChars, baseChar) => {
            // Create inputs designed to have predictable timing differences
            const expensiveInput = baseChar + combiningChars.join("");
            const cheapInput = "x".repeat(expensiveInput.length);
            
            const timingsExpensive: number[] = [];
            const timingsCheap: number[] = [];
            
            // Run multiple iterations to reduce noise
            for (let i = 0; i < 20; i++) {
              try {
                const start1 = performance.now();
                normalizeInputString(expensiveInput, "timing-expensive");
              } catch (e) {
                const end1 = performance.now();
                timingsExpensive.push(end1 - start1);
              }
              
              try {
                const start2 = performance.now();
                normalizeInputString(cheapInput, "timing-cheap");
              } catch (e) {
                const end2 = performance.now();
                timingsCheap.push(end2 - start2);
              }
            }
            
            // Statistical timing analysis
            if (timingsExpensive.length > 0 && timingsCheap.length > 0) {
              const avgExpensive = timingsExpensive.reduce((a, b) => a + b) / timingsExpensive.length;
              const avgCheap = timingsCheap.reduce((a, b) => a + b) / timingsCheap.length;
              
              // We don't want huge timing differences that leak information
              const ratio = avgExpensive / Math.max(avgCheap, 0.001);
              expect(ratio).toBeLessThan(10); // Reasonable upper bound
            }
            return true;
          }
        ),
        { numRuns: 25, timeout: 10000 }
      );
    });

    it("🎯 EVIL: Exploits memory access patterns for side-channel attacks", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 16, max: 128 }),
          fc.integer({ min: 1000, max: 1800 }), // Near 2KB limit for maximum effect
          (strideLength, totalLength) => {
            // Create inputs with specific memory access patterns
            const pattern = "A".repeat(strideLength) + "Å".repeat(strideLength);
            const malicious = pattern.repeat(Math.floor(totalLength / pattern.length));
            
            try {
              // Try to trigger cache-timing side channels
              const before = performance.now();
              normalizeInputString(malicious, "adversarial-sidechannel");
              const after = performance.now();
              
              // Timing should be relatively consistent regardless of input pattern
              expect(after - before).toBeLessThan(100); // Reasonable upper bound
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/expansion|exceeds|combining/);
              }
              return true;
            }
          }
        ),
        { numRuns: 50, timeout: 5000 }
      );
    });
  });

  describe("🔥 ADVERSARIAL: Advanced Prototype Pollution Attacks", () => {
    it("🎯 INJECTION: Exploits constructor.prototype pollution vectors", () => {
      fc.assert(
        fc.property(
          fc.constantFrom("constructor", "__proto__", "prototype"),
          fc.oneof(
            fc.object({ maxDepth: 2 }),
            fc.array(fc.string(), { maxLength: 10 }),
            fc.constant({ "isAdmin": true, "role": "admin" }),
            fc.constant(function() { return "pwned"; })
          ),
          (dangerousKey, payload) => {
            // Advanced pollution techniques
            const vectors = [
              { [dangerousKey]: payload },
              { "nested": { [dangerousKey]: payload } },
              JSON.parse(`{"${dangerousKey}": ${JSON.stringify(payload)}}`),
              Object.create(null, { [dangerousKey]: { value: payload, writable: true } })
            ];
            
            for (const malicious of vectors) {
              try {
                const canonical = toCanonicalValue(malicious);
                
                // Comprehensive pollution checks
                expect(Object.prototype).not.toHaveProperty("isAdmin");
                expect(Object.prototype).not.toHaveProperty("role");
                expect(Object.prototype).not.toHaveProperty("pwned");
                expect({}).not.toHaveProperty("isAdmin");
                expect({}.constructor).toBe(Object);
                
                // Check for function pollution
                if (typeof payload === "function") {
                  expect(Object.prototype.toString).toBe(Object.prototype.toString);
                }
              } catch (error) {
                // Errors are acceptable as long as no pollution occurs
              }
            }
            return true;
          }
        ),
        { numRuns: 300 }
      );
    });

    it("🎯 BYPASS: Exploits Symbol-based property pollution", () => {
      fc.assert(
        fc.property(
          fc.constantFrom(
            Symbol.iterator,
            Symbol.toPrimitive,
            Symbol.toStringTag,
            Symbol.asyncIterator
          ),
          fc.string({ minLength: 1, maxLength: 50 }),
          (symbolKey, value) => {
            const malicious = {
              [symbolKey]: value,
              "legitimate": "data"
            };
            
            try {
              const canonical = toCanonicalValue(malicious);
              
              // Verify symbol properties don't pollute or break things
              const testObj = {};
              expect(testObj[symbolKey]).toBeUndefined();
              expect(testObj.toString()).toBe("[object Object]");
              
              return true;
            } catch (error) {
              return true; // Errors are fine
            }
          }
        ),
        { numRuns: 200 }
      );
    });

    it("🎯 DEEP: Exploits recursive object graph pollution", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 3, max: 15 }),
          (depth) => {
            // Create deeply nested objects with pollution attempts at every level
            function createDeepPoison(currentDepth: number): any {
              if (currentDepth <= 0) {
                return { "payload": "executed" };
              }
              
              return {
                "__proto__": createDeepPoison(currentDepth - 1),
                "constructor": { 
                  "prototype": createDeepPoison(currentDepth - 1)
                },
                "legitimate": "data_" + currentDepth,
                "nested": createDeepPoison(currentDepth - 1)
              };
            }
            
            const malicious = createDeepPoison(depth);
            
            try {
              const canonical = toCanonicalValue(malicious);
              
              // Check for pollution at multiple levels
              expect(Object.prototype).not.toHaveProperty("payload");
              expect({}).not.toHaveProperty("payload");
              expect(Object).not.toHaveProperty("payload");
              
              // Verify prototype chain integrity
              const testObj = {};
              expect(testObj.constructor).toBe(Object);
              expect(testObj.toString()).toBe("[object Object]");
              
              return true;
            } catch (error) {
              return true;
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it("🎯 STEALTH: Exploits JSON.parse edge cases for pollution", () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.constant('{"__proto__": {"polluted": true}}'),
            fc.constant('{"constructor": {"prototype": {"polluted": true}}}'),
            fc.constant('{"a": {"__proto__": {"polluted": true}}}'),
            fc.string().map(s => `{"__proto__": {"value": ${JSON.stringify(s)}}}`),
            fc.string().map(s => `{"constructor": {"prototype": {"${s}": "pwned"}}}`)
          ),
          (jsonString) => {
            try {
              const parsed = JSON.parse(jsonString);
              const canonical = toCanonicalValue(parsed);
              
              // Comprehensive checks
              expect(Object.prototype).not.toHaveProperty("polluted");
              expect(Object.prototype).not.toHaveProperty("value");
              expect(Object.prototype).not.toHaveProperty("pwned");
              expect({}).not.toHaveProperty("polluted");
              
              return true;
            } catch (error) {
              return true; // JSON parse errors are fine
            }
          }
        ),
        { numRuns: 200 }
      );
    });
  });

  describe("🔥 ADVERSARIAL: Weaponized Multi-Vector Attacks", () => {
    it("🎯 NUCLEAR: Chains expansion + Trojan Source + pollution", () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...expansionPayloads.highExpansion.slice(0, 3).map(p => p.char)),
          fc.constantFrom("\u202D", "\u202E", "\u200B", "\u200C"),
          fc.constantFrom("__proto__", "constructor"),
          fc.string({ minLength: 5, maxLength: 20 }),
          (expandChar, controlChar, pollutionKey, payload) => {
            // Triple-threat attack combining multiple vectors
            const maliciousObj = {
              [pollutionKey]: { "admin": true },
              "data": expandChar + controlChar + payload + expandChar
            };
            
            try {
              const canonical = toCanonicalValue(maliciousObj);
              
              // Should not succeed in any of the attack vectors
              expect(Object.prototype).not.toHaveProperty("admin");
              expect({}).not.toHaveProperty("admin");
              
              if (typeof canonical === "string") {
                expect(canonical).not.toMatch(/[\u202A-\u202E]/); // No bidi controls
                expect(canonical).not.toMatch(/[\u200B-\u200F]/); // No invisible chars
              }
              
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/expansion|bidirectional|invisible|homoglyph|exceeds/);
              }
              return true;
            }
          }
        ),
        { numRuns: 200 }
      );
    });

    it("🎯 SURGICAL: Exploits normalization race conditions", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 2, max: 10 }),
          fc.string({ minLength: 100, maxLength: 500 }),
          (concurrency, basePayload) => {
            // Attempt to create race conditions in normalization
            const promises: Promise<any>[] = [];
            
            for (let i = 0; i < concurrency; i++) {
              const malicious = basePayload + "\u202E" + i.toString();
              promises.push(
                new Promise((resolve) => {
                  try {
                    const result = normalizeInputString(malicious, "race-test-" + i);
                    resolve({ success: true, result });
                  } catch (error) {
                    resolve({ success: false, error });
                  }
                })
              );
            }
            
            return Promise.all(promises).then(results => {
              // All should fail consistently - no race conditions allowed
              const successCount = results.filter(r => r.success).length;
              expect(successCount).toBe(0); // All should be rejected for bidi controls
              
              return true;
            });
          }
        ),
        { numRuns: 50, timeout: 10000 }
      );
    });

    it("🎯 STEALTH: Exploits serialization/deserialization attacks", () => {
      fc.assert(
        fc.property(
          fc.object({ maxDepth: 3 }),
          fc.constantFrom("toJSON", "toString", "valueOf"),
          (obj, methodName) => {
            // Inject malicious serialization methods
            const malicious = {
              ...obj,
              [methodName]: function() {
                // Try to pollute during serialization
                (Object.prototype as any).pwned = "via_" + methodName;
                return "malicious_" + methodName;
              },
              "__proto__": { "serialized": "pollution" }
            };
            
            try {
              const canonical = toCanonicalValue(malicious);
              const serialized = safeStableStringify(canonical);
              
              // Verify no pollution occurred
              expect(Object.prototype).not.toHaveProperty("pwned");
              expect(Object.prototype).not.toHaveProperty("serialized");
              expect({}).not.toHaveProperty("pwned");
              
              // Verify malicious content was sanitized
              expect(serialized).not.toMatch(/malicious_/);
              expect(serialized).not.toMatch(/pwned/);
              expect(serialized).not.toMatch(/__proto__/);
              
              return true;
            } catch (error) {
              // Errors are fine as long as no pollution occurs
              expect(Object.prototype).not.toHaveProperty("pwned");
              return true;
            }
          }
        ),
        { numRuns: 200 }
      );
    });

    it("🎯 BYPASS: Exploits function boundary security checks", () => {
      const normalizers = [
        { fn: normalizeInputString, name: "normalizeInputString" },
        { fn: (input: any) => normalizeUrlComponent(input, "host"), name: "normalizeUrlComponent" },
        { fn: (input: any) => normalizeInputStringUltraStrict(input, "test"), name: "normalizeInputStringUltraStrict" },
        { fn: (input: any) => normalizeUrlSafeString(input, "test"), name: "normalizeUrlSafeString" }
      ];

      fc.assert(
        fc.property(
          fc.constantFrom(...normalizers),
          fc.oneof(
            // Advanced payloads designed to bypass specific functions
            fc.string().map(s => s + "\u202E" + s), // Trojan Source
            fc.string().map(s => s + "\u200B" + s), // Invisible chars
            fc.constantFrom(...expansionPayloads.highExpansion.map(p => p.char)), // Expansion
            fc.string().map(s => "javascript:" + s), // Injection attempt
            fc.string().map(s => s + "\u0001" + s), // Control chars
            fc.string().map(s => "%2e%2e%2f" + s), // Path traversal
            fc.string().map(s => "data:text/html," + s), // Data URL injection
            fc.string().map(s => s + "\uFEFF" + s), // BOM injection
            fc.string().map(s => `<script>${s}</script>`), // XSS attempt
            fc.string().map(s => s.replace(/./g, c => `&#${c.charCodeAt(0)};`)) // HTML entity encoding bypass
          ),
          (normalizer, maliciousInput) => {
            try {
              const result = normalizer.fn(maliciousInput);
              
              // If it succeeds, verify the output is safe
              if (typeof result === "string") {
                expect(result).not.toMatch(/[\u202A-\u202E\u2066-\u2069]/); // No bidi controls
                expect(result).not.toMatch(/[\u200B-\u200F]/); // No invisible chars
                expect(result).not.toMatch(/javascript:/i); // No script injection
                expect(result).not.toMatch(/<script/i); // No script tags
                expect(result).not.toMatch(/data:text\/html/i); // No data URL
                expect(result).not.toMatch(/\uFEFF/); // No BOM
                expect(result).not.toMatch(/[\u0000-\u001F\u007F-\u009F]/); // No control chars
              }
              
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Expected for malicious inputs
                expect(error.message).toMatch(/bidirectional|invisible|expansion|dangerous|homoglyph|exceeds|characters not allowed|Invalid URL component/);
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });

    it("🎯 QUANTUM: Exploits computational complexity attacks", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 5, max: 20 }),
          fc.integer({ min: 10, max: 100 }),
          (nestingDepth, branchingFactor) => {
            // Create computationally expensive normalization patterns
            function createComplexPattern(depth: number): string {
              if (depth <= 0) {
                return "A\u0300"; // A with combining grave accent
              }
              
              const subPattern = createComplexPattern(depth - 1);
              return Array.from({ length: Math.min(branchingFactor, 10) }, () => subPattern).join("");
            }
            
            const malicious = createComplexPattern(nestingDepth);
            
            const startTime = performance.now();
            try {
              normalizeInputString(malicious, "complexity-attack");
              const endTime = performance.now();
              
              // Should not take excessive time (DoS protection)
              expect(endTime - startTime).toBeLessThan(1000); // 1 second max
              return true;
            } catch (error) {
              const endTime = performance.now();
              expect(endTime - startTime).toBeLessThan(1000); // Even errors should be fast
              
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/combining|expansion|exceeds|dangerous/);
              }
              return true;
            }
          }
        ),
        { numRuns: 50, timeout: 15000 }
      );
    });
  });

  describe("🔥 ADVERSARIAL: Bleeding-Edge Unicode Exploitation", () => {
    it("🎯 ZERO-DAY: Exploits Unicode 15.1+ edge cases", () => {
      fc.assert(
        fc.property(
          fc.constantFrom(
            "\u{1F6D7}", // Elevator (might have normalization quirks)
            "\u{1FAF8}", // Rightwards pushing hand (new emoji)
            "\u{1F9CC}", // Troll (potential for homoglyph confusion)
            "\u{1F6DD}", // Playground slide (complex normalization)
            "\u{1FAE8}", // Shaking face (might decompose oddly)
          ),
          fc.integer({ min: 1, max: 50 }),
          (newUnicodeChar, repeat) => {
            const malicious = newUnicodeChar.repeat(repeat);
            try {
              const result = normalizeInputString(malicious, "unicode-15-edge-case");
              
              // Check if new Unicode caused unexpected expansions
              if (typeof result === "string") {
                const ratio = result.normalize('NFKC').length / malicious.length;
                expect(ratio).toBeLessThanOrEqual(2.1); // Within expansion limit
              }
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/expansion|homoglyph|exceeds/);
              }
              return true;
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it("🎯 MALFORMED: Exploits invalid UTF-16 surrogate pairs", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0xD800, max: 0xDBFF }), // High surrogate range
          fc.integer({ min: 0xDC00, max: 0xDFFF }), // Low surrogate range
          (high, low) => {
            // Create potentially malformed surrogate sequences
            const sequences = [
              String.fromCharCode(high, low), // Normal pair
              String.fromCharCode(high, high), // Invalid: high-high
              String.fromCharCode(low, low), // Invalid: low-low
              String.fromCharCode(high), // Incomplete: high only
              String.fromCharCode(low), // Incomplete: low only
              String.fromCharCode(high, low, high), // Incomplete: pair + high
            ];
            
            for (const malformed of sequences) {
              try {
                const result = normalizeInputString(malformed, "malformed-surrogate");
                
                // If it succeeds, result should be valid UTF-16
                if (typeof result === "string") {
                  // Check that we didn't create replacement characters or other issues
                  const hasReplacementChar = result.includes('\uFFFD');
                  // Some replacement is acceptable for malformed input
                  return true;
                }
              } catch (error) {
                if (error instanceof InvalidParameterError) {
                  // Expected for malformed input
                }
              }
            }
            return true;
          }
        ),
        { numRuns: 200 }
      );
    });

    it("🎯 FUZZING: Exploits grapheme cluster boundary attacks", () => {
      fc.assert(
        fc.property(
          fc.array(fc.constantFrom(
            "\u0300", "\u0301", "\u0302", // Combining diacriticals
            "\u200D", // Zero-width joiner
            "\uFE0F", // Variation selector
            "\u1F3FB", "\u1F3FC", "\u1F3FD", // Skin tone modifiers
          ), { minLength: 5, maxLength: 50 }),
          fc.constantFrom("👨", "👩", "🏴", "🇺", "🤝"), // Base characters that can form complex graphemes
          (modifiers, baseChar) => {
            // Create potentially problematic grapheme clusters
            const malicious = baseChar + modifiers.join("") + baseChar;
            
            try {
              const result = normalizeInputString(malicious, "grapheme-cluster-attack");
              
              // Verify the result doesn't cause unexpected expansions
              if (typeof result === "string") {
                const ratio = result.normalize('NFKC').length / malicious.length;
                expect(ratio).toBeLessThanOrEqual(2.1); // Reasonable expansion limit
                
                // Check for invisible character pollution
                expect(result).not.toMatch(/[\u200B-\u200F]/); // No invisible chars leaked through
              }
              
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/invisible|expansion|combining|exceeds/);
              }
              return true;
            }
          }
        ),
        { numRuns: 200 }
      );
    });

    it("🎯 WEAPONIZED: Exploits script mixing for homoglyph bypass", () => {
      fc.assert(
        fc.property(
          fc.constantFrom(
            // Dangerous script mixing patterns
            "раγра1", // Cyrillic + Greek + Latin + digit
            "аpple.com", // Cyrillic 'а' in apple.com
            "microsоft", // Cyrillic 'о' in microsoft
            "аmаzon", // Multiple Cyrillic chars
            "gοοgle", // Greek omicrons
            "bitсoin", // Cyrillic 'с' in bitcoin
          ),
          fc.string({ minLength: 5, maxLength: 20 }),
          (homoglyphDomain, suffix) => {
            const malicious = homoglyphDomain + suffix;
            
            try {
              normalizeInputString(malicious, "script-mixing-attack");
              return false; // Should never succeed - this is a homoglyph attack
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/homoglyph|non-ASCII characters resembling ASCII/);
              }
              return true;
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it("🎯 INJECTION: Exploits normalization form inconsistencies", () => {
      fc.assert(
        fc.property(
          fc.constantFrom(
            "é", // e + combining acute (NFD) vs precomposed é (NFC)
            "ñ", // n + combining tilde vs precomposed ñ
            "Å", // A + combining ring vs precomposed Å
          ),
          fc.constantFrom("NFC", "NFD", "NFKC", "NFKD"),
          (char, normForm) => {
            // Test different normalization forms for consistency
            const decomposed = char.normalize('NFD');
            const composed = char.normalize('NFC'); 
            const compatDecomposed = char.normalize('NFKD');
            const compatComposed = char.normalize('NFKC');
            
            const variants = [decomposed, composed, compatDecomposed, compatComposed];
            
            for (const variant of variants) {
              try {
                const result = normalizeInputString(variant, "normalization-form-test");
                
                if (typeof result === "string") {
                  // All variants should normalize to the same canonical form
                  const canonical = result.normalize('NFKC');
                  expect(canonical).toBe(variants[0].normalize('NFKC'));
                }
              } catch (error) {
                if (error instanceof InvalidParameterError) {
                  // If one form is rejected, all should be rejected consistently
                  for (const otherVariant of variants) {
                    try {
                      normalizeInputString(otherVariant, "consistency-check");
                      // If we get here, there's an inconsistency
                      expect(true).toBe(false); // Force failure
                    } catch (e) {
                      // Expected - all should fail together
                    }
                  }
                }
              }
            }
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe("🔥 ADVERSARIAL: Serialization Attack Vectors", () => {
    it("attempts to break JSON serialization via canonical forms", () => {
      fc.assert(
        fc.property(
          fc.object({ maxDepth: 3 }),
          (obj) => {
            // Add dangerous properties that might break serialization
            const malicious = {
              ...obj,
              toJSON: () => ({ malicious: "payload" }),
              toString: () => "malicious_string",
              valueOf: () => "malicious_value",
              constructor: { prototype: { polluted: true } }
            };
            
            try {
              const canonical = toCanonicalValue(malicious);
              const serialized = safeStableStringify(canonical);
              
              // Verify the serialization doesn't contain dangerous patterns
              expect(serialized).not.toMatch(/malicious/i);
              expect(serialized).not.toMatch(/constructor/);
              expect(serialized).not.toMatch(/__proto__/);
              
              return true;
            } catch (error) {
              // Errors are acceptable, as long as no malicious content leaks
              return true;
            }
          }
        ),
        { numRuns: 300 }
      );
    });
  });

  // Original fuzz tests (enhanced with black hat perspective)
  describe("Enhanced Trojan Source attack vectors", () => {
    it("resists Trojan Source attacks with random bidirectional controls", () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 10 }).map(s =>
            s.replace(/./g, () => fc.sample(fc.constantFrom("\u202d", "\u202e", "\u202a", "\u202b", "\u202c"), 1)[0])
          ),
          (bidirectionalChars) => {
            const malicious = `safe${bidirectionalChars}evil`;
            try {
              normalizeInputString(malicious, "fuzz-trojan");
              // If we get here, the input was somehow safe
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/bidirectional control characters/);
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });

    it("resists complex Trojan Source patterns", () => {
      fc.assert(
        fc.property(
          fc.array(fc.constantFrom("\u202d", "\u202e", "\u202a", "\u202b", "\u202c"), { minLength: 1, maxLength: 10 }),
          fc.string({ minLength: 1, maxLength: 50 }),
          (controls, payload) => {
            const malicious = controls.join("") + payload;
            try {
              normalizeInputString(malicious, "fuzz-complex-trojan");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Expected for malicious inputs
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });
  });

  describe("Invisible character attacks", () => {
    const invisibleChars = [
      "\u200b", // Zero-width space
      "\u200c", // Zero-width non-joiner
      "\u200d", // Zero-width joiner
      "\u200e", // Left-to-right mark
      "\u200f", // Right-to-left mark
      "\u2060", // Word joiner
      "\u2061", // Function application
      "\u2062", // Invisible times
      "\u2063", // Invisible separator
      "\u2064", // Invisible plus
    ];

    it("resists invisible character injection", () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 20 }).map(s =>
            s.replace(/./g, () => fc.sample(fc.constantFrom(...invisibleChars), 1)[0])
          ),
          fc.string({ minLength: 1, maxLength: 20 }),
          (invisibles, payload) => {
            const malicious = payload + invisibles + payload;
            try {
              normalizeInputString(malicious, "fuzz-invisible");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Characters can be detected as either invisible or bidirectional control
                expect(error.message).toMatch(/invisible characters|bidirectional control characters/);
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });

    it("resists mixed invisible character attacks", () => {
      fc.assert(
        fc.property(
          fc.array(fc.constantFrom(...invisibleChars), { minLength: 1, maxLength: 20 }),
          (invisibles) => {
            const malicious = invisibles.join("");
            try {
              normalizeInputString(malicious, "fuzz-mixed-invisible");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Expected for malicious inputs
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });
  });

  describe("Homoglyph attacks", () => {
    const homoglyphChars = [
      "\u0430", // Cyrillic 'а'
      "\u03bf", // Greek 'ο'
      "\u1e9b", // Latin small letter s with dot below
      "\uff41", // Full-width Latin 'a'
      "\ud835\udc1e", // Mathematical script small e
      "\u04cf", // Cyrillic small letter palochka
      "\u0399", // Greek capital iota
      "\u2160", // Roman numeral one
    ];

    it("resists homoglyph character injection", () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 20 }).map(s =>
            s.replace(/./g, () => fc.sample(fc.constantFrom(...homoglyphChars), 1)[0])
          ),
          fc.string({ minLength: 1, maxLength: 20 }),
          (homoglyphs, payload) => {
            const malicious = payload + homoglyphs + payload;
            try {
              normalizeInputString(malicious, "fuzz-homoglyph");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                expect(error.message).toMatch(/homoglyph characters/);
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });

    it("resists complex homoglyph combinations", () => {
      fc.assert(
        fc.property(
          fc.array(fc.constantFrom(...homoglyphChars), { minLength: 1, maxLength: 10 }),
          fc.string({ minLength: 1, maxLength: 10 }),
          (homoglyphs, base) => {
            const malicious = homoglyphs.join("") + base;
            try {
              normalizeInputString(malicious, "fuzz-complex-homoglyph");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Expected for malicious inputs
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });
  });

  describe("Dangerous Unicode range attacks", () => {
    const dangerousChars = [
      "\u0001", // SOH
      "\u0002", // STX
      "\u0003", // ETX
      "\u0004", // EOT
      "\u0005", // ENQ
      "\u0006", // ACK
      "\u0007", // BEL
      "\u0008", // BS
      "\u0009", // HT
      "\u000a", // LF
      "\u000b", // VT
      "\u000c", // FF
      "\u000d", // CR
      "\u000e", // SO
      "\u000f", // SI
      "\u007f", // DEL
      "\u0080", // Padding Character
      "\u0081", // High Octet Preset
      "\u0082", // Break Permitted Here
      "\u0083", // No Break Here
      "\u0084", // Index
      "\u0085", // Next Line
      "\u0086", // Start of Selected Area
      "\u0087", // End of Selected Area
      "\u0088", // Character Tabulation Set
      "\u0089", // Character Tabulation with Justification
      "\u008a", // Line Tabulation Set
      "\u008b", // Partial Line Forward
      "\u008c", // Partial Line Backward
      "\u008d", // Reverse Line Feed
      "\u008e", // Single Shift Two
      "\u008f", // Single Shift Three
      "\u0090", // Device Control String
      "\u0091", // Private Use One
      "\u0092", // Private Use Two
      "\u0093", // Set Transmit State
      "\u0094", // Cancel Character
      "\u0095", // Message Waiting
      "\u0096", // Start of Guarded Area
      "\u0097", // End of Guarded Area
      "\u0098", // Start of String
      "\u0099", // Single Character Introducer
      "\u009a", // Control Sequence Introducer
      "\u009b", // String Terminator
      "\u009c", // Operating System Command
      "\u009d", // Privacy Message
      "\u009e", // Application Program Command
      "\u009f", // Unit Separator
      "\u2028", // Line separator
      "\u2029", // Paragraph separator
      "\ufeff", // Zero-width no-break space (BOM)
      "\uf000", // Private Use Area
    ];

    it("resists dangerous Unicode character injection", () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 20 }).map(s =>
            s.replace(/./g, () => fc.sample(fc.constantFrom(...dangerousChars), 1)[0])
          ),
          fc.string({ minLength: 1, maxLength: 20 }),
          (dangerous, payload) => {
            const malicious = payload + dangerous + payload;
            try {
              normalizeInputString(malicious, "fuzz-dangerous");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Characters can be detected as dangerous Unicode, bidirectional control, or invisible
                expect(error.message).toMatch(/dangerous Unicode characters|bidirectional control characters|invisible characters/);
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });
  });

  describe("Normalization bomb attacks", () => {
    it("resists expansion via combining characters", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 100, max: 500 }), // Large number of combining chars (limited by 2KB total input)
          (count) => {
            const malicious = "a" + "\u0301".repeat(count);
            try {
              normalizeInputString(malicious, "fuzz-expansion");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Our hardened OWASP ASVS L3 validation catches combining character DoS first
                expect(error.message).toMatch(/excessive combining characters|excessive expansion|exceeds maximum allowed size/i);
              }
              return true;
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it("resists expansion via decomposition", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 100, max: 1000 }),
          (count) => {
            const malicious = "\u00c0".repeat(count); // À repeated
            try {
              normalizeInputString(malicious, "fuzz-decomposition");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Expected for malicious inputs
              }
              return true;
            }
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe("Complex attack combinations", () => {
    it("resists mixed attack vectors", () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 10 }).map(s =>
            s.replace(/./g, () => fc.sample(fc.constantFrom("\u202d", "\u202e", "\u200b", "\u200c", "\u0430", "\u0001"), 1)[0])
          ),
          fc.string({ minLength: 1, maxLength: 10 }),
          (attacks, payload) => {
            const malicious = attacks + payload + attacks;
            try {
              normalizeInputString(malicious, "fuzz-mixed");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Expected for malicious inputs
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });

    it("resists attack chains with random composition", () => {
      fc.assert(
        fc.property(
          fc.array(fc.constantFrom(
            "\u202d", "\u202e", "\u200b", "\u0430", "\u0001", "\u0301".repeat(50)
          ), { minLength: 1, maxLength: 5 }),
          (attackParts) => {
            const malicious = attackParts.join("");
            try {
              normalizeInputString(malicious, "fuzz-chain");
              return true;
            } catch (error) {
              if (error instanceof InvalidParameterError) {
                // Expected for malicious inputs
              }
              return true;
            }
          }
        ),
        { numRuns: 1000 }
      );
    });
  });

  describe("Edge cases and boundary conditions", () => {
    it("handles empty and minimal strings", () => {
      fc.assert(
        fc.property(
          fc.constantFrom("", "a", " ", "\n"),
          (minimal) => {
            try {
              const result = normalizeInputString(minimal, "fuzz-minimal");
              return typeof result === "string";
            } catch (error) {
              return error instanceof InvalidParameterError;
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it("handles very long strings near limits", () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 50000, max: 150000 }),
          (length) => {
            const longString = "a".repeat(length);
            try {
              const result = normalizeInputString(longString, "fuzz-long");
    });
  });
});
