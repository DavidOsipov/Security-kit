// Debug script to understand the metamorphic test failure
import { normalizeInputString } from "./src/canonical.ts";
import { InvalidParameterError } from "./src/errors.ts";

// Test the exact failing case from the ACTUAL test output
const exactFailingCase = "    !  !!\"0000100002"; // Latest failing case from test output
console.log("Testing EXACT failing case from test:", JSON.stringify(exactFailingCase));
console.log("Length:", exactFailingCase.length);

const testCases = [exactFailingCase];

testCases.forEach((payload, index) => {
  console.log(`\n=== TESTING CASE ${index + 1}: ${JSON.stringify(payload)} ===`);
  console.log(`Length: ${payload.length}`);
  
  // Analyze the whitespace pattern
  const whitespaceMatches = payload.match(/[\s\u00A0\u2000-\u200B\u2028\u2029\u202F\u205F\u3000]+/g);
  console.log("Whitespace patterns:", whitespaceMatches?.map(m => `"${m}" (${m.length})`));
  
  // Calculate expected security score manually for debugging
  const whitespaceRatio = (payload.match(/[\s\u00A0\u2000-\u200B\u2028\u2029\u202F\u205F\u3000]/gu) || []).length / payload.length;
  const consecutiveWhitespace = payload.match(/[\s\u00A0\u2000-\u200B\u2028\u2029\u202F\u205F\u3000]{3,}/gu);
  const maxConsecutive = consecutiveWhitespace ? Math.max(...consecutiveWhitespace.map(m => m.length)) : 0;
  const punctuationRatio = (payload.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/gu) || []).length / payload.length;
  
  console.log("Manual scoring analysis:");
  console.log(`- Whitespace ratio: ${(whitespaceRatio * 100).toFixed(1)}% (threshold: >40%)`);
  console.log(`- Max consecutive whitespace: ${maxConsecutive} chars (scoring: ${Math.min(maxConsecutive * 8, 40)} points if >=3)`);
  console.log(`- Punctuation ratio: ${(punctuationRatio * 100).toFixed(1)}% (threshold: >30%)`);
  
  // Estimate total score using UPDATED heuristic rules
  let estimatedScore = 0;
  
  // Updated Factor 1: Whitespace density >=35%
  if (whitespaceRatio >= 0.35) estimatedScore += Math.round(whitespaceRatio * 120);
  
  // Updated Factor 2: Consecutive whitespace >=3 chars
  if (maxConsecutive >= 3) estimatedScore += Math.min(maxConsecutive * 10, 50);
  
  // Updated Factor 3: Punctuation density >=25%
  if (punctuationRatio >= 0.25) estimatedScore += Math.round(punctuationRatio * 100);
  
  // Updated Factor 4: Leading whitespace pattern (4+ spaces)
  if (/^\s{4,}/u.test(payload)) {
    estimatedScore += 15;
    console.log(`- Leading whitespace bonus: +15 points`);
  }
  
  // Updated Factor 5: Short pattern boost (length < 30)
  if (payload.length < 30 && estimatedScore > 0) {
    const boost = Math.round(15 * (30 - payload.length) / 30);
    estimatedScore += boost;
    console.log(`- Short pattern boost: +${boost} points`);
  }
  
  console.log(`- Updated estimated score: ${estimatedScore} (threshold: >=70)`);
  
  const mutations = [
    payload + "\u202E",                    // Trojan Source
    payload.replace(/o/g, "\u03BF"),       // Greek omicron  
    payload + "\u200B".repeat(10),         // Invisible spaces
    payload + "A\u0300".repeat(20),        // Combining chars
    payload.replace(/a/g, "\u0430"),       // Cyrillic a
    payload + "\uFEFF",                    // BOM
    payload.split("").reverse().join("") + "\u202E" // Reverse + bidi
  ];

  let successfulMutations = 0;
  const vulnerabilities = [];

  mutations.forEach((mutation, mutIndex) => {
    console.log(`\n--- Mutation ${mutIndex + 1} ---`);
    console.log("Mutation:", JSON.stringify(mutation.substring(0, 50) + (mutation.length > 50 ? "..." : "")));
    try {
      normalizeInputString(mutation, "debug-test");
      successfulMutations++;
      vulnerabilities.push(`Mutation ${mutIndex + 1}: SHOULD BE BLOCKED but succeeded`);
      console.log("🔥 VULNERABILITY: SUCCEEDED (should be rejected!)");
    } catch (error) {
      if (error instanceof InvalidParameterError) {
        console.log("✅ CORRECTLY REJECTED:", error.message.substring(0, 80));
      } else {
        successfulMutations++;
        vulnerabilities.push(`Mutation ${mutIndex + 1}: Unexpected error: ${error.message}`);
        console.log("🔥 UNEXPECTED ERROR:", error.message);
      }
    }
  });

  console.log(`\n🎯 CASE ${index + 1} RESULTS:`);
  console.log(`- Vulnerabilities found: ${successfulMutations}/7 mutations`);
  console.log(`- Should be: 0/7 (all rejected)`);

  if (vulnerabilities.length > 0) {
    console.log("💀 VULNERABILITIES:");
    vulnerabilities.forEach(v => console.log("  -", v));
  } else {
    console.log("✅ No vulnerabilities found - all attacks properly blocked!");
  }
});
