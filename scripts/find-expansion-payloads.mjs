#!/usr/bin/env node

/**
 * Unicode Normalization Expansion Payload Discovery Script
 * 
 * This script systematically searches through Unicode code points to find
 * characters that expand when normalized with NFKC. These characters are
 * potential sources of normalization bomb attacks where a single character
 * becomes multiple characters, potentially causing DoS through excessive
 * memory consumption.
 * 
 * The script focuses on practical ranges where expansion is most likely:
 * - Basic Multilingual Plane (U+0000-U+FFFF) 
 * - Supplementary Multilingual Plane (U+10000-U+1FFFF)
 * - Key areas: ligatures, CJK compatibility, enclosed characters, etc.
 */

import fs from "fs";
import path from "path";

console.log("Starting systematic search for Unicode NFKC expansion payloads...");
console.log("This will help create realistic normalization bomb test cases.\n");

const expansionPayloads = [];
const categoryStats = new Map();

// Define ranges to search with their descriptions
const searchRanges = [
  { start: 0x00A0, end: 0x024F, name: "Latin Extended" },
  { start: 0x0370, end: 0x03FF, name: "Greek and Coptic" },
  { start: 0x0400, end: 0x04FF, name: "Cyrillic" },
  { start: 0x1D00, end: 0x1D7F, name: "Phonetic Extensions" },
  { start: 0x1E00, end: 0x1EFF, name: "Latin Extended Additional" },
  { start: 0x2000, end: 0x206F, name: "General Punctuation" },
  { start: 0x2070, end: 0x209F, name: "Superscripts and Subscripts" },
  { start: 0x20A0, end: 0x20CF, name: "Currency Symbols" },
  { start: 0x2100, end: 0x214F, name: "Letterlike Symbols" },
  { start: 0x2150, end: 0x218F, name: "Number Forms" },
  { start: 0x2190, end: 0x21FF, name: "Arrows" },
  { start: 0x2460, end: 0x24FF, name: "Enclosed Alphanumerics" },
  { start: 0x3300, end: 0x33FF, name: "CJK Compatibility" },
  { start: 0x3400, end: 0x4DBF, name: "CJK Extension A" },
  { start: 0xF900, end: 0xFAFF, name: "CJK Compatibility Ideographs" },
  { start: 0xFB00, end: 0xFB4F, name: "Alphabetic Presentation Forms" },
  { start: 0xFE20, end: 0xFE2F, name: "Combining Half Marks" },
  { start: 0xFE30, end: 0xFE4F, name: "CJK Compatibility Forms" },
  { start: 0xFF00, end: 0xFFEF, name: "Halfwidth and Fullwidth Forms" },
];

function categorizeCharacter(codePoint, char, normalized) {
  // Analyze the character to categorize the type of expansion
  if (/^[a-zA-Z]{2,}$/.test(normalized)) {
    return "Ligature";
  }
  if (/^\d+$/.test(normalized) || /^[IVXLCDM]+$/i.test(normalized)) {
    return "Number/Roman";
  }
  if (/^\([^)]+\)$/.test(normalized) || /^\[[^\]]+\]$/.test(normalized)) {
    return "Enclosed";
  }
  if (/^[a-zA-Z]+\/[a-zA-Z]+$/.test(normalized) || /^[a-zA-Z]+\^?\d*$/.test(normalized)) {
    return "Unit/Scientific";
  }
  if (/^\d+\/\d+$/.test(normalized)) {
    return "Fraction";
  }
  if (codePoint >= 0x3300 && codePoint <= 0x33FF) {
    return "CJK Compatibility";
  }
  if (codePoint >= 0xFB00 && codePoint <= 0xFB4F) {
    return "Presentation Form";
  }
  if (codePoint >= 0xFF00 && codePoint <= 0xFFEF) {
    return "Fullwidth/Halfwidth";
  }
  return "Other";
}

function searchRange(start, end, rangeName) {
  let found = 0;
  console.log(`Searching ${rangeName} (U+${start.toString(16).toUpperCase()}-U+${end.toString(16).toUpperCase()})...`);
  
  for (let i = start; i <= end; i++) {
    try {
      const originalChar = String.fromCodePoint(i);
      
      // Skip non-printable control characters and private use areas
      if (i < 0x20 || (i >= 0x7f && i <= 0x9f) || (i >= 0xE000 && i <= 0xF8FF)) {
        continue;
      }
      
      const normalizedString = originalChar.normalize("NFKC");
      
      if (normalizedString.length > originalChar.length) {
        const category = categorizeCharacter(i, originalChar, normalizedString);
        const payload = {
          char: originalChar,
          hex: `U+${i.toString(16).toUpperCase().padStart(4, "0")}`,
          decimal: i,
          normalized: normalizedString,
          originalLength: originalChar.length,
          normalizedLength: normalizedString.length,
          expansionRatio: normalizedString.length / originalChar.length,
          category: category,
          range: rangeName,
          // Add some metadata for better understanding
          description: `${originalChar} → ${normalizedString}`,
          bytes: Buffer.from(normalizedString, 'utf8').length,
        };
        expansionPayloads.push(payload);
        found++;
        
        // Update category statistics
        const count = categoryStats.get(category) || 0;
        categoryStats.set(category, count + 1);
        
        // Log interesting high-expansion findings
        if (payload.expansionRatio >= 3) {
          console.log(`  🎯 High expansion: ${payload.description} (${payload.expansionRatio}x)`);
        }
      }
    } catch (error) {
      // Ignore errors for invalid code points
      continue;
    }
  }
  
  console.log(`  Found ${found} expansion characters in ${rangeName}\n`);
  return found;
}

// Main discovery process
let totalFound = 0;

for (const range of searchRanges) {
  totalFound += searchRange(range.start, range.end, range.name);
}

console.log(`\n🎉 Discovery complete! Found ${expansionPayloads.length} characters that expand under NFKC.`);

// Sort by expansion ratio (most dangerous first)
expansionPayloads.sort((a, b) => b.expansionRatio - a.expansionRatio);

// Display statistics
console.log("\n📊 Category Statistics:");
const sortedCategories = Array.from(categoryStats.entries())
  .sort((a, b) => b[1] - a[1]);

for (const [category, count] of sortedCategories) {
  console.log(`  ${category}: ${count} characters`);
}

// Show most dangerous characters
console.log("\n🚨 Top 15 Most Expansive Characters (Highest DoS Risk):");
const topExpanders = expansionPayloads.slice(0, 15);
console.table(topExpanders.map(p => ({
  Character: p.char,
  Unicode: p.hex,
  "Expands To": p.normalized,
  "Ratio": `${p.expansionRatio}x`,
  Category: p.category,
  Range: p.range
})));

// Create fixtures directory if it doesn't exist
const fixturesDir = path.join(process.cwd(), 'tests', 'fixtures');
if (!fs.existsSync(fixturesDir)) {
  fs.mkdirSync(fixturesDir, { recursive: true });
}

// Save comprehensive results
const outputPath = path.join(fixturesDir, 'unicode-expansion-payloads.json');
const results = {
  metadata: {
    generatedAt: new Date().toISOString(),
    totalCharacters: expansionPayloads.length,
    searchRanges: searchRanges.map(r => `${r.name} (U+${r.start.toString(16)}-U+${r.end.toString(16)})`),
    categories: Object.fromEntries(categoryStats),
    maxExpansionRatio: Math.max(...expansionPayloads.map(p => p.expansionRatio)),
  },
  // Separate arrays for different use cases
  all: expansionPayloads,
  highRisk: expansionPayloads.filter(p => p.expansionRatio >= 3),
  mediumRisk: expansionPayloads.filter(p => p.expansionRatio >= 2 && p.expansionRatio < 3),
  lowRisk: expansionPayloads.filter(p => p.expansionRatio > 1 && p.expansionRatio < 2),
  // By category for targeted testing
  byCategory: Object.fromEntries(
    Array.from(categoryStats.keys()).map(cat => [
      cat, 
      expansionPayloads.filter(p => p.category === cat)
    ])
  ),
};

fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
console.log(`\n💾 Results saved to: ${outputPath}`);

// Create a simplified payload for quick testing
const testPayloadsPath = path.join(fixturesDir, 'test-expansion-payloads.json');
const testPayloads = {
  // Perfect for testing MAX_NORMALIZED_LENGTH_RATIO = 2
  highExpansion: expansionPayloads.filter(p => p.expansionRatio >= 2.5),
  // Safe for testing (should pass)
  safeExpansion: expansionPayloads.filter(p => p.expansionRatio > 1 && p.expansionRatio <= 2),
  // Most dangerous single characters
  maxThreat: expansionPayloads.slice(0, 5),
  // Common categories for comprehensive testing
  ligatures: expansionPayloads.filter(p => p.category === "Ligature").slice(0, 10),
  cjkCompatibility: expansionPayloads.filter(p => p.category === "CJK Compatibility").slice(0, 10),
  fractions: expansionPayloads.filter(p => p.category === "Fraction"),
};

fs.writeFileSync(testPayloadsPath, JSON.stringify(testPayloads, null, 2));
console.log(`💾 Test payloads saved to: ${testPayloadsPath}`);

console.log(`\n✅ Ready for integration into your test suite!`);
console.log(`   Use the payloads in your adversarial tests to create realistic normalization bomb scenarios.`);
console.log(`   These are REAL Unicode characters that actually expand under NFKC normalization.`);