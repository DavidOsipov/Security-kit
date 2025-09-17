#!/usr/bin/env node

// Test script to reproduce the "Hello World!" blocking issue described in the handover document

import { normalizeInputString } from './src/canonical.ts';

console.log('Testing the claimed "Hello World!" blocking issue...\n');

const testCases = [
  { input: "Hello World!", context: "natural-language" },
  { input: "Hello World!", context: "input" },
  { input: "Hello World!", context: "shell-input" },
  { input: "Hello World!", context: "user-content" },
  { input: "Hello World!", context: "colon" }, // URL context that should be safe
  { input: "Hello World!", context: "hostname" }, // URL context that should be safe
];

for (const testCase of testCases) {
  try {
    const result = normalizeInputString(testCase.input, testCase.context);
    console.log(`✅ PASS: "${testCase.input}" in context "${testCase.context}" -> "${result}"`);
  } catch (error) {
    console.log(`❌ BLOCKED: "${testCase.input}" in context "${testCase.context}" -> ${error.message}`);
    if (error.securityScore !== undefined) {
      console.log(`   Security score: ${error.securityScore}/${error.threshold}, Primary threat: ${error.primaryThreat}`);
    }
  }
}

console.log('\nTesting other interesting cases...\n');

const otherCases = [
  { input: "Hello", context: "input" },
  { input: "rm -rf /", context: "input" },
  { input: "javascript:alert(1)", context: "input" },
  { input: "user@domain.com", context: "hostname" },
  { input: ":", context: "colon" },
];

for (const testCase of otherCases) {
  try {
    const result = normalizeInputString(testCase.input, testCase.context);
    console.log(`✅ PASS: "${testCase.input}" in context "${testCase.context}" -> "${result}"`);
  } catch (error) {
    console.log(`❌ BLOCKED: "${testCase.input}" in context "${testCase.context}" -> ${error.message}`);
    if (error.securityScore !== undefined) {
      console.log(`   Security score: ${error.securityScore}/${error.threshold}, Primary threat: ${error.primaryThreat}`);
    }
  }
}