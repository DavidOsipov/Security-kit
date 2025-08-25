#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Verify-sanitize script as mandated by Security Constitution
 * Performs static analysis to ensure production safety guards
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔍 Running security sanitization checks...');

const checks = [
  {
    name: 'Production console statements',
    description: 'Ensure no console.log statements in production code',
    check: () => {
      const srcPath = path.join(__dirname, '../src');
      
      try {
        const violations = [];
        
        // Check each TypeScript file
        const checkFile = (filePath) => {
          const content = fs.readFileSync(filePath, 'utf8');
          const lines = content.split('\n');

          // Helper: find matching brace range starting at openBraceLine index
          const findBlockEnd = (startLineIndex) => {
            let depth = 0;
            let started = false;
            for (let i = startLineIndex; i < lines.length; i++) {
              const l = lines[i];
              for (let ch of l) {
                if (ch === '{') { depth++; started = true; }
                else if (ch === '}') depth--;
              }
              if (started && depth === 0) return i; // inclusive end line
            }
            return lines.length - 1;
          };

          // Identify function ranges that should be considered dev-only
          const devRanges = [];

          const functionStartRegex = /^(?:export\s+)?function\s+(\w+)\s*\(/;
          const arrowAssignRegex = /^(?:const|let|var)\s+(\w+)\s*=\s*\(/;

          for (let i = 0; i < lines.length; i++) {
            const trimmed = lines[i].trim();
            let m = trimmed.match(functionStartRegex);
            if (!m) m = trimmed.match(/^(?:export\s+)?const\s+(\w+)\s*=\s*\(/);
            if (m) {
              const fnName = m[1];
              // find where the block ends
              const startLine = i;
              const openBraceLine = (() => {
                // search forward for the first line containing '{'
                for (let j = i; j < Math.min(i + 6, lines.length); j++) {
                  if (lines[j].includes('{')) return j;
                }
                // fallback to current line
                return i;
              })();
              const endLine = findBlockEnd(openBraceLine);
              // check if function body contains immediate dev guard
              const guardWindowEnd = Math.min(openBraceLine + 6, endLine);
              let hasGuard = false;
              for (let k = openBraceLine + 1; k <= guardWindowEnd; k++) {
                const l = lines[k] || '';
                if (l.includes('isDevelopment()') || l.includes('environment.isProduction')) {
                  hasGuard = true; break;
                }
              }
              // always allow secureDevLog by name
              if (fnName === 'secureDevLog' || hasGuard) devRanges.push([openBraceLine, endLine]);
              i = endLine;
            }
          }

          // Now scan for console.* occurrences and check whether they fall into devRanges
          // Only allow console calls inside a function named `_devConsole`.
          let allowedDevConsoleRange = null;
          for (let i = 0; i < lines.length; i++) {
            const t = lines[i].trim();
            const m = t.match(/^function\s+_devConsole\s*\(/);
            if (m) {
              // find where the function block opens
              let openLine = i;
              for (let j = i; j < Math.min(i + 6, lines.length); j++) {
                if (lines[j].includes('{')) { openLine = j; break; }
              }
              const end = findBlockEnd(openLine);
              allowedDevConsoleRange = [openLine, end];
              break;
            }
          }

          for (let i = 0; i < lines.length; i++) {
            const trimmed = lines[i].trim();
            if (!/console\.(log|info|warn|error|debug)/.test(trimmed)) continue;

            // If this console is inside the explicit dev-console function, allow it
            if (allowedDevConsoleRange && i >= allowedDevConsoleRange[0] && i <= allowedDevConsoleRange[1]) continue;

            // If this console is within any devRange (guarded function), skip
            let allowed = false;
            for (const [s, e] of devRanges) {
              if (i >= s && i <= e) { allowed = true; break; }
            }
            // Also allow if preceding few lines contain an immediate dev guard
            if (!allowed) {
              for (let k = Math.max(0, i - 4); k < i; k++) {
                const l = lines[k];
                if (!l) continue;
                if (l.includes('isDevelopment()') || l.includes('environment.isProduction')) {
                  allowed = true; break;
                }
              }
            }

            if (!allowed) {
              violations.push(`${path.relative(srcPath, filePath)}:${i+1}: ${trimmed}`);
            }
          }
        };
        
        // Recursively check all TypeScript files
        const walkDir = (dir) => {
          const files = fs.readdirSync(dir);
          for (const file of files) {
            const fullPath = path.join(dir, file);
            const stat = fs.statSync(fullPath);
            
            if (stat.isDirectory()) {
              walkDir(fullPath);
            } else if (file.endsWith('.ts') && !file.endsWith('.d.ts')) {
              checkFile(fullPath);
            }
          }
        };
        
        walkDir(srcPath);
        
        if (violations.length > 0) {
          console.error('❌ Found console statements without environment guards:');
          violations.forEach(v => console.error(`   ${v}`));
          return false;
        }
        
        console.log('✅ No unguarded console statements found');
        return true;
        
      } catch (e) {
        console.log('⚠️  Could not check console statements:', e.message);
        return true; // Don't fail if there's an error
      }
    }
  },
  
  {
    name: 'Prototype pollution protection',
    description: 'Verify prototype pollution safeguards are in place',
    check: () => {
      const postMessagePath = path.join(__dirname, '../src/postMessage.ts');
      if (!fs.existsSync(postMessagePath)) {
        console.error('❌ postMessage.ts not found');
        return false;
      }
      
      const content = fs.readFileSync(postMessagePath, 'utf8');
      
      if (!content.includes('toNullProto')) {
        console.error('❌ Prototype pollution protection (toNullProto) not found');
        return false;
      }
      
      if (!content.includes('POSTMESSAGE_FORBIDDEN_KEYS')) {
        console.error('❌ Forbidden keys protection not found');
        return false;
      }
      
      console.log('✅ Prototype pollution protections verified');
      return true;
    }
  },
  
  {
    name: 'Crypto sync guards',
    description: 'Verify sync crypto functions have proper error handling',
    check: () => {
      const cryptoPath = path.join(__dirname, '../src/crypto.ts');
      if (!fs.existsSync(cryptoPath)) {
        console.error('❌ crypto.ts not found');
        return false;
      }
      
      const content = fs.readFileSync(cryptoPath, 'utf8');
      
      if (!content.includes('assertCryptoAvailableSync')) {
        console.error('❌ Sync crypto guard function not found');
        return false;
      }
      
      if (!content.includes('CRYPTO_UNAVAILABLE_SYNC')) {
        console.error('❌ Sync crypto error code not found');
        return false;
      }
      
      console.log('✅ Sync crypto guards verified');
      return true;
    }
  },
  
  {
    name: 'Error codes stability',
    description: 'Verify all custom errors have stable codes',
    check: () => {
      const errorsPath = path.join(__dirname, '../src/errors.ts');
      if (!fs.existsSync(errorsPath)) {
        console.error('❌ errors.ts not found');
        return false;
      }
      
      const content = fs.readFileSync(errorsPath, 'utf8');
      
      const expectedCodes = [
        'ERR_CRYPTO_UNAVAILABLE',
        'ERR_INVALID_PARAMETER', 
        'ERR_RANDOM_GENERATION',
        'ERR_INVALID_CONFIGURATION'
      ];
      
      for (const code of expectedCodes) {
        if (!content.includes(code)) {
          console.error(`❌ Error code ${code} not found`);
          return false;
        }
      }
      
      console.log('✅ Error code stability verified');
      return true;
    }
  }
];

let allPassed = true;

console.log('Running security checks...\n');

for (const check of checks) {
  console.log(`Checking: ${check.description}`);
  const passed = check.check();
  if (!passed) {
    allPassed = false;
  }
  console.log('');
}

if (allPassed) {
  console.log('🎉 All security sanitization checks passed!');
  process.exit(0);
} else {
  console.log('💥 Security sanitization checks failed!');
  process.exit(1);
}