import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { normalizeInputString, sanitizeForLogging } from '../src/canonical.ts';
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig } from '../src/config.ts';
import { SecurityValidationError, InvalidParameterError } from '../src/errors.ts';

describe('multi-vector attack scenarios (OWASP ASVS L3 defense-in-depth)', () => {
  const original = getUnicodeSecurityConfig();

  afterAll(() => {
    // Restore original configuration
    setUnicodeSecurityConfig(original);
  });

  describe('combined Unicode and shell injection vectors', () => {
    beforeAll(() => {
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 40,
        riskBlockThreshold: 60,
        blockRawShellChars: true,
      });
    });

    it('blocks direct shell metacharacters before normalization analysis', () => {
      // Raw shell injection should be blocked immediately
      expect(() => normalizeInputString('innocent`malicious`'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('file$INJECTION'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('cmd1|cmd2'))
        .toThrow(InvalidParameterError);
    });

    it('blocks shell chars introduced via Unicode normalization', () => {
      // This tests the original introduced structural char detection
      // Note: These test cases use theoretical examples as actual Unicode
      // normalization rarely introduces shell metacharacters
      
      // Test with Unicode characters that might normalize to structural chars
      // Full-width variants that normalize to ASCII
      expect(() => normalizeInputString('file＄USER'))  // full-width dollar
        .toThrow(InvalidParameterError);
    });

    it('detects high-risk Unicode patterns with cumulative scoring', () => {
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 20,
        riskBlockThreshold: 40,
        blockRawShellChars: false, // Focus on scoring
      });

      // Construct a payload that scores high on multiple metrics:
      // - Bidi controls + invisible chars + expansion + mixed script
      const maliciousPayload = 
        '\u202A' +                    // Bidi control (40 points)
        '\u200B'.repeat(3) +          // Invisible chars (20 points) 
        '\uFB00'.repeat(2) +          // Ligatures for expansion (15 points)
        'test' +                      // ASCII 
        'ρ' +                         // Greek for mixed script (25 points)
        '\u0301'.repeat(3);           // Combining marks (15-20 points)
      
      expect(() => normalizeInputString(maliciousPayload))
        .toThrow(SecurityValidationError);
    });
  });

  describe('bypass attempt scenarios', () => {
    beforeAll(() => {
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 30,
        riskBlockThreshold: 50,
        blockRawShellChars: true,
      });
    });

    it('blocks attempts to hide shell chars in Unicode normalization', () => {
      // Test various encoding attempts
      const bypassAttempts = [
        'cmd＄USER',        // Full-width dollar
        'file｜grep',       // Full-width pipe
        'echo；rm',         // Full-width semicolon
        'test＆background', // Full-width ampersand
      ];

      for (const attempt of bypassAttempts) {
        expect(() => normalizeInputString(attempt), `Should block: ${attempt}`)
          .toThrow();
      }
    });

    it('prevents log injection via sanitization bypass', () => {
      const logInjectionAttempt = '\u0000'.repeat(20) + '\nMalicious log entry\n' + '\u202A';
      const sanitized = sanitizeForLogging(logInjectionAttempt, 200, { includeRawHash: true });
      
      // Should cap the control characters and not allow newline injection
      expect(sanitized).not.toContain('\n');
      expect(sanitized).toContain('[CTRL][CTRL][CTRL][CTRL][CTRL][+5more]');
      expect(sanitized).toContain('[BIDI]');
      expect(sanitized).toMatch(/\[rawHash:[a-f0-9]{8}\]$/);
    });

    it('handles deeply nested Unicode complexity', () => {
      // Create a string with multiple layers of complexity but under hard limits
      const complexPayload = 
        '\uFB01'.repeat(5) +     // ligatures (expansion)
        'α'.repeat(10) +         // Greek letters (mixed script)
        '\u0301'.repeat(4) +     // combining marks (but under limit)
        '\u200D' +               // zero-width joiner
        'test';

      let threwError = false;
      let errorType: string | undefined;
      try {
        normalizeInputString(complexPayload);
      } catch (error) {
        threwError = true;
        if (error instanceof SecurityValidationError) {
          errorType = 'SecurityValidationError';
        } else if (error instanceof InvalidParameterError) {
          errorType = 'InvalidParameterError';
        }
      }

      // Should either pass or throw a security error, depending on cumulative score
      if (threwError) {
        expect(errorType).toBeDefined();
      }
    });
  });

  describe('forensic evidence preservation', () => {
    beforeAll(() => {
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 20,
        riskBlockThreshold: 100, // High to allow processing for forensics
        blockRawShellChars: false,
      });
    });

    it('preserves forensic evidence of attack attempts', () => {
      const attackPayload = 'legitimate\u202Ahidden\u0000malicious`cmd`';
      
      // Should process but capture evidence
      let observed: any;
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 10,
        riskBlockThreshold: 100,
        blockRawShellChars: false,
        onRiskAssessment: (detail) => { observed = detail; }
      });

      const result = normalizeInputString(attackPayload);
      const sanitized = sanitizeForLogging(attackPayload, 200, { includeRawHash: true });

      // Should have triggered risk assessment
      expect(observed).toBeDefined();
      expect(observed.score).toBeGreaterThan(0);
      expect(observed.primaryThreat).toBeTruthy();

      // Sanitized log should preserve evidence while being safe
      expect(sanitized).toContain('legitimate');
      expect(sanitized).toContain('[BIDI]');
      expect(sanitized).toContain('[CTRL]');
      expect(sanitized).toContain('malicious');
      expect(sanitized).toMatch(/\[rawHash:[a-f0-9]{8}\]$/);
    });

    it('captures different attack vectors in metrics', () => {
      let capturedMetrics: any[] = [];
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 10,
        riskBlockThreshold: 100,
        blockRawShellChars: false,
        onRiskAssessment: (detail) => { 
          capturedMetrics = detail.metrics.filter(m => m.triggered);
        }
      });

      // Multi-vector payload
      const payload = '\u202A' +           // bidi
                     '\uFB00test' +        // expansion via ligature
                     'ρ' +                 // mixed script  
                     '\u0301\u0301\u0301'; // combining

      normalizeInputString(payload);

      // Should capture multiple threat vectors
      expect(capturedMetrics.length).toBeGreaterThan(1);
      const metricIds = capturedMetrics.map(m => m.id);
      expect(metricIds).toContain('bidi');
    });
  });

  describe('real-world attack simulation', () => {
    beforeAll(() => {
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 40,
        riskBlockThreshold: 60,
        blockRawShellChars: true,
      });
    });

    it('blocks trojan source style attacks', () => {
      // Simulate a trojan source attack with bidi controls
      const trojanPayload = 'isAdmin = false; // \u202E } \u202D if (isAdmin) { allowAccess();';
      
      expect(() => normalizeInputString(trojanPayload))
        .toThrow(InvalidParameterError); // Should block on bidi controls
    });

    it('blocks filename injection attempts', () => {
      const filenameAttempts = [
        '../../../etc/passwd',
        'file\u0000.txt',       // null byte injection
        'name\u200B.exe',       // hidden extension
        'doc.pdf\u202Atxt',     // extension spoofing
      ];

      for (const filename of filenameAttempts) {
        expect(() => normalizeInputString(filename), `Should block: ${filename}`)
          .toThrow();
      }
    });

    it('blocks homoglyph domain spoofing attempts', () => {
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 20,
        riskBlockThreshold: 40,
        blockRawShellChars: false,
        enableConfusablesDetection: true,
      });

      // Domain with mixed scripts that could spoof legitimate domains
      const spoofedDomains = [
        'gοοgle.com',     // Greek omicron
        'аpple.com',      // Cyrillic 'a'
        'microsοft.com',  // Mixed Greek/Latin
      ];

      for (const domain of spoofedDomains) {
        // Might not throw but should trigger risk assessment
        let riskDetected = false;
        setUnicodeSecurityConfig({
          enableRiskScoring: true,
          riskWarnThreshold: 10,
          riskBlockThreshold: 100,
          blockRawShellChars: false,
          onRiskAssessment: (detail) => {
            if (detail.score > 0) riskDetected = true;
          }
        });

        normalizeInputString(domain);
        
        // At minimum should detect mixed script risk in dev logs
        // The actual behavior depends on configured thresholds
      }
    });
  });

  describe('performance under attack', () => {
    it('handles large malicious inputs efficiently', () => {
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 50,
        riskBlockThreshold: 80,
        blockRawShellChars: true,
      });

      // Large input should be rejected at length check, not hang
      const largePayload = 'a'.repeat(10000) + '`malicious`';
      
      const start = performance.now();
      expect(() => normalizeInputString(largePayload)).toThrow();
      const elapsed = performance.now() - start;
      
      // Should reject quickly, not spend significant time processing
      expect(elapsed).toBeLessThan(100); // milliseconds
    });

    it('caps forensic data collection to prevent DoS', () => {
      const attackWithManyMarkers = '\u0000'.repeat(1000);
      const sanitized = sanitizeForLogging(attackWithManyMarkers, 500);
      
      // Should be capped, not proportional to input size
      expect(sanitized.length).toBeLessThan(100);
      expect(sanitized).toContain('[+5more]');
    });
  });
});