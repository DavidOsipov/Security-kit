import { describe, it, expect } from 'vitest';
import { sanitizeForLogging } from '../src/canonical.ts';

describe('enhanced logging forensics', () => {
  describe('raw hash capture', () => {
    it('includes raw hash when requested', () => {
      const input = 'test\u0000input';
      const result = sanitizeForLogging(input, 200, { includeRawHash: true });
      
      expect(result).toMatch(/\[rawHash:[a-f0-9]{8}\]$/);
      expect(result).toContain('[CTRL]');
    });

    it('does not include hash by default', () => {
      const input = 'test\u0000input';
      const result = sanitizeForLogging(input, 200);
      
      expect(result).not.toMatch(/\[rawHash:/);
      expect(result).toContain('[CTRL]');
    });

    it('generates consistent hashes for identical inputs', () => {
      const input = 'test\u200Einput';
      const result1 = sanitizeForLogging(input, 200, { includeRawHash: true });
      const result2 = sanitizeForLogging(input, 200, { includeRawHash: true });
      
      const hash1 = result1.match(/\[rawHash:([a-f0-9]{8})\]$/)?.[1];
      const hash2 = result2.match(/\[rawHash:([a-f0-9]{8})\]$/)?.[1];
      
      expect(hash1).toBeDefined();
      expect(hash2).toBeDefined();
      expect(hash1).toBe(hash2);
    });

    it('generates different hashes for different inputs', () => {
      const input1 = 'test\u200Einput1';
      const input2 = 'test\u200Einput2';
      const result1 = sanitizeForLogging(input1, 200, { includeRawHash: true });
      const result2 = sanitizeForLogging(input2, 200, { includeRawHash: true });
      
      const hash1 = result1.match(/\[rawHash:([a-f0-9]{8})\]$/)?.[1];
      const hash2 = result2.match(/\[rawHash:([a-f0-9]{8})\]$/)?.[1];
      
      expect(hash1).toBeDefined();
      expect(hash2).toBeDefined();
      expect(hash1).not.toBe(hash2);
    });

    it('captures hash before normalization', () => {
      // Use a string that changes during normalization
      const input = '\uFB00test'; // ﬀtest (ligature that expands to "ff")
      const result = sanitizeForLogging(input, 200, { includeRawHash: true });
      
      // The hash should be based on the original ligature, not the expanded form
      const hash = result.match(/\[rawHash:([a-f0-9]{8})\]$/)?.[1];
      expect(hash).toBeDefined();
      
      // Compare with a hash of the expanded form to ensure they're different
      const expandedInput = 'fftest';
      const expandedResult = sanitizeForLogging(expandedInput, 200, { includeRawHash: true });
      const expandedHash = expandedResult.match(/\[rawHash:([a-f0-9]{8})\]$/)?.[1];
      
      expect(hash).not.toBe(expandedHash);
    });
  });

  describe('marker repetition capping', () => {
    it('caps BIDI marker repetitions', () => {
      const input = '\u202A'.repeat(10); // 10 left-to-right embedding characters
      const result = sanitizeForLogging(input, 200);
      
      // Should cap at 5 repetitions plus overflow indicator
      expect(result).toBe('[BIDI][BIDI][BIDI][BIDI][BIDI][+5more]');
    });

    it('caps CTRL marker repetitions', () => {
      const input = '\u0000'.repeat(8); // 8 null characters
      const result = sanitizeForLogging(input, 200);
      
      // Should cap at 5 repetitions plus overflow indicator
      expect(result).toBe('[CTRL][CTRL][CTRL][CTRL][CTRL][+5more]');
    });

    it('handles mixed dangerous characters correctly', () => {
      const input = '\u202A'.repeat(3) + '\u0000'.repeat(7) + 'test';
      const result = sanitizeForLogging(input, 200);
      
      expect(result).toContain('[BIDI][BIDI][BIDI]');
      expect(result).toContain('[CTRL][CTRL][CTRL][CTRL][CTRL][+5more]');
      expect(result).toContain('test');
    });

    it('does not cap when repetitions are under threshold', () => {
      const input = '\u202A'.repeat(3) + '\u0000'.repeat(2);
      const result = sanitizeForLogging(input, 200);
      
      expect(result).toBe('[BIDI][BIDI][BIDI][CTRL][CTRL]');
      expect(result).not.toContain('[+');
    });

    it('handles non-consecutive repetitions correctly', () => {
      const input = '\u202A' + 'test' + '\u202A'.repeat(8);
      const result = sanitizeForLogging(input, 200);
      
      // First BIDI should remain, consecutive ones should be capped
      expect(result).toContain('[BIDI]test');
      expect(result).toContain('[BIDI][BIDI][BIDI][BIDI][BIDI][+5more]');
    });

    it('prevents log flooding with excessive markers', () => {
      const input = '\u0000'.repeat(100); // Extreme case
      const result = sanitizeForLogging(input, 500); // Generous max length
      
      expect(result).toBe('[CTRL][CTRL][CTRL][CTRL][CTRL][+5more]');
      expect(result.length).toBeLessThan(50); // Much shorter than input would produce
    });
  });

  describe('combined hash and capping', () => {
    it('includes hash and caps markers when both features are used', () => {
      const input = '\u0000'.repeat(10) + 'test';
      const result = sanitizeForLogging(input, 200, { includeRawHash: true });
      
      expect(result).toContain('[CTRL][CTRL][CTRL][CTRL][CTRL][+5more]');
      expect(result).toContain('test');
      expect(result).toMatch(/\[rawHash:[a-f0-9]{8}\]$/);
    });

    it('maintains forensic value with very dangerous input', () => {
      const input = '\u202A'.repeat(5) + '\u0000'.repeat(5) + '\uFB00dangerous\u200E';
      const result = sanitizeForLogging(input, 200, { includeRawHash: true });
      
      // Should contain capped markers
      expect(result).toContain('[BIDI][BIDI][BIDI][BIDI][BIDI]');
      expect(result).toContain('[CTRL][CTRL][CTRL][CTRL][CTRL]');
      // Should contain normalized content
      expect(result).toContain('ffdangerous');
      // Should contain hash for forensic tracking
      expect(result).toMatch(/\[rawHash:[a-f0-9]{8}\]$/);
      
      // Should be reasonably bounded in length despite extreme input
      expect(result.length).toBeLessThan(150);
    });
  });

  describe('edge cases', () => {
    it('handles empty input gracefully', () => {
      const result1 = sanitizeForLogging('');
      const result2 = sanitizeForLogging('', 200, { includeRawHash: true });
      
      expect(result1).toBe('');
      expect(result2).toMatch(/^\[rawHash:[a-f0-9]{8}\]$/);
    });

    it('handles non-string input types', () => {
      const result1 = sanitizeForLogging(123, 200, { includeRawHash: true });
      const result2 = sanitizeForLogging(null, 200, { includeRawHash: true });
      const result3 = sanitizeForLogging(undefined, 200, { includeRawHash: true });
      
      expect(result1).toMatch(/^123 \[rawHash:[a-f0-9]{8}\]$/);
      expect(result2).toMatch(/^ \[rawHash:[a-f0-9]{8}\]$/);
      expect(result3).toMatch(/^ \[rawHash:[a-f0-9]{8}\]$/);
    });

    it('respects maxLength parameter with hash included', () => {
      const longInput = 'a'.repeat(100);
      const result = sanitizeForLogging(longInput, 20, { includeRawHash: true });
      
      expect(result.length).toBeLessThanOrEqual(20);
      expect(result).toMatch(/\[rawHash:[a-f0-9]{8}\]$/);
    });
  });
});