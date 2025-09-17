import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { normalizeInputString } from '../src/canonical.ts';
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig } from '../src/config.ts';
import { InvalidParameterError } from '../src/errors.ts';

describe('raw shell character blocking (optional defense-in-depth)', () => {
  const original = getUnicodeSecurityConfig();

  afterAll(() => {
    // Restore original configuration to avoid test order dependence.
    setUnicodeSecurityConfig({
      blockRawShellChars: original.blockRawShellChars,
    });
  });

  describe('when blockRawShellChars is disabled (default)', () => {
    beforeAll(() => {
      setUnicodeSecurityConfig({ blockRawShellChars: false });
    });

    it('allows raw shell metacharacters by default', () => {
      const testCases = [
        'command`whoami`',
        'file$USER.txt',
        'cmd1|cmd2',
        'cmd1;cmd2',
        'cmd1&cmd2',
        'array[index]',
        'object{key}',
        'path/to/file*',
        'command!',
        'home~dir',
      ];

      for (const input of testCases) {
        expect(() => normalizeInputString(input)).not.toThrow();
      }
    });
  });

  describe('when blockRawShellChars is enabled', () => {
    beforeAll(() => {
      setUnicodeSecurityConfig({ blockRawShellChars: true });
    });

    it('blocks raw backticks (command substitution)', () => {
      expect(() => normalizeInputString('command`whoami`'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('innocent`malicious'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw dollar signs (variable expansion)', () => {
      expect(() => normalizeInputString('file$USER.txt'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('echo $(whoami)'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw pipe characters (command chaining)', () => {
      expect(() => normalizeInputString('cmd1|cmd2'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('cat file | grep pattern'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw semicolons (command separation)', () => {
      expect(() => normalizeInputString('cmd1;cmd2'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('echo hello; rm -rf /'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw ampersands (background execution)', () => {
      expect(() => normalizeInputString('cmd1&cmd2'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('sleep 10 & echo done'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw parentheses (subshells)', () => {
      expect(() => normalizeInputString('(cd /tmp && rm *)'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('echo (test)'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw braces (brace expansion)', () => {
      expect(() => normalizeInputString('echo {1,2,3}'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('file{.txt,.bak}'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw brackets (character classes)', () => {
      expect(() => normalizeInputString('ls *.txt[0-9]'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('array[index]'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw tildes (home directory expansion)', () => {
      expect(() => normalizeInputString('~/.bashrc'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('cd ~/Documents'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw asterisks (glob expansion)', () => {
      expect(() => normalizeInputString('rm *'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('ls *.txt'))
        .toThrow(InvalidParameterError);
    });

    it('blocks raw exclamation marks (history expansion)', () => {
      expect(() => normalizeInputString('echo !!'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('run !last'))
        .toThrow(InvalidParameterError);
    });

    it('provides informative error messages', () => {
      expect(() => normalizeInputString('cmd`test`')).toThrow(/shell metacharacters.*`/);
      expect(() => normalizeInputString('var$test')).toThrow(/shell metacharacters.*\$/);
      expect(() => normalizeInputString('cmd1|cmd2')).toThrow(/shell metacharacters.*\|/);
    });

    it('detects multiple shell characters and reports them', () => {
      expect(() => normalizeInputString('cmd`test`|grep$VAR'))
        .toThrow(/shell metacharacters.*[`,|,$]/);
    });

    it('still allows safe characters', () => {
      const safeCases = [
        'normal-text',
        'hello_world',
        'file.txt',
        'path/to/file', // forward slash is structural but not shell-specific
        'query?param=value', // query chars are structural but not shell-specific
        'email@domain.com',
        'percentage-20%',
        'quoted"text"',
        "single'quotes",
        'hash#tag',
        'colon:value',
      ];

      for (const input of safeCases) {
        expect(() => normalizeInputString(input)).not.toThrow();
      }
    });

    it('blocks shell chars even when mixed with safe content', () => {
      expect(() => normalizeInputString('legitimate_file_name`dangerous`'))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString('normal-text$INJECTION'))
        .toThrow(InvalidParameterError);
    });
  });
});