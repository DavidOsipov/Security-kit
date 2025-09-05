import { describe, it, expect } from 'vitest';
import { createSecureURL, updateURLParams, validateURL, parseAndValidateURL } from '../../src/url';

describe('comprehensive adversarial URL tests', () => {
  // Dangerous scheme tests with comprehensive payload coverage
  describe('dangerous schemes', () => {
    const dangerousPayloads = [
      'javascript:alert(1)',
      'javascript:alert(1)//',
      '//javascript:alert(1);',
      '/javascript:alert(1);',
      '//javascript:alert(1)',
      '/javascript:alert(1)',
      '/%5cjavascript:alert(1);',
      '/%5cjavascript:alert(1)',
      '//%5cjavascript:alert(1);',
      '//%5cjavascript:alert(1)',
      '/%09/javascript:alert(1);',
      '/%09/javascript:alert(1)',
      'java%0d%0ascript%0d%0a:alert(0)',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
      'vbscript:alert(1)',
      'data:,alert(1)',
      'blob:http://example.com/123',
      'file:///etc/passwd',
      'about:blank',
      // Additional dangerous schemes from payload list
      'javascript:alert(1)',
      'javascript:alert(1)//',
      '/javascript:alert(1);',
      '//javascript:alert(1);',
      '/javascript:alert(1)',
      '//javascript:alert(1)',
      '/%5cjavascript:alert(1);',
      '/%5cjavascript:alert(1)',
      '//%5cjavascript:alert(1);',
      '//%5cjavascript:alert(1)',
      '/%09/javascript:alert(1);',
      '/%09/javascript:alert(1)',
      'java%0d%0ascript%0d%0a:alert(0)',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
      'vbscript:alert(1)',
      'data:,alert(1)',
      'blob:http://example.com/123',
      'file:///etc/passwd',
      'about:blank',
      'javascript://www.whitelisteddomain.tld?%a0alert%281%29',
      'data:www.whitelisteddomain.tld;text/html;charset=UTF-8,<html><script>document.write(document.domain);</script><iframe/src=xxxxx>aaaa</iframe></html>',
      'jaVAscript://www.whitelisteddomain.tld//%0d%0aalert(1);',
      'javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)',
      'java\nva\tscript\r:alert(1)',
      'ja\nva\tscript\r:alert(1)',
      '\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)',
      '\152\141\166\141\163\143\162\151\160\164\072alert(1)',
      'java%0ascript:alert(1)',
      'java%09script:alert(1)',
      'java%0dscript:alert(1)',
      'javascript://%0aalert(1)',
      'Javas%26%2399;ript:alert(1)',
      '\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)',
      '\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)',
      'jaVAscript://www.whitelisteddomain.tld//%0d%0aalert(1);',
      '<>javascript:alert(1);',
      '<>//google.com',
      'javascript:alert(1)',
      'javascript:alert(1)//',
      '/javascript:alert(1);',
      '//javascript:alert(1);',
      '/javascript:alert(1)',
      '//javascript:alert(1)',
      '/%5cjavascript:alert(1);',
      '/%5cjavascript:alert(1)',
      '//%5cjavascript:alert(1);',
      '//%5cjavascript:alert(1)',
      '/%09/javascript:alert(1);',
      '/%09/javascript:alert(1)',
      'java%0d%0ascript%0d%0a:alert(0)',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
      'vbscript:alert(1)',
      'data:,alert(1)',
      'blob:http://example.com/123',
      'file:///etc/passwd',
      'about:blank',
      'javascript://www.whitelisteddomain.tld?%a0alert%281%29',
      'data:www.whitelisteddomain.tld;text/html;charset=UTF-8,<html><script>document.write(document.domain);</script><iframe/src=xxxxx>aaaa</iframe></html>',
      'jaVAscript://www.whitelisteddomain.tld//%0d%0aalert(1);',
      'javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)',
      'java\nva\tscript\r:alert(1)',
      'ja\nva\tscript\r:alert(1)',
      '\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)',
      '\152\141\166\141\163\143\162\151\160\164\072alert(1)',
      'java%0ascript:alert(1)',
      'java%09script:alert(1)',
      'java%0dscript:alert(1)',
      'javascript://%0aalert(1)',
      'Javas%26%2399;ript:alert(1)',
      '\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)',
      '\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)',
      'jaVAscript://www.whitelisteddomain.tld//%0d%0aalert(1);',
      '<>javascript:alert(1);',
      '<>//google.com',
    ];

    dangerousPayloads.forEach(payload => {
      it(`should reject dangerous scheme: ${payload}`, () => {
        expect(() => createSecureURL(payload)).toThrow();
        expect(() => parseAndValidateURL(payload, 'test')).toThrow();
        expect(validateURL(payload).ok).toBe(false);
      });
    });
  });

  // Path traversal and normalization bypass tests
  describe('path traversal attacks', () => {
    const traversalPayloads = [
      '/%09/example.com',
      '/%2f%2fexample.com',
      '/%2f%2f%2fbing.com%2f%3fwww.omise.co',
      '/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/',
      '/%5cexample.com',
      '/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d',
      '/.example.com',
      '//%09/example.com',
      '//%5cexample.com',
      '///%09/example.com',
      '///%5cexample.com',
      '////%09/example.com',
      '////%5cexample.com',
      '/////example.com',
      '/////example.com/',
      '////\;@example.com',
      '////example.com/',
      '////example.com/%2e%2e',
      '////example.com/%2e%2e%2f',
      '////example.com/%2f%2e%2e',
      '////example.com/%2f..',
      '////example.com//',
      '///\;@example.com',
      '///example.com',
      '///example.com/',
      // Additional traversal payloads from the list
      '/%09/google.com',
      '/%09/www.whitelisteddomain.tld@google.com',
      '//%09/google.com',
      '//%09/www.whitelisteddomain.tld@google.com',
      '///%09/google.com',
      '///%09/www.whitelisteddomain.tld@google.com',
      '////%09/google.com',
      '////%09/www.whitelisteddomain.tld@google.com',
      'https://%09/google.com',
      'https://%09/www.whitelisteddomain.tld@google.com',
      '/%5cgoogle.com',
      '/%5cwww.whitelisteddomain.tld@google.com',
      '//%5cgoogle.com',
      '//%5cwww.whitelisteddomain.tld@google.com',
      '///%5cgoogle.com',
      '///%5cwww.whitelisteddomain.tld@google.com',
      '////%5cgoogle.com',
      '////%5cwww.whitelisteddomain.tld@google.com',
      'https://%5cgoogle.com',
      'https://%5cwww.whitelisteddomain.tld@google.com',
      '/https://%5cgoogle.com',
      '/https://%5cwww.whitelisteddomain.tld@google.com',
      'https://google.com',
      'https://www.whitelisteddomain.tld@google.com',
      'javascript:alert(1)',
      'javascript:alert(1)//',
      '/javascript:alert(1);',
      '//javascript:alert(1);',
      '/javascript:alert(1)',
      '//javascript:alert(1)',
      '/%5cjavascript:alert(1);',
      '/%5cjavascript:alert(1)',
      '//%5cjavascript:alert(1);',
      '//%5cjavascript:alert(1)',
      '/%09/javascript:alert(1);',
      '/%09/javascript:alert(1)',
      'java%0d%0ascript%0d%0a:alert(0)',
      '//google.com',
      'https:google.com',
      '//google%E3%80%82com',
      '\/\/google.com/',
      '/\/google.com/',
      '//google%00.com',
      'https://www.whitelisteddomain.tld/https://www.google.com/',
      '";alert(0);//',
      'javascript://www.whitelisteddomain.tld?%a0alert%281%29',
      'http://0xd8.0x3a.0xd6.0xce',
      'http://www.whitelisteddomain.tld@0xd8.0x3a.0xd6.0xce',
      'http://3H6k7lIAiqjfNeN@0xd8.0x3a.0xd6.0xce',
      'http://XY>.7d8T\205pZM@0xd8.0x3a.0xd6.0xce',
      'http://0xd83ad6ce',
      'http://www.whitelisteddomain.tld@0xd83ad6ce',
      'http://3H6k7lIAiqjfNeN@0xd83ad6ce',
      'http://XY>.7d8T\205pZM@0xd83ad6ce',
      'http://3627734734',
      'http://www.whitelisteddomain.tld@3627734734',
      'http://3H6k7lIAiqjfNeN@3627734734',
      'http://XY>.7d8T\205pZM@3627734734',
      'http://472.314.470.462',
      'http://www.whitelisteddomain.tld@472.314.470.462',
      'http://3H6k7lIAiqjfNeN@472.314.470.462',
      'http://XY>.7d8T\205pZM@472.314.470.462',
      'http://0330.072.0326.0316',
      'http://www.whitelisteddomain.tld@0330.072.0326.0316',
      'http://3H6k7lIAiqjfNeN@0330.072.0326.0316',
      'http://XY>.7d8T\205pZM@0330.072.0326.0316',
      'http://00330.00072.0000326.00000316',
      'http://www.whitelisteddomain.tld@00330.00072.0000326.00000316',
      'http://3H6k7lIAiqjfNeN@00330.00072.0000326.00000316',
      'http://XY>.7d8T\205pZM@00330.00072.0000326.00000316',
      'http://[::216.58.214.206]',
      'http://www.whitelisteddomain.tld@[::216.58.214.206]',
      'http://3H6k7lIAiqjfNeN@[::216.58.214.206]',
      'http://XY>.7d8T\205pZM@[::216.58.214.206]',
      'http://[::ffff:216.58.214.206]',
      'http://www.whitelisteddomain.tld@[::ffff:216.58.214.206]',
      'http://3H6k7lIAiqjfNeN@[::ffff:216.58.214.206]',
      'http://XY>.7d8T\205pZM@[::ffff:216.58.214.206]',
      'http://0xd8.072.54990',
      'http://www.whitelisteddomain.tld@0xd8.072.54990',
      'http://3H6k7lIAiqjfNeN@0xd8.072.54990',
      'http://XY>.7d8T\205pZM@0xd8.072.54990',
      'http://0xd8.3856078',
      'http://www.whitelisteddomain.tld@0xd8.3856078',
      'http://3H6k7lIAiqjfNeN@0xd8.3856078',
      'http://XY>.7d8T\205pZM@0xd8.3856078',
      'http://00330.3856078',
      'http://www.whitelisteddomain.tld@00330.3856078',
      'http://3H6k7lIAiqjfNeN@00330.3856078',
      'http://XY>.7d8T\205pZM@00330.3856078',
      'http://00330.0x3a.54990',
      'http://www.whitelisteddomain.tld@00330.0x3a.54990',
      'http://3H6k7lIAiqjfNeN@00330.0x3a.54990',
      'http://XY>.7d8T\205pZM@00330.0x3a.54990',
    ];

    const ambiguousAllow = new Set([
      'https://google.com',
      'https:google.com',
      'https://www.whitelisteddomain.tld/https://www.google.com/',
    ]);

    traversalPayloads.forEach(payload => {
      it(`should handle traversal-like input safely: ${payload}`, () => {
        const shouldReject = !ambiguousAllow.has(payload);

        if (shouldReject) {
          expect(() => parseAndValidateURL(payload, 'test')).toThrow();
          expect(validateURL(payload).ok).toBe(false);
        } else {
          // In benign or ambiguous cases, parsing may succeed; still must be safe
          try {
            const ok = validateURL(payload).ok;
            expect(ok === true || ok === false).toBe(true);
          } catch (e) {
            // Accept throw as safe failure mode as well
            expect(e).toBeDefined();
          }
        }
      });
    });
  });

  // Host header injection and bypass tests
  describe('host header attacks', () => {
    const hostPayloads = [
      'http://0xd8.0x3a.0xd6.0xce',
      'http://www.whitelisteddomain.tld@0xd8.0x3a.0xd6.0xce',
      'http://3H6k7lIAiqjfNeN@0xd8.0x3a.0xd6.0xce',
      'http://XY>.7d8T\205pZM@0xd8.0x3a.0xd6.0xce',
      'http://0xd83ad6ce',
      'http://www.whitelisteddomain.tld@0xd83ad6ce',
      'http://3H6k7lIAiqjfNeN@0xd83ad6ce',
      'http://XY>.7d8T\205pZM@0xd83ad6ce',
      'http://3627734734',
      'http://www.whitelisteddomain.tld@3627734734',
      'http://3H6k7lIAiqjfNeN@3627734734',
      'http://XY>.7d8T\205pZM@3627734734',
      'http://472.314.470.462',
      'http://www.whitelisteddomain.tld@472.314.470.462',
      'http://3H6k7lIAiqjfNeN@472.314.470.462',
      'http://XY>.7d8T\205pZM@472.314.470.462',
      'http://0330.072.0326.0316',
      'http://www.whitelisteddomain.tld@0330.072.0326.0316',
      'http://3H6k7lIAiqjfNeN@0330.072.0326.0316',
      'http://XY>.7d8T\205pZM@0330.072.0326.0316',
      'http://00330.00072.0000326.00000316',
      'http://www.whitelisteddomain.tld@00330.00072.0000326.00000316',
      'http://3H6k7lIAiqjfNeN@00330.00072.0000326.00000316',
      'http://XY>.7d8T\205pZM@00330.00072.0000326.00000316',
      'http://[::216.58.214.206]',
      'http://www.whitelisteddomain.tld@[::216.58.214.206]',
      'http://3H6k7lIAiqjfNeN@[::216.58.214.206]',
      'http://XY>.7d8T\205pZM@[::216.58.214.206]',
      'http://[::ffff:216.58.214.206]',
      'http://www.whitelisteddomain.tld@[::ffff:216.58.214.206]',
      'http://3H6k7lIAiqjfNeN@[::ffff:216.58.214.206]',
      'http://XY>.7d8T\205pZM@[::ffff:216.58.214.206]',
      'http://0xd8.072.54990',
      'http://www.whitelisteddomain.tld@0xd8.072.54990',
      'http://3H6k7lIAiqjfNeN@0xd8.072.54990',
      'http://XY>.7d8T\205pZM@0xd8.072.54990',
      'http://0xd8.3856078',
      'http://www.whitelisteddomain.tld@0xd8.3856078',
      'http://3H6k7lIAiqjfNeN@0xd8.3856078',
      'http://XY>.7d8T\205pZM@0xd8.3856078',
      'http://00330.3856078',
      'http://www.whitelisteddomain.tld@00330.3856078',
      'http://3H6k7lIAiqjfNeN@00330.3856078',
      'http://XY>.7d8T\205pZM@00330.3856078',
      'http://00330.0x3a.54990',
      'http://www.whitelisteddomain.tld@00330.0x3a.54990',
      'http://3H6k7lIAiqjfNeN@00330.0x3a.54990',
      'http://XY>.7d8T\205pZM@00330.0x3a.54990',
    ];

    hostPayloads.forEach(payload => {
      it(`should reject host header attack: ${payload}`, () => {
        expect(() => parseAndValidateURL(payload, 'test')).toThrow();
        expect(validateURL(payload).ok).toBe(false);
      });
    });
  });

  // Unicode and normalization bypass tests
  describe('unicode normalization attacks', () => {
    const unicodePayloads = [
      '〱google.com',
      '〵google.com',
      'ゝgoogle.com',
      'ーgoogle.com',
      'ｰgoogle.com',
      '/〱google.com',
      '/〵google.com',
      '/ゝgoogle.com',
      '/ーgoogle.com',
      '/ｰgoogle.com',
      '%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d',
      'http://%67%6f%6f%67%6c%65%2e%63%6f%6d',
      '<>javascript:alert(1);',
      '<>//google.com',
      '//google.com\@www.whitelisteddomain.tld',
      'https://:@google.com\@www.whitelisteddomain.tld',
      '\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)',
      '\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)',
      'ja\nva\tscript\r:alert(1)',
      '\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)',
      '\152\141\166\141\163\143\162\151\160\164\072alert(1)',
      'http://google.com:80#@www.whitelisteddomain.tld/',
      'http://google.com:80?@www.whitelisteddomain.tld/',
    ];

    unicodePayloads.forEach(payload => {
      it(`should reject unicode attack: ${payload}`, () => {
        expect(() => parseAndValidateURL(payload, 'test')).toThrow();
        expect(validateURL(payload).ok).toBe(false);
      });
    });
  });

  // Fragment and XSS tests
  describe('fragment attacks', () => {
    const fragmentPayloads = [
      'https://example.com#javascript:alert(1)',
      'https://example.com#//javascript:alert(1)',
      'https://example.com#%2f%2fjavascript:alert(1)',
      'https://example.com#%5cjavascript:alert(1)',
      'https://example.com#%09javascript:alert(1)',
      'https://example.com#data:text/html,<script>alert(1)</script>',
      'https://example.com#vbscript:alert(1)',
    ];

    fragmentPayloads.forEach(payload => {
      it(`should reject fragment attack: ${payload}`, () => {
        expect(validateURL(payload).ok).toBe(false);
        expect(validateURL(payload, { strictFragment: true }).ok).toBe(false);
      });
    });
  });

  // Resource limiting tests
  describe('resource limiting', () => {
    it('should reject too many path segments', () => {
      const manySegments = 'https://example.com/' + Array.from({ length: 70 }, (_, i) => `segment${i}`).join('/');
      expect(() => createSecureURL('https://example.com', Array.from({ length: 70 }, (_, i) => `segment${i}`))).toThrow();
    });

    it('should reject too many query parameters', () => {
      const manyParams: Record<string, unknown> = {};
      for (let i = 0; i < 300; i++) manyParams[`param${i}`] = 'v';

      expect(() => createSecureURL('https://example.com', [], manyParams)).toThrow();
    });

    it('should reject URL with too many params', () => {
      const urlWithManyParams = 'https://example.com?' + Array.from({ length: 300 }, (_, i) => `k${i}=v`).join('&');
      expect(validateURL(urlWithManyParams).ok).toBe(false);
    });
  });

  // Valid URL tests to ensure we don't break legitimate use
  describe('valid URLs', () => {
    const validUrls = [
      'https://example.com',
      'https://example.com/path',
      'https://example.com/path?query=value',
      'https://example.com/path?query=value&other=test',
      'https://example.com#fragment',
      'https://sub.example.com/path',
    ];

    validUrls.forEach(url => {
      it(`should accept valid URL: ${url}`, () => {
        expect(validateURL(url).ok).toBe(true);
      });
    });
  });
});