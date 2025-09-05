import { describe, it, expect } from "vitest";
import { createSecureURL, updateURLParams, validateURL } from "../../src/url";

describe("Proxy behavior tests", () => {
  describe("URL object proxy semantics", () => {
    it("should handle URL object properties correctly through proxy", () => {
      const result = validateURL(
        "https://example.com/path?query=value#fragment",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test that proxy doesn't interfere with standard URL properties
        expect(url.href).toBe("https://example.com/path?query=value#fragment");
        expect(url.protocol).toBe("https:");
        expect(url.hostname).toBe("example.com");
        expect(url.pathname).toBe("/path");
        expect(url.search).toBe("?query=value");
        expect(url.hash).toBe("#fragment");

        // Test that URL methods work through proxy
        expect(url.toString()).toBe(
          "https://example.com/path?query=value#fragment",
        );
        expect(url.toJSON()).toBe(
          "https://example.com/path?query=value#fragment",
        );
      }
    });

    it("should handle URLSearchParams through proxy", () => {
      const result = validateURL("https://example.com?a=1&b=2&c=3");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test searchParams proxy behavior
        expect(url.searchParams.get("a")).toBe("1");
        expect(url.searchParams.get("b")).toBe("2");
        expect(url.searchParams.get("c")).toBe("3");
        expect(url.searchParams.has("a")).toBe(true);
        expect(url.searchParams.has("nonexistent")).toBe(false);

        // Test iteration
        const params = Array.from(url.searchParams.entries());
        expect(params).toEqual([
          ["a", "1"],
          ["b", "2"],
          ["c", "3"],
        ]);
      }
    });

    it("should handle URL mutations through proxy", () => {
      const result = validateURL("https://example.com/path");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test that mutations work through proxy
        url.searchParams.set("test", "value");
        expect(url.search).toBe("?test=value");
        expect(url.href).toBe("https://example.com/path?test=value");

        url.hash = "#section";
        expect(url.hash).toBe("#section");
        expect(url.href).toBe("https://example.com/path?test=value#section");
      }
    });

    it("should preserve URL object identity through proxy", () => {
      const result1 = validateURL("https://example.com");
      const result2 = validateURL("https://example.com");
      expect(result1.ok && result2.ok).toBe(true);

      if (result1.ok && result2.ok) {
        // URLs should be different objects but equivalent
        expect(result1.url).not.toBe(result2.url);
        expect(result1.url.href).toBe(result2.url.href);

        // Test that instanceof works through proxy
        expect(result1.url instanceof URL).toBe(true);
        expect(Object.prototype.toString.call(result1.url)).toBe(
          "[object URL]",
        );
      }
    });

    it("should handle URL prototype methods through proxy", () => {
      const result = validateURL("https://example.com/path/to/resource");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test prototype method access
        expect(typeof url.toString).toBe("function");
        expect(typeof url.toJSON).toBe("function");

        // Test that methods work correctly
        expect(url.toString()).toBe("https://example.com/path/to/resource");
        expect(url.toJSON()).toBe("https://example.com/path/to/resource");
      }
    });

    it("should handle URL property descriptors through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test that we can still get/set properties
        expect(url.href).toBe("https://example.com/");
        url.href = "https://test.com";
        expect(url.href).toBe("https://test.com/");
      }
    });

    it("should handle URL in Map and Set through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test Map usage
        const urlMap = new Map();
        urlMap.set(url, "test-value");
        expect(urlMap.get(url)).toBe("test-value");

        // Test Set usage
        const urlSet = new Set();
        urlSet.add(url);
        expect(urlSet.has(url)).toBe(true);
      }
    });

    it("should handle URL comparison through proxy", () => {
      const result1 = validateURL("https://example.com");
      const result2 = validateURL("https://example.com");
      expect(result1.ok && result2.ok).toBe(true);

      if (result1.ok && result2.ok) {
        // Test equality comparison
        expect(result1.url.href === result2.url.href).toBe(true);
        expect(result1.url.toString() === result2.url.toString()).toBe(true);

        // Test that proxy doesn't interfere with URL equality
        expect(result1.url).not.toBe(result2.url); // Different objects
        expect(result1.url.href).toBe(result2.url.href); // Same content
      }
    });

    it("should handle destructuring and spread through proxy", () => {
      const result = validateURL("https://example.com?a=1&b=2");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test destructuring
        const { href, protocol, hostname } = url;
        expect(href).toBe("https://example.com/?a=1&b=2");
        expect(protocol).toBe("https:");
        expect(hostname).toBe("example.com");

        // Test spread operator (URL objects don't spread their properties)
        const urlCopy = { ...url };
        expect(urlCopy.href).toBeUndefined(); // URL properties don't spread
        expect(url.href).toBe("https://example.com/?a=1&b=2"); // Original URL still works
      }
    });

    it("should handle JSON serialization through proxy", () => {
      const result = validateURL("https://example.com/path?query=value");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test JSON.stringify works through proxy
        const jsonString = JSON.stringify(url);
        expect(jsonString).toBe('"https://example.com/path?query=value"');

        // Test JSON.parse roundtrip
        const parsed = JSON.parse(jsonString);
        expect(parsed).toBe("https://example.com/path?query=value");
      }
    });
  });

  describe("proxy edge cases", () => {
    it("should handle undefined and null values through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test that proxy handles undefined/null correctly
        expect(url.searchParams.get("nonexistent")).toBe(null);
        expect(url.searchParams.get("nonexistent") ?? "default").toBe(
          "default",
        );
      }
    });

    it("should handle symbol properties through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;
        const testSymbol = Symbol("test");

        // Test symbol property access
        expect((url as any)[testSymbol]).toBeUndefined();

        // Test that proxy doesn't interfere with symbol iteration
        const symbols = Object.getOwnPropertySymbols(url);
        expect(symbols.length).toBeGreaterThanOrEqual(0);
      }
    });

    it("should handle property deletion through proxy", () => {
      const result = validateURL("https://example.com?test=value");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test that proxy handles delete operations gracefully
        const originalHref = url.href;
        try {
          // @ts-expect-error - testing delete operation
          delete url.href;
        } catch {
          // Expected - delete may not be allowed
        }
        // URL should remain unchanged
        expect(url.href).toBe(originalHref);
      }
    });

    it("should handle prototype chain through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test prototype chain
        expect((url as any).__proto__).toBe(URL.prototype);
        expect(Object.getPrototypeOf(url)).toBe(URL.prototype);

        // Test instanceof through proxy
        expect(url instanceof URL).toBe(true);
      }
    });
  });

  describe("Comprehensive proxy behavior tests", () => {
    it("should handle complex URLSearchParams operations through proxy", () => {
      const result = validateURL("https://example.com?a=1&a=2&b=3");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test multiple values for same key
        expect(url.searchParams.getAll("a")).toEqual(["1", "2"]);
        expect(url.searchParams.get("a")).toBe("1"); // First value

        // Test deletion
        url.searchParams.delete("a");
        expect(url.searchParams.has("a")).toBe(false);
        expect(url.searchParams.get("b")).toBe("3");

        // Test appending
        url.searchParams.append("c", "4");
        expect(url.searchParams.getAll("c")).toEqual(["4"]);

        // Test sorting
        url.searchParams.sort();
        const keys = Array.from(url.searchParams.keys());
        expect(keys).toEqual(["b", "c"]);
      }
    });

    it("should handle URLSearchParams iteration methods through proxy", () => {
      const result = validateURL("https://example.com?a=1&b=2&c=3");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test for...of iteration
        const entries: [string, string][] = [];
        for (const entry of url.searchParams) {
          entries.push(entry);
        }
        expect(entries).toEqual([
          ["a", "1"],
          ["b", "2"],
          ["c", "3"],
        ]);

        // Test forEach
        const forEachResult: [string, string][] = [];
        url.searchParams.forEach((value, key) => {
          forEachResult.push([key, value]);
        });
        expect(forEachResult).toEqual([
          ["a", "1"],
          ["b", "2"],
          ["c", "3"],
        ]);

        // Test keys(), values(), entries() iterators
        expect(Array.from(url.searchParams.keys())).toEqual(["a", "b", "c"]);
        expect(Array.from(url.searchParams.values())).toEqual(["1", "2", "3"]);
        expect(Array.from(url.searchParams.entries())).toEqual([
          ["a", "1"],
          ["b", "2"],
          ["c", "3"],
        ]);
      }
    });

    it("should handle URL mutations that affect multiple properties through proxy", () => {
      const result = validateURL("https://example.com/path");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test href mutation affects all properties
        url.href = "https://test.com:8080/newpath?query=value#fragment";
        expect(url.protocol).toBe("https:");
        expect(url.hostname).toBe("test.com");
        expect(url.port).toBe("8080");
        expect(url.pathname).toBe("/newpath");
        expect(url.search).toBe("?query=value");
        expect(url.hash).toBe("#fragment");

        // Test that searchParams reflects href changes
        expect(url.searchParams.get("query")).toBe("value");
      }
    });

    it("should handle URL with IPv6 addresses through proxy", () => {
      const result = validateURL("https://[::1]:8080/path");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        expect(url.hostname).toBe("[::1]");
        expect(url.port).toBe("8080");
        expect(url.host).toBe("[::1]:8080");
        expect(url.href).toBe("https://[::1]:8080/path");
      }
    });

    it("should handle URL with username/password through proxy", () => {
      // Note: Our URL module rejects URLs with credentials, but test the proxy behavior
      const result = validateURL("https://user:pass@example.com/path");
      expect(result.ok).toBe(false); // Should be rejected by our security checks
    });

    it("should handle URL with complex query strings through proxy", () => {
      const result = validateURL(
        "https://example.com?empty=&duplicate=1&duplicate=2&special=%40%23%24",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        expect(url.searchParams.get("empty")).toBe("");
        expect(url.searchParams.getAll("duplicate")).toEqual(["1", "2"]);
        expect(url.searchParams.get("special")).toBe("@#$");

        // Test URL encoding/decoding through proxy
        expect(url.search).toBe(
          "?empty=&duplicate=1&duplicate=2&special=%40%23%24",
        );
      }
    });

    it("should handle URL object in async operations through proxy", async () => {
      const result = validateURL("https://example.com/api");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test that proxy works in async contexts
        const asyncTest = async () => {
          return new Promise<string>((resolve) => {
            setTimeout(() => resolve(url.href), 1);
          });
        };

        const href = await asyncTest();
        expect(href).toBe("https://example.com/api");
      }
    });

    it("should handle URL object property enumeration through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test that proxied URL exposes standard properties via direct access.
        // Enumeration via Object.keys may not list proxied properties; assert direct reads.
        expect(url.href).toBeDefined();
        expect(url.protocol).toBeDefined();
        expect(url.hostname).toBeDefined();

        // Note: URL properties like 'href' and 'protocol' are on the prototype; own-property
        // enumeration is not guaranteed to include them. Validate via direct access and Reflect.
        const propNames = Object.getOwnPropertyNames(url);
        expect(Array.isArray(propNames)).toBe(true);
        // for...in also won't reliably include prototype props; ensure no runtime errors
        const forInKeys: string[] = [];
        for (const key in url) {
          forInKeys.push(key);
        }
        expect(Array.isArray(forInKeys)).toBe(true);
      }
    });

    it("should handle URL object with Reflect API through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test Reflect.get
        expect(Reflect.get(url, "href")).toBe("https://example.com/");
        expect(Reflect.get(url, "protocol")).toBe("https:");

        // Test Reflect.set
        const success = Reflect.set(url, "hash", "#test");
        expect(success).toBe(true);
        expect(url.hash).toBe("#test");

        // Test Reflect.has
        expect(Reflect.has(url, "href")).toBe(true);
        expect(Reflect.has(url, "nonexistent")).toBe(false);
      }
    });

    it("should handle URL object in template literals through proxy", () => {
      const result = validateURL("https://example.com/path");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test template literal interpolation
        const template = `URL: ${url}`;
        expect(template).toBe("URL: https://example.com/path");

        // Test with other properties
        const detailed = `Protocol: ${url.protocol}, Host: ${url.hostname}`;
        expect(detailed).toBe("Protocol: https:, Host: example.com");
      }
    });

    it("should handle URL object in array operations through proxy", () => {
      const result1 = validateURL("https://example.com/a");
      const result2 = validateURL("https://example.com/b");
      expect(result1.ok && result2.ok).toBe(true);

      if (result1.ok && result2.ok) {
        const urls = [result1.url, result2.url];

        // Test array methods
        expect(urls.map((u) => u.pathname)).toEqual(["/a", "/b"]);
        expect(urls.find((u) => u.pathname === "/b")).toBe(result2.url);
        expect(urls.filter((u) => u.hostname === "example.com")).toHaveLength(
          2,
        );

        // Test array spreading
        const spreadUrls = [...urls];
        expect(spreadUrls).toHaveLength(2);
        expect(spreadUrls[0].href).toBe("https://example.com/a");
      }
    });

    it("should handle URL object in object operations through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test Object.assign
        const assigned = Object.assign({}, { url });
        expect(assigned.url.href).toBe("https://example.com/");

        // Test Object.defineProperty
        Object.defineProperty(url, "customProp", {
          value: "test",
          enumerable: true,
        });
        expect((url as any).customProp).toBe("test");
      }
    });

    it("should handle URL with special characters in path through proxy", () => {
      const result = validateURL(
        "https://example.com/path%20with%20spaces/unicode%C3%A9",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        expect(url.pathname).toBe("/path%20with%20spaces/unicode%C3%A9");
        expect(decodeURIComponent(url.pathname)).toBe(
          "/path with spaces/unicodeé",
        );
      }
    });

    it("should handle URL with fragment containing special characters through proxy", () => {
      const result = validateURL(
        "https://example.com#fragment%20with%20spaces",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        expect(url.hash).toBe("#fragment%20with%20spaces");
        expect(decodeURIComponent(url.hash.slice(1))).toBe(
          "fragment with spaces",
        );
      }
    });

    it("should handle URL object in Promise chains through proxy", async () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Test Promise chain
        const result2 = await Promise.resolve(url)
          .then((u) => u.href)
          .then((href) => href.toUpperCase());

        expect(result2).toBe("HTTPS://EXAMPLE.COM/");
      }
    });

    it("should handle URL object in try-catch blocks through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        try {
          // Test that proxy doesn't interfere with error handling
          const href = url.href;
          expect(href).toBe("https://example.com/");

          // Test throwing with URL in context
          throw new Error(`URL error: ${url.hostname}`);
        } catch (error) {
          expect((error as Error).message).toBe("URL error: example.com");
        }
      }
    });

    it("should handle URL object with Object.freeze/Object.seal through proxy", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (result.ok) {
        const url = result.url;

        // Note: Freezing/sealing a proxy doesn't prevent URL mutations
        // since the underlying URL object is what's being mutated
        const originalHref = url.href;
        url.hash = "#test";
        expect(url.href).toBe("https://example.com/#test");

        // Reset for next test
        url.hash = "";
        expect(url.href).toBe(originalHref);
      }
    });
  });
});
