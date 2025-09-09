import { describe, it, expect } from "vitest";
import { createSecureURL, updateURLParams, validateURL } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("URL Resource Limiting (Layer 5 DoS Protection)", () => {
  describe("createSecureURL - maxPathSegments", () => {
    it("should allow URLs within path segment limit", () => {
      const pathSegments = Array.from({ length: 60 }, (_, i) => `segment${i}`);
      const url = createSecureURL(
        "https://example.com",
        pathSegments,
        {},
        undefined,
        { maxPathSegments: 64 },
      );
      expect(url).toMatch(/^https:\/\/example\.com\/segment0\/segment1/);
    });

    it("should reject URLs exceeding path segment limit", () => {
      const pathSegments = Array.from({ length: 70 }, (_, i) => `segment${i}`);
      expect(() =>
        createSecureURL("https://example.com", pathSegments, {}, undefined, {
          maxPathSegments: 64,
        }),
      ).toThrow(InvalidParameterError);

      expect(() =>
        createSecureURL("https://example.com", pathSegments, {}, undefined, {
          maxPathSegments: 64,
        }),
      ).toThrow("Path segments exceed maximum allowed (64)");
    });

    it("should use default maxPathSegments of 64", () => {
      const pathSegments = Array.from({ length: 65 }, (_, i) => `segment${i}`);
      expect(() =>
        createSecureURL("https://example.com", pathSegments),
      ).toThrow("Path segments exceed maximum allowed (64)");
    });
  });

  describe("createSecureURL - maxQueryParameters", () => {
    it("should allow URLs within query parameter limit", () => {
      const queryParams: Record<string, string> = {};
      for (let i = 0; i < 250; i++) {
        queryParams[`param${i}`] = `value${i}`;
      }

      const url = createSecureURL(
        "https://example.com",
        [],
        queryParams,
        undefined,
        { maxQueryParameters: 256 },
      );
      expect(url).toMatch(/^https:\/\/example\.com\/\?param0=value0/);
    }, 20000);

    it("should reject URLs exceeding query parameter limit", () => {
      const queryParams: Record<string, string> = {};
      for (let i = 0; i < 300; i++) {
        queryParams[`param${i}`] = `value${i}`;
      }

      expect(() =>
        createSecureURL("https://example.com", [], queryParams, undefined, {
          maxQueryParameters: 256,
        }),
      ).toThrow(InvalidParameterError);

      expect(() =>
        createSecureURL("https://example.com", [], queryParams, undefined, {
          maxQueryParameters: 256,
        }),
      ).toThrow("Query parameters exceed maximum allowed (256)");
    });

    it("should use default maxQueryParameters of 256", () => {
      const queryParams: Record<string, string> = {};
      for (let i = 0; i < 300; i++) {
        queryParams[`param${i}`] = `value${i}`;
      }

      expect(() =>
        createSecureURL("https://example.com", [], queryParams),
      ).toThrow("Query parameters exceed maximum allowed (256)");
    }, 20000);
  });

  describe("createSecureURL - post-merge caps", () => {
    it("should enforce final query parameter cap after merging with base URL", () => {
      // Base URL with 250 params
      const baseParams = new URLSearchParams();
      for (let i = 0; i < 250; i++) {
        baseParams.set(`p${i}`, `v${i}`);
      }
      const baseUrl = `https://example.com/?${baseParams.toString()}`;

      // Add 10 more (→ 260 > 256)
      const extra: Record<string, string> = {};
      for (let i = 250; i < 260; i++) {
        extra[`p${i}`] = `v${i}`;
      }

      expect(() =>
        createSecureURL(baseUrl, [], extra, undefined, {
          maxQueryParameters: 256,
        }),
      ).toThrow(InvalidParameterError);

      expect(() =>
        createSecureURL(baseUrl, [], extra, undefined, {
          maxQueryParameters: 256,
        }),
      ).toThrow("Final query parameters exceed maximum allowed (256)");
    });

    it("should allow when final query parameter count equals the cap", () => {
      // Base URL with 250 params
      const baseParams = new URLSearchParams();
      for (let i = 0; i < 250; i++) {
        baseParams.set(`k${i}`, `v${i}`);
      }
      const baseUrl = `https://example.com/?${baseParams.toString()}`;

      // Add exactly 6 more (→ 256 == cap)
      const extra: Record<string, string> = {};
      for (let i = 250; i < 256; i++) {
        extra[`k${i}`] = `v${i}`;
      }

      const href = createSecureURL(baseUrl, [], extra, undefined, {
        maxQueryParameters: 256,
      });
      const u = new URL(href);
      expect(u.searchParams.size).toBe(256);
    });

    it("should enforce final path segment cap after merging with base URL", () => {
      // Base URL with 60 segments
      const basePath = Array.from({ length: 60 }, (_, i) => `s${i}`).join("/");
      const baseUrl = `https://example.com/${basePath}`;

      // Add 5 more segments (→ 65 > 64)
      const addSegments = Array.from({ length: 5 }, (_, i) => `t${i}`);

      expect(() =>
        createSecureURL(baseUrl, addSegments, {}, undefined, {
          maxPathSegments: 64,
        }),
      ).toThrow(InvalidParameterError);

      expect(() =>
        createSecureURL(baseUrl, addSegments, {}, undefined, {
          maxPathSegments: 64,
        }),
      ).toThrow("Path segments exceed maximum allowed (64)");
    });

    it("should allow when final path segment count equals the cap", () => {
      // Base URL with 60 segments
      const basePath = Array.from({ length: 60 }, (_, i) => `p${i}`).join("/");
      const baseUrl = `https://example.com/${basePath}`;

      // Add 4 more (→ 64 == cap)
      const addSegments = Array.from({ length: 4 }, (_, i) => `q${i}`);

      const href = createSecureURL(baseUrl, addSegments, {}, undefined, {
        maxPathSegments: 64,
      });
      const u = new URL(href);
      // Expect base segments + added ones
      expect(u.pathname.split("/").filter(Boolean).length).toBe(64);
    });
  });

  describe("updateURLParams - maxQueryParameters", () => {
    it("should allow updates within query parameter limit", () => {
      // Start with a URL that has 200 parameters
      const initialParams: Record<string, string> = {};
      for (let i = 0; i < 200; i++) {
        initialParams[`param${i}`] = `value${i}`;
      }
      const initialUrl = createSecureURL(
        "https://example.com",
        [],
        initialParams,
      );

      // Add 50 more parameters (total 250, under limit of 256)
      const updates: Record<string, string> = {};
      for (let i = 200; i < 250; i++) {
        updates[`param${i}`] = `value${i}`;
      }

      const updatedUrl = updateURLParams(initialUrl, updates, {
        maxQueryParameters: 256,
      });
      expect(updatedUrl).toMatch(/param249=value249/);
    }, 20000);

    it("should reject updates that would exceed query parameter limit", () => {
      // Start with a URL that has 200 parameters
      const initialParams: Record<string, string> = {};
      for (let i = 0; i < 200; i++) {
        initialParams[`param${i}`] = `value${i}`;
      }
      const initialUrl = createSecureURL(
        "https://example.com",
        [],
        initialParams,
      );

      // Try to add 100 more parameters (total 300, over limit of 256)
      const updates: Record<string, string> = {};
      for (let i = 200; i < 300; i++) {
        updates[`param${i}`] = `value${i}`;
      }

      expect(() =>
        updateURLParams(initialUrl, updates, { maxQueryParameters: 256 }),
      ).toThrow(InvalidParameterError);

      expect(() =>
        updateURLParams(initialUrl, updates, { maxQueryParameters: 256 }),
      ).toThrow("Final query parameters would exceed maximum allowed (256)");
    });

    it("should use default maxQueryParameters of 256", () => {
      // Start with a URL that has 200 parameters
      const initialParams: Record<string, string> = {};
      for (let i = 0; i < 200; i++) {
        initialParams[`param${i}`] = `value${i}`;
      }
      const initialUrl = createSecureURL(
        "https://example.com",
        [],
        initialParams,
      );

      // Try to add 100 more parameters (total 300, over default limit)
      const updates: Record<string, string> = {};
      for (let i = 200; i < 300; i++) {
        updates[`param${i}`] = `value${i}`;
      }

      expect(() => updateURLParams(initialUrl, updates)).toThrow(
        "Final query parameters would exceed maximum allowed (256)",
      );
    }, 20000);
  });

  describe("validateURL - maxQueryParameters", () => {
    it("should validate URLs within query parameter limit", () => {
      // Create a URL with many parameters
      const queryParams: Record<string, string> = {};
      for (let i = 0; i < 200; i++) {
        queryParams[`param${i}`] = `value${i}`;
      }
      const url = createSecureURL("https://example.com", [], queryParams);

      // Set a high maxLength to ensure we test the query parameter limit, not URL length
      const result = validateURL(url, {
        maxQueryParameters: 256,
        maxLength: 100000,
      });
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.url.searchParams.size).toBe(200);
      }
    });

    it("should reject URLs exceeding query parameter limit", () => {
      // Create a URL with many parameters
      const queryParams: Record<string, string> = {};
      for (let i = 0; i < 300; i++) {
        queryParams[`param${i}`] = `value${i}`;
      }

      // Create URL with higher limit, then validate with lower limit
      const url = createSecureURL(
        "https://example.com",
        [],
        queryParams,
        undefined,
        {
          maxQueryParameters: 500,
        },
      );

      const result = validateURL(url, {
        maxQueryParameters: 256,
        maxLength: 100000,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
        expect(result.error.message).toMatch(
          /URL query parameters exceed maximum allowed \(256\)/,
        );
      }
    });

    it("should use default maxQueryParameters of 256", () => {
      // Create a URL with many parameters
      const queryParams: Record<string, string> = {};
      for (let i = 0; i < 300; i++) {
        queryParams[`param${i}`] = `value${i}`;
      }

      // Create URL with higher limit, then validate with default limit
      const url = createSecureURL(
        "https://example.com",
        [],
        queryParams,
        undefined,
        {
          maxQueryParameters: 500,
        },
      );

      const result = validateURL(url, { maxLength: 100000 });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
        expect(result.error.message).toMatch(
          /URL query parameters exceed maximum allowed \(256\)/,
        );
      }
    }, 20000);
  });

  describe("DoS protection edge cases", () => {
    it("should handle Map-based query parameters correctly", () => {
      const queryMap = new Map<string, string>();
      for (let i = 0; i < 300; i++) {
        queryMap.set(`param${i}`, `value${i}`);
      }

      expect(() =>
        createSecureURL("https://example.com", [], queryMap),
      ).toThrow("Query parameters exceed maximum allowed (256)");
    });

    it("should handle empty path segments correctly", () => {
      // Use fewer than the cap so we test empty-segment validation, not the cap
      const pathSegments = Array.from({ length: 5 }, () => "");
      expect(() =>
        createSecureURL("https://example.com", pathSegments),
      ).toThrow(
        /Path segments must be non-empty strings shorter than 1024 chars/,
      );
    });

    it("should handle updateURLParams with Map updates", () => {
      const initialUrl = "https://example.com";
      const updates = new Map<string, string>();
      for (let i = 0; i < 300; i++) {
        updates.set(`param${i}`, `value${i}`);
      }

      expect(() => updateURLParams(initialUrl, updates)).toThrow(
        "Final query parameters would exceed maximum allowed (256)",
      );
    });
  });
});
