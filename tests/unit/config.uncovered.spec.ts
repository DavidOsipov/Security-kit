import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  setLoggingConfig,
  getLoggingConfig,
  setSecureLRUProfiles,
  getSecureLRUProfiles,
  resolveSecureLRUOptions,
  setHandshakeConfig,
  getHandshakeConfig,
  setRuntimePolicy,
  getRuntimePolicy,
  setAppEnvironment,
  setProductionErrorHandler,
  configureErrorReporter,
  freezeConfig,
  setCrypto,
} from "../../src/config";
import { environment } from "../../src/environment";
import { __test_resetCryptoStateForUnitTests } from "../../src/state";
import { InvalidConfigurationError, InvalidParameterError } from "../../src/errors";

const savedEnv = environment.isProduction;

describe("config - uncovered branches", () => {
  beforeEach(() => {
    if (typeof __test_resetCryptoStateForUnitTests === "function") {
      __test_resetCryptoStateForUnitTests();
    }
    // Reset environment
    environment.setExplicitEnv(savedEnv ? "production" : "development");
  });

  afterEach(() => {
    if (typeof __test_resetCryptoStateForUnitTests === "function") {
      __test_resetCryptoStateForUnitTests();
    }
  });

  describe("setLoggingConfig validation errors", () => {
    it("rejects properties with getters/setters", () => {
      const configWithGetter = {};
      Object.defineProperty(configWithGetter, "allowUnsafeKeyNamesInDev", {
        get: () => true,
        enumerable: true,
      });

      expect(() => {
        setLoggingConfig(configWithGetter as any);
      }).toThrow(InvalidParameterError);
    });

    it("rejects non-boolean allowUnsafeKeyNamesInDev", () => {
      expect(() => {
        setLoggingConfig({ allowUnsafeKeyNamesInDev: "true" as any });
      }).toThrow(InvalidParameterError);
    });

    it("rejects non-boolean includeUnsafeKeyHashesInDev", () => {
      expect(() => {
        setLoggingConfig({ includeUnsafeKeyHashesInDev: 123 as any });
      }).toThrow(InvalidParameterError);
    });

    it("rejects non-string unsafeKeyHashSalt", () => {
      expect(() => {
        setLoggingConfig({ unsafeKeyHashSalt: 123 as any });
      }).toThrow(InvalidParameterError);
    });

    it("rejects non-positive-integer rateLimitTokensPerMinute", () => {
      expect(() => {
        setLoggingConfig({ rateLimitTokensPerMinute: 0 });
      }).toThrow(InvalidParameterError);

      expect(() => {
        setLoggingConfig({ rateLimitTokensPerMinute: -1 });
      }).toThrow(InvalidParameterError);

      expect(() => {
        setLoggingConfig({ rateLimitTokensPerMinute: 3.14 });
      }).toThrow(InvalidParameterError);
    });

    it("enforces production constraints", () => {
      environment.setExplicitEnv("production");

      expect(() => {
        setLoggingConfig({ allowUnsafeKeyNamesInDev: true });
      }).toThrow(InvalidParameterError);

      expect(() => {
        setLoggingConfig({ includeUnsafeKeyHashesInDev: true });
      }).toThrow(InvalidParameterError);
    });

    it("allows production constraints when explicitly set to false", () => {
      environment.setExplicitEnv("production");

      expect(() => {
        setLoggingConfig({
          allowUnsafeKeyNamesInDev: false,
          includeUnsafeKeyHashesInDev: false
        });
      }).not.toThrow();
    });
  });

  describe("setLoggingConfig after sealing", () => {
    it("throws when configuration is sealed", () => {
      // Set up crypto to allow sealing
      const mockCrypto = {
        getRandomValues: vi.fn((buffer: Uint8Array) => buffer),
      } as any;
      setCrypto(mockCrypto, { allowInProduction: true });
      freezeConfig();

      expect(() => {
        setLoggingConfig({ allowUnsafeKeyNamesInDev: true });
      }).toThrow(InvalidConfigurationError);
    });
  });

  describe("getLoggingConfig immutability", () => {
    it("returns frozen object", () => {
      const config = getLoggingConfig();
      expect(Object.isFrozen(config)).toBe(true);
    });

    it("prevents mutation of returned config", () => {
      const config = getLoggingConfig();
      expect(() => {
        (config as any).allowUnsafeKeyNamesInDev = true;
      }).toThrow();
    });
  });

  describe("setSecureLRUProfiles validation", () => {
    it("rejects unknown default profile", () => {
      expect(() => {
        setSecureLRUProfiles({
          defaultProfile: "non-existent-profile",
          profiles: []
        });
      }).toThrow(InvalidParameterError);
    });

    it("accepts valid profile configuration", () => {
      const customProfiles = [
        {
          name: "test-profile",
          description: "Test profile",
          options: {
            maxEntries: 100,
            defaultTtlMs: 60000,
          }
        }
      ];

      expect(() => {
        setSecureLRUProfiles({
          defaultProfile: "test-profile",
          profiles: customProfiles
        });
      }).not.toThrow();
    });
  });

  describe("setSecureLRUProfiles after sealing", () => {
    it("throws when configuration is sealed", () => {
      const mockCrypto = {
        getRandomValues: vi.fn((buffer: Uint8Array) => buffer),
      } as any;
      setCrypto(mockCrypto, { allowInProduction: true });
      freezeConfig();

      expect(() => {
        setSecureLRUProfiles({ defaultProfile: "balanced" });
      }).toThrow(InvalidConfigurationError);
    });
  });

  describe("getSecureLRUProfiles immutability", () => {
    it("returns object with frozen profiles array", () => {
      const config = getSecureLRUProfiles();
      expect(Object.isFrozen(config.profiles)).toBe(true);
    });

    it("prevents mutation of profiles array", () => {
      const config = getSecureLRUProfiles();
      expect(() => {
        config.profiles.push({
          name: "test",
          description: "test",
          options: {}
        });
      }).toThrow();
    });
  });

  describe("resolveSecureLRUOptions", () => {
    it("throws for unknown profile name", () => {
      expect(() => {
        resolveSecureLRUOptions("unknown-profile");
      }).toThrow(InvalidParameterError);
    });

    it("returns shallow clone of options", () => {
      const options = resolveSecureLRUOptions("balanced");
      const originalValue = options.maxEntries;

      // Modify the returned object
      (options as any).maxEntries = 999;

      // Get fresh options and verify original wasn't mutated
      const freshOptions = resolveSecureLRUOptions("balanced");
      expect(freshOptions.maxEntries).toBe(originalValue);
    });
  });

  describe("setHandshakeConfig additional validation", () => {
    it("rejects negative handshakeMaxNonceLength", () => {
      expect(() => {
        setHandshakeConfig({ handshakeMaxNonceLength: -1 });
      }).toThrow(InvalidParameterError);
    });

    it("rejects non-integer handshakeMaxNonceLength", () => {
      expect(() => {
        setHandshakeConfig({ handshakeMaxNonceLength: 64.5 });
      }).toThrow(InvalidParameterError);
    });

    it("rejects empty string in allowedNonceFormats", () => {
      expect(() => {
        setHandshakeConfig({ allowedNonceFormats: ["hex", ""] as any });
      }).toThrow(InvalidParameterError);
    });

    it("rejects non-array allowedNonceFormats", () => {
      expect(() => {
        setHandshakeConfig({ allowedNonceFormats: "hex" as any });
      }).toThrow(InvalidParameterError);
    });
  });

  describe("setHandshakeConfig after sealing", () => {
    it("throws when configuration is sealed", () => {
      const mockCrypto = {
        getRandomValues: vi.fn((buffer: Uint8Array) => buffer),
      } as any;
      setCrypto(mockCrypto, { allowInProduction: true });
      freezeConfig();

      expect(() => {
        setHandshakeConfig({ handshakeMaxNonceLength: 128 });
      }).toThrow(InvalidConfigurationError);
    });
  });

  describe("getHandshakeConfig immutability", () => {
    it("returns frozen object", () => {
      const config = getHandshakeConfig();
      expect(Object.isFrozen(config)).toBe(true);
    });

    it("prevents mutation of returned config", () => {
      const config = getHandshakeConfig();
      expect(() => {
        (config as any).handshakeMaxNonceLength = 999;
      }).toThrow();
    });
  });

  describe("setRuntimePolicy validation", () => {
    it("rejects non-boolean values", () => {
      expect(() => {
        setRuntimePolicy({ allowBlobUrls: "true" as any });
      }).toThrow(InvalidParameterError);

      expect(() => {
        setRuntimePolicy({ allowBlobWorkers: 123 as any });
      }).toThrow(InvalidParameterError);
    });

    it("filters unknown keys", () => {
      const originalPolicy = getRuntimePolicy();

      expect(() => {
        setRuntimePolicy({
          allowBlobUrls: true,
          unknownKey: "value" as any
        });
      }).not.toThrow();

      const newPolicy = getRuntimePolicy();
      expect(newPolicy.allowBlobUrls).toBe(true);
      // Unknown key should be ignored
      expect((newPolicy as any).unknownKey).toBeUndefined();
    });
  });

  describe("setRuntimePolicy after sealing", () => {
    it("throws when configuration is sealed", () => {
      const mockCrypto = {
        getRandomValues: vi.fn((buffer: Uint8Array) => buffer),
      } as any;
      setCrypto(mockCrypto, { allowInProduction: true });
      freezeConfig();

      expect(() => {
        setRuntimePolicy({ allowBlobUrls: true });
      }).toThrow(InvalidConfigurationError);
    });
  });

  describe("getRuntimePolicy immutability", () => {
    it("returns frozen object", () => {
      const policy = getRuntimePolicy();
      expect(Object.isFrozen(policy)).toBe(true);
    });

    it("prevents mutation of returned policy", () => {
      const policy = getRuntimePolicy();
      expect(() => {
        (policy as any).allowBlobUrls = false;
      }).toThrow();
    });
  });

  describe("setAppEnvironment validation", () => {
    it("rejects invalid environment values", () => {
      expect(() => {
        setAppEnvironment("invalid" as any);
      }).toThrow(InvalidParameterError);

      expect(() => {
        setAppEnvironment("" as any);
      }).toThrow(InvalidParameterError);
    });

    it("accepts valid environment values", () => {
      expect(() => {
        setAppEnvironment("development");
      }).not.toThrow();

      expect(() => {
        setAppEnvironment("production");
      }).not.toThrow();
    });
  });

  describe("setAppEnvironment after sealing", () => {
    it("throws when configuration is sealed", () => {
      const mockCrypto = {
        getRandomValues: vi.fn((buffer: Uint8Array) => buffer),
      } as any;
      setCrypto(mockCrypto, { allowInProduction: true });
      freezeConfig();

      expect(() => {
        setAppEnvironment("development");
      }).toThrow(InvalidConfigurationError);
    });
  });

  describe("setProductionErrorHandler after sealing", () => {
    it("throws when configuration is sealed", () => {
      const mockCrypto = {
        getRandomValues: vi.fn((buffer: Uint8Array) => buffer),
      } as any;
      setCrypto(mockCrypto, { allowInProduction: true });
      freezeConfig();

      expect(() => {
        setProductionErrorHandler(() => {});
      }).toThrow(InvalidConfigurationError);
    });
  });

  describe("configureErrorReporter after sealing", () => {
    it("throws when configuration is sealed", () => {
      const mockCrypto = {
        getRandomValues: vi.fn((buffer: Uint8Array) => buffer),
      } as any;
      setCrypto(mockCrypto, { allowInProduction: true });
      freezeConfig();

      expect(() => {
        configureErrorReporter({ burst: 10, refillRatePerSec: 1 });
      }).toThrow(InvalidConfigurationError);
    });
  });

  describe("freezeConfig idempotency", () => {
    it("can be called multiple times without error", () => {
      const mockCrypto = {
        getRandomValues: vi.fn((buffer: Uint8Array) => buffer),
      } as any;
      setCrypto(mockCrypto, { allowInProduction: true });

      expect(() => freezeConfig()).not.toThrow();
      expect(() => freezeConfig()).not.toThrow(); // Should be idempotent
    });
  });

  describe("configuration state isolation", () => {
    it("logging config changes don't affect other configs", () => {
      const originalHandshake = getHandshakeConfig();
      const originalPolicy = getRuntimePolicy();

      setLoggingConfig({ allowUnsafeKeyNamesInDev: true });

      expect(getHandshakeConfig()).toEqual(originalHandshake);
      expect(getRuntimePolicy()).toEqual(originalPolicy);
    });

    it("secure LRU config changes don't affect other configs", () => {
      const originalLogging = getLoggingConfig();
      const originalPolicy = getRuntimePolicy();

      setSecureLRUProfiles({ defaultProfile: "low-latency" });

      expect(getLoggingConfig()).toEqual(originalLogging);
      expect(getRuntimePolicy()).toEqual(originalPolicy);
    });
  });
});