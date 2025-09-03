import { describe, it, expect, beforeEach } from "vitest";
import { setHandshakeConfig, freezeConfig, setCrypto } from "../../src/config";
import { __test_resetCryptoStateForUnitTests } from "../../src/state";

describe("configuration sealing", () => {
  beforeEach(() => {
    if (typeof __test_resetCryptoStateForUnitTests === "function") {
      __test_resetCryptoStateForUnitTests();
    }
    // Allow test-only APIs by ensuring __TEST__ guard is active in vitest runtime
  });

  it("prevents setHandshakeConfig after freezeConfig/sealSecurityKit", () => {
    // Provide a minimal mock crypto so sealSecurityKit precondition passes
    const mockCrypto = {
      getRandomValues(buffer: Uint8Array) {
        if (!(buffer instanceof Uint8Array))
          throw new Error("buffer must be Uint8Array");
        for (let i = 0; i < buffer.length; i++) buffer[i] = i % 256;
        return buffer;
      },
    } as unknown as Crypto;
    // Inject the mock crypto
    setCrypto(mockCrypto, { allowInProduction: true });

    // Initially we can set handshake config
    setHandshakeConfig({ handshakeMaxNonceLength: 128 });

    // Freeze configuration
    freezeConfig();

    // Now attempts to change config should throw InvalidConfigurationError
    let threw = false;
    try {
      setHandshakeConfig({ handshakeMaxNonceLength: 64 });
    } catch (err) {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});
