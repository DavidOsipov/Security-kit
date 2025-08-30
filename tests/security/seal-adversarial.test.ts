import { describe, it, expect, beforeEach } from 'vitest';
import {
  setHandshakeConfig,
  getHandshakeConfig,
  freezeConfig,
  setCrypto,
  sealSecurityKit,
} from '../../src/config';
import { __test_resetCryptoStateForUnitTests, ensureCryptoSync, getCryptoState, __resetCryptoStateForTests } from '../../src/state';
import { getInternalTestUtils } from '../../src/state';

// Adversarial tests to ensure sealing hardens the runtime configuration
describe('adversarial: sealing behavior', () => {
  it('seal without crypto should throw CryptoUnavailableError', () => {
    if (typeof __test_resetCryptoStateForUnitTests === 'function') __test_resetCryptoStateForUnitTests();
    let threw = false;
    try {
      // Attempt to call the underlying seal directly
      sealSecurityKit();
    } catch (err) {
      threw = true;
    }
    expect(threw).toBe(true);
    // Ensure we don't leave the runtime sealed for following tests
    if (typeof __test_resetCryptoStateForUnitTests === 'function') __test_resetCryptoStateForUnitTests();
  });

  describe('with mock crypto configured', () => {
    it('runs idempotent seal, setter-after-seal, and reset reconfiguration scenarios sequentially', () => {
      // Diagnostic helper to read internal state when available
      const internal = typeof getInternalTestUtils === 'function' ? getInternalTestUtils() : undefined;
      const readState = internal && typeof (internal as any)._getCryptoStateForTest === 'function'
        ? (internal as any)._getCryptoStateForTest
        : () => 'unknown';

      // Phase 1: idempotent sealing
  if (typeof __test_resetCryptoStateForUnitTests === 'function') __test_resetCryptoStateForUnitTests();
  // also support environment reset helper when available
  if (typeof __resetCryptoStateForTests === 'function') __resetCryptoStateForTests();
      ensureCryptoSync();
      // state should be configured now
      // First seal should succeed
      freezeConfig();
      // Second seal should be a no-op
      let threw = false;
      try {
        freezeConfig();
      } catch {
        threw = true;
      }
      expect(threw).toBe(false);

      // Phase 2: setHandshakeConfig should throw after seal and object mutation shouldn't affect internal state
  if (typeof __test_resetCryptoStateForUnitTests === 'function') __test_resetCryptoStateForUnitTests();
  if (typeof __resetCryptoStateForTests === 'function') __resetCryptoStateForTests();
  ensureCryptoSync();
  // silence diagnostic logs in finalized test
      setHandshakeConfig({ handshakeMaxNonceLength: 512 });
      const before = getHandshakeConfig();
  freezeConfig();
      let setterThrew = false;
      try {
        setHandshakeConfig({ handshakeMaxNonceLength: 128 });
      } catch (err) {
        setterThrew = true;
      }
      expect(setterThrew).toBe(true);
      const cfg = getHandshakeConfig() as any;
      const original = cfg.handshakeMaxNonceLength;
      try {
        cfg.handshakeMaxNonceLength = 16;
      } catch {}
      const after = getHandshakeConfig();
      expect(after.handshakeMaxNonceLength).toBe(original);

      // Phase 3: reset helper should allow reconfiguration again
      if (typeof __test_resetCryptoStateForUnitTests === 'function') __test_resetCryptoStateForUnitTests();
      if (typeof __resetCryptoStateForTests === 'function') __resetCryptoStateForTests();
      // After reset re-initialize and then setHandshakeConfig should succeed
      ensureCryptoSync();
      let threwReset = false;
      try {
        setHandshakeConfig({ handshakeMaxNonceLength: 42 });
      } catch (err) {
        threwReset = true;
      }
      expect(threwReset).toBe(false);
    });
  });
});
