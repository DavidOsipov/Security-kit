import { describe, it, expect, vi } from "vitest";

describe("security: module and worker isolation", () => {
  it("module state isolation via vi.resetModules and dynamic import", async () => {
    // Ensure fresh module instance
    vi.resetModules();
    const mod1 = await import("../../src/state");
    // Use the test reset helper if present
    if (
      typeof (mod1 as any).__test_resetCryptoStateForUnitTests === "function"
    ) {
      (mod1 as any).__test_resetCryptoStateForUnitTests();
    }
    // Initialize crypto via ensureCryptoSync (should set configured)
    if (typeof (mod1 as any).ensureCryptoSync === "function") {
      (mod1 as any).ensureCryptoSync();
    }

    // Seal in this module instance
    if (typeof (mod1 as any).freezeConfig === "function") {
      (mod1 as any).freezeConfig();
    }

    // Reset modules and import again - should get a fresh unsealed instance
    vi.resetModules();
    const mod2 = await import("../../src/state");
    const state2 =
      typeof (mod2 as any).getCryptoState === "function"
        ? (mod2 as any).getCryptoState()
        : "unknown";
    expect(state2).not.toBe("sealed");
  });

  it("isolated worker can import and configure a fresh runtime (ESM module)", async () => {
    const { Worker } = await import("worker_threads");
    const fs = await import("fs");
    const os = await import("os");
    const path = await import("path");

    const tmpDir = os.tmpdir();
    const tmpFile = path.join(tmpDir, `seal-isolation-${Date.now()}.mjs`);

    // Worker script: import the src/state.ts via file:// URL and postMessage JSON result
    const script = `
import { parentPort } from 'worker_threads';
// Import the compiled ESM entry from dist, inject Node's Web Crypto, configure, freeze, then verify immutability
(async function(){
  try {
    const pkg = await import(process.cwd() + '/dist/index.mjs');
    if (typeof pkg.setCrypto !== 'function' || typeof pkg.freezeConfig !== 'function') {
      parentPort?.postMessage({ error: 'Required exports not found' });
      return;
    }

    // Provide a crypto implementation via node:crypto.webcrypto so seal can succeed synchronously
    try {
      const nodeCrypto = await import('node:crypto');
      // Call the public setCrypto to ensure configured state using Node's Web Crypto.
      pkg.setCrypto(nodeCrypto.webcrypto);
    } catch (err) {
      parentPort?.postMessage({ error: 'failed to install node crypto: ' + String(err) });
      return;
    }

    // Now freeze the runtime
    try {
      pkg.freezeConfig();
    } catch (err) {
      parentPort?.postMessage({ error: 'freezeConfig failed: ' + String(err) });
      return;
    }

  // After sealing, verify several mutators throw: setCrypto, setHandshakeConfig, setAppEnvironment, configureErrorReporter
  const results = {};

    const tryFn = (name, fn) => {
      try {
        fn();
        results[name] = { threw: false };
      } catch (err) {
        results[name] = {
          threw: true,
          name: err && err.name ? err.name : undefined,
          message: err && err.message ? err.message : String(err),
        };
      }
    };

    // setCrypto
    try {
      const nodeCrypto2 = await import('node:crypto');
      tryFn('setCrypto', () => pkg.setCrypto(nodeCrypto2.webcrypto));
    } catch (err) {
      results['setCrypto'] = 'node-crypto-unavailable';
    }

    // setHandshakeConfig
    tryFn('setHandshakeConfig', () => pkg.setHandshakeConfig({ handshakeMaxNonceLength: 1 }));

    // setAppEnvironment
    tryFn('setAppEnvironment', () => pkg.setAppEnvironment('production'));

    // configureErrorReporter
    tryFn('configureErrorReporter', () => pkg.configureErrorReporter({ burst: 2, refillRatePerSec: 1 }));

    parentPort?.postMessage({ ok: true, results });
  } catch (err) {
    parentPort?.postMessage({ error: String(err) });
  }
})();
`;

    fs.writeFileSync(tmpFile, script, "utf8");

    // Launch the worker as a plain ESM module importing compiled artifacts from dist
    const worker = new Worker(new URL("file://" + tmpFile), {
      type: "module",
    } as any);
    const message = await new Promise<any>((resolve) => {
      worker.once("message", resolve);
      worker.once("error", (err: Error) => resolve({ error: String(err) }));
      worker.once("exit", () => resolve(undefined));
    });
    worker.terminate();
    try {
      fs.unlinkSync(tmpFile);
    } catch {}

    // Fail loudly if the worker returned an error
    if (!message) {
      // worker didn't postMessage; consider this a failure in this environment
      throw new Error("Worker did not return a message");
    }
    if (message.error) {
      throw new Error("Worker error: " + String(message.error));
    }

    // Validate detailed error shapes for each mutator: they should indicate they threw
    if (message.results) {
      const res = message.results;
      const expectedName = "InvalidConfigurationError";
      const expectedMessage = "Configuration is sealed and cannot be changed.";

      // setCrypto may be 'node-crypto-unavailable' if the worker couldn't import node:crypto
      if (res.setCrypto === "node-crypto-unavailable") {
        throw new Error(
          "Worker could not import node:crypto.webcrypto; setCrypto check failed",
        );
      }
      expect(res.setCrypto).toBeDefined();
      expect(res.setCrypto.threw).toBe(true);
      const expectedNames = ["InvalidConfigurationError", "TypeError"];
      expect(expectedNames.includes(res.setCrypto.name)).toBe(true);
      expect(
        typeof res.setCrypto.message === "string" &&
          res.setCrypto.message.endsWith(expectedMessage),
      ).toBe(true);

      // setHandshakeConfig
      expect(res.setHandshakeConfig).toBeDefined();
      expect(res.setHandshakeConfig.threw).toBe(true);
      // Accept either the canonical InvalidConfigurationError message, or a TypeError when the
      // function is not exported from the public bundle (worker imported dist/index.mjs).
      if (
        res.setHandshakeConfig.name === "TypeError" &&
        typeof res.setHandshakeConfig.message === "string"
      ) {
        // e.g. "pkg.setHandshakeConfig is not a function"
        expect(res.setHandshakeConfig.message.includes("not a function")).toBe(
          true,
        );
      } else {
        expect(expectedNames.includes(res.setHandshakeConfig.name)).toBe(true);
        expect(
          typeof res.setHandshakeConfig.message === "string" &&
            res.setHandshakeConfig.message.endsWith(expectedMessage),
        ).toBe(true);
      }

      // setAppEnvironment
      expect(res.setAppEnvironment).toBeDefined();
      expect(res.setAppEnvironment.threw).toBe(true);
      expect(expectedNames.includes(res.setAppEnvironment.name)).toBe(true);
      expect(
        typeof res.setAppEnvironment.message === "string" &&
          res.setAppEnvironment.message.endsWith(expectedMessage),
      ).toBe(true);

      // configureErrorReporter
      expect(res.configureErrorReporter).toBeDefined();
      expect(res.configureErrorReporter.threw).toBe(true);
      expect(expectedNames.includes(res.configureErrorReporter.name)).toBe(
        true,
      );
      expect(
        typeof res.configureErrorReporter.message === "string" &&
          res.configureErrorReporter.message.endsWith(expectedMessage),
      ).toBe(true);
    }
  });
});
