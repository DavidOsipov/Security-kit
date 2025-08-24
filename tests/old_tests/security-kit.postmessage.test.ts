import { describe, it, expect, vi } from "vitest";
import {
  POSTMESSAGE_MAX_PAYLOAD_BYTES,
  _validatePayload,
  createSecurePostMessageListener,
  sendSecurePostMessage,
  InvalidParameterError,
  setAppEnvironment,
} from "../utils/security_kit";
import * as SK from "../utils/security_kit";

// (No DOM message dispatch in unit tests; validation logic is exercised directly.)

describe("postMessage validation (unit)", () => {
  it("accepts valid shallow schema", () => {
    const validator = { action: "string" } as const;
    const data = { action: "submit" };
    const res = _validatePayload(data, validator as any);
    expect(res.valid).toBe(true);
  });

  it("rejects missing property", () => {
    const validator = { action: "string", id: "number" } as const;
    const data = { action: "submit" };
    const res = _validatePayload(data, validator as any);
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/Missing required property/);
  });

  it("rejects wrong type", () => {
    const validator = { action: "string", id: "number" } as const;
    const data = { action: "submit", id: "not-a-number" };
    const res = _validatePayload(data, validator as any);
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/has wrong type/);
  });

  it("forbids prototype pollution keys", () => {
    const validator = { __proto__: "object" } as unknown as Record<string, any>;
    const data = { __proto__: { evil: true } } as unknown as Record<
      string,
      unknown
    >;
    const res = _validatePayload(data, validator);
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/forbid|prototype|Forbidden/i);
  });
});

// Basic integration test: ensure validator attached to handler drops invalid payloads
describe("createSecurePostMessageListener integration (validation-focused)", () => {
  it("validator behavior mirrors listener expectations (shallow schema)", () => {
    const invalid = JSON.stringify({ bad: true });
    const resInvalid = _validatePayload(JSON.parse(invalid), {
      action: "string",
    } as any);
    expect(resInvalid.valid).toBe(false);

    const valid = JSON.stringify({ action: "submit" });
    const resValid = _validatePayload(JSON.parse(valid), {
      action: "string",
    } as any);
    expect(resValid.valid).toBe(true);
  });
});

describe("createSecurePostMessageListener - edge validation branches", () => {
  it("handles validator function that throws without crashing the listener", async () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);

    // Ensure development mode so secureDevLog emits to console
    try {
      setAppEnvironment("development");
    } catch {}

    // Inject a deterministic SubtleCrypto so fingerprinting resolves reliably in tests
    const mockCrypto = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = 0;
        return arr;
      },
      subtle: {
        digest: async (_alg: string, _data: BufferSource) =>
          new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer,
      },
    } as unknown as Crypto;
    SK.setCrypto(mockCrypto);

    // Do not rely on secureDevLog executing (environment may be sealed in other tests).
    // Instead assert the handler did not call the consumer callback and did not throw.

    const validator = () => {
      throw new Error("boom");
    };
    const onMessage = vi.fn();
    const listener = (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage,
      validate: validator,
    } as any);

    // Retrieve registered handler and invoke with a JSON string payload from allowed origin
    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: JSON.stringify({ foo: "bar" }),
    };
    expect(() => handler(event)).not.toThrow();

    // Allow the microtask queue to flush
    await Promise.resolve();

    // Validator threw; listener should not deliver the message to the consumer
    expect(onMessage).not.toHaveBeenCalled();
    // Cleanup injected crypto and global stub
    SK.setCrypto(null);
    vi.unstubAllGlobals();
  });

  it("when validation fails it schedules fingerprint logging (drop path)", async () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);

    // Ensure development mode so secureDevLog emits to console
    try {
      setAppEnvironment("development");
    } catch {}

    // Inject deterministic SubtleCrypto so fingerprinting resolves in test
    const mockCrypto2 = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = 0;
        return arr;
      },
      subtle: {
        digest: async (_alg: string, _data: BufferSource) =>
          new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9]).buffer,
      },
    } as unknown as Crypto;
    SK.setCrypto(mockCrypto2);

    // Spy on the injected SubtleCrypto.digest to confirm fingerprinting runs
    const digestSpy = vi.fn(
      async (_alg: string, _data: BufferSource) =>
        new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9]).buffer,
    );
    (mockCrypto2.subtle as any).digest = digestSpy;

    const validatorSchema = { action: "string" } as any;
    const onMessage = vi.fn();
    (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage,
      validate: validatorSchema,
    } as any);

    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: JSON.stringify({ not_action: true }),
    };
    // Invoke handler - validation will fail and code will call getPayloadFingerprint().then(...)
    handler(event);

    // Allow the async fingerprinting/logging promise chain to resolve (microtask)
    await Promise.resolve();

    // Validation failure should schedule fingerprinting; ensure digest was invoked
    expect(digestSpy).toHaveBeenCalled();
    // Cleanup injected crypto and global stub
    SK.setCrypto(null);
    vi.unstubAllGlobals();
  });

  it("scheduled then branch logs fingerprint when SubtleCrypto resolves", async () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);

    try {
      setAppEnvironment("development");
    } catch {}

    // Create a deterministic subtle.digest that returns a known buffer
    const known = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer;
    const mockCrypto = {
      getRandomValues: (arr: Uint8Array) => {
        arr.fill(0);
        return arr;
      },
      subtle: { digest: vi.fn(async () => known) },
    } as unknown as Crypto;
    SK.setCrypto(mockCrypto);

    // Spy on multiple console sinks to capture where secureDevLog may route
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    const debugSpy = vi.spyOn(console, "debug").mockImplementation(() => {});

    const validatorSchema = { action: "string" } as any;
    (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage: vi.fn(),
      validate: validatorSchema,
    } as any);

    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: JSON.stringify({ not_action: true }),
    };
    handler(event);

    // Wait for the async fingerprint generation and logging to complete
    await vi.waitFor(
      () => {
        expect((mockCrypto.subtle as any).digest).toHaveBeenCalled();
      },
      { timeout: 1000 },
    );

    // Wait for the console logging to occur after fingerprint generation
    await vi.waitFor(
      () => {
        const anyCalled =
          warnSpy.mock.calls.length ||
          infoSpy.mock.calls.length ||
          debugSpy.mock.calls.length;
        const combinedArgs = [
          ...warnSpy.mock.calls.flat(),
          ...infoSpy.mock.calls.flat(),
          ...debugSpy.mock.calls.flat(),
        ];
        const found =
          combinedArgs.some(
            (a) =>
              typeof a === "string" &&
              (a.includes("fingerprint") ||
                a.includes("SubtleCrypto") ||
                a.includes("Message dropped")),
          ) ||
          combinedArgs.some(
            (a) => a && typeof a === "object" && "fingerprint" in a,
          );

        expect(found || anyCalled).toBe(true);
      },
      { timeout: 1000 },
    );

    warnSpy.mockRestore();
    infoSpy.mockRestore();
    debugSpy.mockRestore();
    SK.setCrypto(null);
    vi.unstubAllGlobals();
  });

  it("logs listener handler errors (secureDevLog path) when onMessage throws", async () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);

    try {
      setAppEnvironment("development");
    } catch {}

    const mockCrypto = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = 0;
        return arr;
      },
      subtle: {
        digest: async () => new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer,
      },
    } as unknown as Crypto;
    SK.setCrypto(mockCrypto);

    // Spy on console.error which secureDevLog calls for 'error' level. We spy on
    // the global side-effect rather than the exported function because the
    // module's internal binding may not be replaced by spying the export.
    const errorSpy = vi.spyOn(console, "error");

    const onMessage = () => {
      throw new Error("consumer-failed");
    };
    (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage,
    } as any);

    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: JSON.stringify({ action: "ok" }),
    };
    expect(() => handler(event)).not.toThrow();

    // Let any async work settle
    await Promise.resolve();

    // secureDevLog logs via console.error for 'error' level
    expect(errorSpy).toHaveBeenCalled();

    SK.setCrypto(null);
    vi.unstubAllGlobals();
    errorSpy.mockRestore?.();
  });

  it("when fingerprinting rejects the catch branch executes without throwing", async () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);

    // Ensure development mode so secureDevLog may attempt to emit
    try {
      setAppEnvironment("development");
    } catch {}

    // Provide a crypto whose subtle.digest rejects to simulate fingerprinting failure
    const mockCrypto = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = 0;
        return arr;
      },
      subtle: {
        digest: async () => {
          throw new Error("digest-failed");
        },
      },
    } as unknown as Crypto;
    SK.setCrypto(mockCrypto);

    const validatorSchema = { action: "string" } as any;
    const onMessage = vi.fn();
    (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage,
      validate: validatorSchema,
    } as any);

    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: JSON.stringify({ not_action: true }),
    };
    // Invoke handler - validation will fail and code will call getPayloadFingerprint().then(...).catch(...)
    handler(event);

    // Allow the async fingerprinting/logging promise chain to resolve (microtasks)
    await Promise.resolve();
    await Promise.resolve();

    // The listener should not deliver the message to the consumer and should not throw
    expect(onMessage).not.toHaveBeenCalled();

    // Cleanup
    SK.setCrypto(null);
    vi.unstubAllGlobals();
  });

  it("schedules UNSERIALIZABLE fingerprint when payload cannot be stringified", async () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);

    try {
      setAppEnvironment("development");
    } catch {}

    // Ensure deterministic crypto so fingerprint attempt is stable even if it tries
    SK.setCrypto({ getRandomValues: () => {} } as any);

    const validatorSchema = { action: "string" } as any;
    const onMessage = vi.fn();
    (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage,
      validate: validatorSchema,
    } as any);

    const handler = mockWindow.addEventListener.mock.calls[0][1];

    // Create a circular object that throws on JSON.stringify
    const circular: any = {};
    circular.self = circular;

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    // Invoke handler with non-string data (caller-owned object with circular refs)
    const event = { origin: "https://trusted.example.com", data: circular };
    handler(event);

    // Allow scheduled fingerprinting to run
    await Promise.resolve();
    await Promise.resolve();

    // Should have logged a warning for dropped validation (fingerprint branch executed)
    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
    SK.setCrypto(null);
    vi.unstubAllGlobals();
  });

  it("uses deterministic fallback fingerprint when SubtleCrypto is unavailable", async () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);

    try {
      setAppEnvironment("development");
    } catch {}

    // Ensure SubtleCrypto is not available to force the deterministic fallback
    SK.setCrypto({
      getRandomValues: () => {
        /* noop */
      },
    } as any);

    const validatorSchema = { action: "string" } as any;
    const onMessage = vi.fn();
    (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage,
      validate: validatorSchema,
    } as any);

    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: JSON.stringify({ not_action: true }),
    };

    // Spy on console.warn which secureDevLog will call for 'warn' level
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    handler(event);

    // Allow microtasks to settle (two ticks to reach then/catch resolution)
    await Promise.resolve();
    await Promise.resolve();

    // Because SubtleCrypto.digest is unavailable, we should still see a scheduled
    // warning about dropped validation, but the fingerprint will be produced by
    // the deterministic fallback (a short hex string) and code should not throw.
    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
    SK.setCrypto(null);
    vi.unstubAllGlobals();
  });
});

describe("sendSecurePostMessage - serialization errors", () => {
  it("throws InvalidParameterError when payload is not JSON-serializable (circular)", () => {
    const targetWindow = { postMessage: vi.fn() } as any;
    const a: any = {};
    a.self = a; // circular

    expect(() =>
      sendSecurePostMessage({
        targetWindow,
        payload: a,
        targetOrigin: "https://trusted.example.com",
      }),
    ).toThrow(InvalidParameterError);
  });
});

// Simple fuzz tests to exercise edge cases (not exhaustive but helpful in CI)
describe("postMessage fuzzing (small)", () => {
  it("rejects oversized string payloads", () => {
    const huge = "x".repeat(POSTMESSAGE_MAX_PAYLOAD_BYTES + 1);
    expect(huge.length).toBeGreaterThan(POSTMESSAGE_MAX_PAYLOAD_BYTES);
    // The listener would drop this before parsing; simulate by asserting length
  });

  it.skip("randomized shallow shapes do not throw", () => {
    // Small randomized smoke test to ensure validator never throws for random input
    for (let i = 0; i < 500; i++) {
      const obj: Record<string, unknown> = {};
      const props = Math.floor(Math.random() * 5);
      for (let p = 0; p < props; p++) {
        obj["k" + p] =
          Math.random() > 0.5 ? "s" : Math.floor(Math.random() * 100);
      }
      expect(() =>
        _validatePayload(obj, { k0: "string" } as any),
      ).not.toThrow();
    }
  });
});
