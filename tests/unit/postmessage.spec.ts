import { describe, it, expect, vi } from "vitest";
import {
  _validatePayload,
  createSecurePostMessageListener,
  sendSecurePostMessage,
  InvalidParameterError,
  setAppEnvironment,
  setCrypto,
} from "../../src";
import { getPostMessageConfig } from "../../src/config";

describe("postMessage validation (unit)", () => {
  it("accepts valid shallow schema", () => {
    const validator = { action: "string" } as const;
    const data = { action: "submit" };
    const res = _validatePayload(data, validator as any);
    expect(res.valid).toBe(true);
  });

  it("accepts null-prototype objects created by sanitizer", () => {
    const validator = { action: "string" } as const;
    const data = Object.assign(Object.create(null), { action: "go" });
    const res = _validatePayload(data, validator as any);
    expect(res.valid).toBe(true);
  });

  it("forbids prototype pollution keys", () => {
    const validator = { __proto__: "object" } as unknown as Record<string, any>;
    const data = { __proto__: { evil: true } } as unknown as Record<
      string,
      unknown
    >;
    const res = _validatePayload(data, validator);
    expect(res.valid).toBe(false);
  });
});

describe("createSecurePostMessageListener basic integration", () => {
  it("drops invalid payloads and does not call onMessage when validator throws", async () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);
    try {
      setAppEnvironment("development");
    } catch {}

    const mockCrypto = {
      getRandomValues: (arr: Uint8Array) => {
        arr.fill(0);
        return arr;
      },
      subtle: { digest: async () => new Uint8Array([1, 2, 3, 4]).buffer },
    } as unknown as Crypto;
    setCrypto(mockCrypto);

    const validator = () => {
      throw new Error("boom");
    };
    const onMessage = vi.fn();
    const listener = (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage,
      validate: validator,
    } as any);

    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: JSON.stringify({ foo: "bar" }),
    };
    expect(() => handler(event)).not.toThrow();
    await Promise.resolve();
    expect(onMessage).not.toHaveBeenCalled();

    setCrypto(null);
    vi.unstubAllGlobals();
  });
});

describe("sendSecurePostMessage serialization", () => {
  it("throws InvalidParameterError when payload is circular", () => {
    const targetWindow = { postMessage: vi.fn() } as any;
    const a: any = {};
    a.self = a;
    expect(() =>
      sendSecurePostMessage({
        targetWindow,
        payload: a,
        targetOrigin: "https://trusted.example.com",
      }),
    ).toThrow(InvalidParameterError);
  });

  it("enforces max payload bytes on send", () => {
    const targetWindow = { postMessage: vi.fn() } as any;
  const big = "x".repeat(getPostMessageConfig().maxPayloadBytes + 10);
    expect(() =>
      sendSecurePostMessage({
        targetWindow,
        payload: { big },
        targetOrigin: "https://trusted.example.com",
      }),
    ).toThrow(InvalidParameterError);
  });

  it("rejects non-string postMessage payloads on receive (API contract)", () => {
    // The public API now requires serialized JSON strings for incoming messages.
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);
    try {
      setAppEnvironment("development");
    } catch {}

    const onMessage = vi.fn();
    const listener = (createSecurePostMessageListener as any)(
      ["https://trusted.example.com"],
      onMessage as any,
    );
    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: { not: "a string" },
    };
    // The listener swallows parsing errors and logs them; it should not call onMessage
    expect(() => handler(event)).not.toThrow();
    expect(onMessage).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});

describe("createSecurePostMessageListener additional hardening", () => {
  it("throws when allowedOrigins contains non-absolute/insecure origin", () => {
    expect(() =>
      (createSecurePostMessageListener as any)(["example.com"], () => {}),
    ).toThrow(InvalidParameterError);
  });

  it("drops messages from 'null' origin by default", () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);
    const onMessage = vi.fn();
    const listener = (createSecurePostMessageListener as any)(
      ["https://trusted.example.com"],
      onMessage as any,
    );
    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = { origin: "null", data: JSON.stringify({ a: 1 }) };
    expect(() => handler(event)).not.toThrow();
    expect(onMessage).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("rejects unexpected extra properties when allowExtraProps is false", () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);
    const onMessage = vi.fn();
    const validator = { action: "string" } as const;
    const listener = (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage,
      validate: validator,
      allowExtraProps: false,
    } as any);
    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: JSON.stringify({ action: "ok", extra: 1 }),
    };
    expect(() => handler(event)).not.toThrow();
    expect(onMessage).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("rate-limits diagnostic fingerprinting when enabled", async () => {
    const mockWindow: any = { addEventListener: vi.fn() };
    vi.stubGlobal("window", mockWindow);
    try {
      setAppEnvironment("development");
    } catch {}

    const mockCrypto = {
      getRandomValues: (arr: Uint8Array) => {
        arr.fill(0);
        return arr;
      },
      subtle: { digest: async () => new Uint8Array([1, 2, 3, 4]).buffer },
    } as unknown as Crypto;
    setCrypto(mockCrypto);

    const onMessage = vi.fn();
    const validator = () => false; // always invalid
    const listener = (createSecurePostMessageListener as any)({
      allowedOrigins: ["https://trusted.example.com"],
      onMessage,
      validate: validator,
      enableDiagnostics: true,
    } as any);

    const handler = mockWindow.addEventListener.mock.calls[0][1];
    const event = {
      origin: "https://trusted.example.com",
      data: JSON.stringify({ foo: "bar" }),
    };
    // Exceed diagnostic budget: DEFAULT_DIAGNOSTIC_BUDGET is 5, call 7 times
    for (let i = 0; i < 7; i++) handler(event);
    // allow async fingerprints to schedule
    await Promise.resolve();
    // No onMessage calls
    expect(onMessage).not.toHaveBeenCalled();

    setCrypto(null);
    vi.unstubAllGlobals();
  });
});
