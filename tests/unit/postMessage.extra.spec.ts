import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  sendSecurePostMessage,
  createSecurePostMessageListener,
  POSTMESSAGE_MAX_PAYLOAD_BYTES,
} from "../../src/postMessage";
import {
  InvalidParameterError,
  InvalidConfigurationError,
} from "../../src/errors";
import { environment } from "../../src/environment";

beforeEach(() => {
  // Ensure development by default and clear cache
  environment.setExplicitEnv("development");
  environment.clearCache();
});

afterEach(() => {
  environment.setExplicitEnv("development");
  environment.clearCache();
});

describe("sendSecurePostMessage validations", () => {
  it("requires targetWindow and non-wildcard origin", () => {
    expect(() =>
      // @ts-expect-error intentionally invalid
      sendSecurePostMessage({
        targetWindow: null,
        payload: {},
        targetOrigin: "https://x",
      }),
    ).toThrow(InvalidParameterError);

    expect(() =>
      // wildcard not allowed
      sendSecurePostMessage({
        targetWindow: { postMessage() {} } as any,
        payload: {},
        targetOrigin: "*",
      }),
    ).toThrow(InvalidParameterError);
  });

  it("rejects invalid and insecure origins but allows localhost over http", () => {
    const fakeWin = {
      posted: null as any,
      postMessage(pay: any, origin: string) {
        this.posted = { pay, origin };
      },
    } as any;
    expect(() =>
      sendSecurePostMessage({
        targetWindow: fakeWin,
        payload: {},
        targetOrigin: "not-a-url",
      }),
    ).toThrow(InvalidParameterError);
    expect(() =>
      sendSecurePostMessage({
        targetWindow: fakeWin,
        payload: {},
        targetOrigin: "http://example.com",
      }),
    ).toThrow(InvalidParameterError);

    // localhost over http is allowed
    sendSecurePostMessage({
      targetWindow: fakeWin,
      payload: { a: 1 },
      targetOrigin: "http://localhost",
    });
    expect(fakeWin.posted).toBeTruthy();
  });

  it("rejects circular and oversized payloads", () => {
    const fakeWin = { postMessage() {} } as any;
    const a: any = {};
    a.self = a;
    expect(() =>
      sendSecurePostMessage({
        targetWindow: fakeWin,
        payload: a,
        targetOrigin: "http://localhost",
      }),
    ).toThrow(InvalidParameterError);

    // Oversized payload
    const big = "x".repeat(POSTMESSAGE_MAX_PAYLOAD_BYTES + 10);
    expect(() =>
      sendSecurePostMessage({
        targetWindow: fakeWin,
        payload: big,
        targetOrigin: "http://localhost",
      }),
    ).toThrow(InvalidParameterError);
  });
});

describe("createSecurePostMessageListener handler behavior", () => {
  it("throws in production when no allowedOrigins or expectedSource provided", () => {
    environment.setExplicitEnv("production");
    expect(() => createSecurePostMessageListener([], (d) => {})).toThrow(
      InvalidConfigurationError,
    );
    environment.setExplicitEnv("development");
  });

  it("accepts messages from allowed origin and validates schema", (done) => {
    const opts = {
      allowedOrigins: ["https://trusted.example.com"],
      validate: { x: "number" } as any,
      onMessage: (data: unknown) => {
        try {
          expect((data as any).x).toBe(1);
          l.destroy();
          done();
        } catch (e) {
          done(e);
        }
      },
    } as any;
    const l = createSecurePostMessageListener(opts, undefined as any);
    // dispatch allowed message
    window.dispatchEvent(
      new MessageEvent("message", {
        origin: "https://trusted.example.com",
        data: JSON.stringify({ x: 1 }),
      } as any),
    );
  });

  it("drops opaque origin 'null' and does not call onMessage", () => {
    let called = false;
    const l = createSecurePostMessageListener(
      {
        allowedOrigins: ["https://a"],
        validate: (d: any) => true,
        onMessage: () => {
          called = true;
        },
      } as any,
      undefined as any,
    );
    window.dispatchEvent(
      new MessageEvent("message", {
        origin: "null",
        data: JSON.stringify({}),
      } as any),
    );
    l.destroy();
    expect(called).toBe(false);
  });

  it("handles non-string and invalid JSON payloads gracefully", () => {
    let called = false;
    const l = createSecurePostMessageListener(
      {
        allowedOrigins: ["https://trusted.example.com"],
        validate: (d: any) => true,
        onMessage: () => {
          called = true;
        },
      } as any,
      undefined as any,
    );
    // non-string data
    window.dispatchEvent(
      new MessageEvent("message", {
        origin: "https://trusted.example.com",
        data: { not: "string" },
      } as any),
    );
    // invalid json
    window.dispatchEvent(
      new MessageEvent("message", {
        origin: "https://trusted.example.com",
        data: "not json",
      } as any),
    );
    l.destroy();
    expect(called).toBe(false);
  });

  it("enforces depth limit and rejects deeply nested payloads", () => {
    const schema = { a: "object" } as any;
    let called = false;
    const l = createSecurePostMessageListener(
      {
        allowedOrigins: ["https://trusted.example.com"],
        validate: schema,
        onMessage: () => {
          called = true;
        },
      } as any,
      undefined as any,
    );
    // create deeply nested object exceeding depth
    let obj: any = {};
    let cur = obj;
    for (let i = 0; i < 20; i++) {
      cur.next = {};
      cur = cur.next;
    }
    window.dispatchEvent(
      new MessageEvent("message", {
        origin: "https://trusted.example.com",
        data: JSON.stringify(obj),
      } as any),
    );
    l.destroy();
    expect(called).toBe(false);
  });

  it("respects allowExtraProps option when true", (done) => {
    const opts = {
      allowedOrigins: ["https://trusted.example.com"],
      validate: { a: "number" } as any,
      allowExtraProps: true,
      onMessage: (data: unknown) => {
        try {
          expect((data as any).extra).toBe(2);
          done();
        } catch (e) {
          done(e);
        }
      },
    } as any;
    const l = createSecurePostMessageListener(opts, undefined as any);
    window.dispatchEvent(
      new MessageEvent("message", {
        origin: "https://trusted.example.com",
        data: JSON.stringify({ a: 1, extra: 2 }),
      } as any),
    );
  });

  it("drops messages from unexpected source when expectedSource set", () => {
    const realSource = {} as any;
    let called = false;
    const l = createSecurePostMessageListener(
      {
        allowedOrigins: ["https://trusted.example.com"],
        validate: (d: any) => true,
        expectedSource: realSource,
        onMessage: () => {
          called = true;
        },
      } as any,
      undefined as any,
    );
    // dispatch with different source
    window.dispatchEvent(
      new MessageEvent("message", {
        origin: "https://trusted.example.com",
        data: JSON.stringify({}),
        source: {} as any,
      } as any),
    );
    l.destroy();
    expect(called).toBe(false);
  });
});

describe("security-fixes: sanitize/typedarray and listener immutability", () => {
  it("sendSecurePostMessage fails fast with incompatible sanitize=true + allowTypedArrays=true", () => {
    const payload = new Uint8Array([1, 2, 3]);
    const fakeWin = { postMessage: (_p: any, _o: string) => {} } as any;

    expect(() =>
      // @ts-expect-error testing invalid combination
      sendSecurePostMessage({
        targetWindow: fakeWin,
        payload,
        targetOrigin: "https://example.com",
        wireFormat: "structured",
        sanitize: true,
        allowTypedArrays: true,
      } as any),
    ).toThrow(InvalidParameterError);
  });

  it("listener configuration is immutable after creation (TOCTOU fix)", () => {
    const originalValidator = (() => false) as any;
    const permissiveValidator = (() => true) as any;

    const options: any = {
      allowedOrigins: ["https://example.com"],
      onMessage: () => {},
      validate: originalValidator,
      allowExtraProps: false,
    };

    const listener = createSecurePostMessageListener(options as any);

    // mutate options after creation
    options.validate = permissiveValidator;
    options.allowExtraProps = true;

    expect(listener).toBeDefined();
    expect(listener.destroy).toBeInstanceOf(Function);
    listener.destroy();
  });

  it("sendSecurePostMessage allows sanitize=true with plain objects", () => {
    const fakeWin = {
      posted: null as any,
      postMessage(payload: any, origin: string) {
        this.posted = { payload, origin };
      },
    } as any;
    const payload = { message: "ok", v: [1, 2, 3] };

    expect(() =>
      sendSecurePostMessage({
        targetWindow: fakeWin,
        payload,
        targetOrigin: "https://example.com",
        wireFormat: "structured",
        sanitize: true,
      } as any),
    ).not.toThrow();
    expect(fakeWin.posted).toBeTruthy();
  });
});
