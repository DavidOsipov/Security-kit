import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createSecureURL } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";
import {
  configureUrlPolicy,
  _resetUrlPolicyForTests,
} from "../../src/config";

describe("createSecureURL: opaque schemes (mailto, tel, sms)", () => {
  beforeAll(() => {
    // Widen safe schemes for this spec so allowedSchemes survives policy intersection.
    // Keep https: to avoid surprising interactions with helpers that may parse temporary URLs.
    configureUrlPolicy({ safeSchemes: ["https:", "mailto:", "tel:", "sms:"] });
  });

  afterAll(() => {
    // Restore default policy to avoid leaking configuration into other specs.
    _resetUrlPolicyForTests();
  });

  it("builds a simple mailto with query params when allowed", () => {
    const href = createSecureURL(
      "mailto:alice@example.com",
      [],
      { subject: "Hello", body: "Test 1 2" },
      undefined,
      { allowedSchemes: ["mailto:"] },
    );
    expect(href.startsWith("mailto:alice@example.com?")).toBe(true);
    const qs = href.split("?")[1] || "";
    const sp = new URL("http://local/?" + qs).searchParams;
    expect(sp.get("subject")).toBe("Hello");
    expect(sp.get("body")).toBe("Test 1 2");
  });

  it("supports multiple mailto addresses and encodes local-part safely", () => {
    const href = createSecureURL(
      "mailto:foo+bar@example.com,bob@example.net",
      [],
      { cc: "carol@example.org" },
      undefined,
      { allowedSchemes: ["mailto:"] },
    );
    expect(href.startsWith("mailto:")).toBe(true);
    const addressList = href.slice("mailto:".length).split("?")[0];
    // local part + should be encoded
    expect(addressList).toContain("foo%2Bbar@example.com");
    expect(addressList).toContain("bob@example.net");
  });

  it("rejects invalid mailto address (missing domain)", () => {
    expect(() =>
      createSecureURL("mailto:alice", [], {}, undefined, {
        allowedSchemes: ["mailto:"],
      }),
    ).toThrow(InvalidParameterError);
  });

  it("rejects fragments for opaque schemes", () => {
    expect(() =>
      createSecureURL("mailto:alice@example.com", [], {}, "frag", {
        allowedSchemes: ["mailto:"],
      }),
    ).toThrow(InvalidParameterError);
  });

  it("rejects mailto when not allowed by allowedSchemes", () => {
    expect(() =>
      createSecureURL("mailto:alice@example.com", [], {}, undefined, {
        allowedSchemes: ["https:"],
      }),
    ).toThrow(InvalidParameterError);
  });

  it("normalizes tel numbers to E.164-like and appends query params", () => {
    const href = createSecureURL(
      "tel:+1 (650) 555-1234",
      [],
      { ext: "123" },
      undefined,
      { allowedSchemes: ["tel:"] },
    );
    expect(href.startsWith("tel:+16505551234")).toBe(true);
    const qs = href.split("?")[1] || "";
    const sp = new URL("http://local/?" + qs).searchParams;
    expect(sp.get("ext")).toBe("123");
  });

  it("rejects tel numbers with invalid characters", () => {
    expect(() =>
      createSecureURL("tel:+1-650-ABC-1234", [], {}, undefined, {
        allowedSchemes: ["tel:"],
      }),
    ).toThrow(InvalidParameterError);
  });

  it("supports sms with normalization identical to tel", () => {
    const href = createSecureURL(
      "sms:(650) 555 0000",
      [],
      { body: "Ping" },
      undefined,
      { allowedSchemes: ["sms:"] },
    );
    expect(href.startsWith("sms:6505550000")).toBe(true);
    const qs = href.split("?")[1] || "";
    const sp = new URL("http://local/?" + qs).searchParams;
    expect(sp.get("body")).toBe("Ping");
  });
});
