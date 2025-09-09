import { describe, it, expect } from "vitest";
import { sanitizeLogMessage } from "../../src/utils";

describe("numeric secrets redaction", () => {
  it("redacts PAN-like numbers via Luhn", () => {
    // 4111111111111111 passes Luhn (Visa test number)
    const input = "card=4111111111111111";
    const out = sanitizeLogMessage(input);
    expect(out).toBe("[REDACTED]");
  });

  it("does not redact non-Luhn 16 digits", () => {
    const input = "id=1234567890123456";
    const out = sanitizeLogMessage(input);
    expect(out).not.toBe("[REDACTED]");
  });

  it("redacts long numeric tokens (>=24 digits)", () => {
    const input = "token=" + "9".repeat(24);
    const out = sanitizeLogMessage(input);
    expect(out).toBe("[REDACTED]");
  });

  it("redacts OTP/PIN values when key context indicates OTP", () => {
    const input = { otp: "123456" };
    const out = sanitizeLogMessage(input);
    expect(out).toContain("\"otp\":\"[REDACTED]\"");
  });
});
