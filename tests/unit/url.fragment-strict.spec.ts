import { describe, it, expect } from "vitest";
import { createSecureURL, validateURL, normalizeOrigin } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("URL fragments: strict security handling", () => {
	it("does not carry over base fragment implicitly (explicit-only)", () => {
		const href = createSecureURL("https://example.test/path#baseFrag", ["x"]);
		expect(href).toBe("https://example.test/path/x");
	});

	it("encodes explicit fragment per RFC3986 in strict mode", () => {
		const href = createSecureURL(
			"https://example.test/path",
			["x"],
			{},
			"spaces and#hash",
			{ strictFragment: true },
		);
		expect(href).toBe("https://example.test/path/x#spaces%20and%23hash");
	});

	it("rejects dangerous fragments that could enable XSS (javascript:)", () => {
		expect(() =>
			createSecureURL(
				"https://example.test/secure",
				[],
				{},
				"javascript:alert(1)",
				{ strictFragment: true },
			),
		).toThrow(InvalidParameterError);
	});

	it("rejects fragments containing control characters", () => {
		expect(() =>
			createSecureURL(
				"https://example.test/secure",
				[],
				{},
				"ok\u0007bad",
				{ strictFragment: true },
			),
		).toThrow(InvalidParameterError);
	});

	it("normalizeOrigin rejects any input containing a fragment", () => {
		expect(() => normalizeOrigin("https://example.test/#frag")).toThrow(
			InvalidParameterError,
		);
	});

	it("validateURL defaults to strict fragment validation and rejects dangerous fragments", () => {
		const res = validateURL("https://example.test/#javascript:alert(1)");
		expect(res.ok).toBe(false);
		if (!res.ok) expect(res.error).toBeInstanceOf(InvalidParameterError);
	});

	it("rejects fragments for opaque schemes (mailto)", () => {
		expect(() =>
			createSecureURL("mailto:user@example.test", [], {}, "frag"),
		).toThrow(InvalidParameterError);
	});
});

