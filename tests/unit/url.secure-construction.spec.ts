import { describe, it, expect } from "vitest";
import { InvalidParameterError } from "../../src/errors";
import { setRuntimePolicy } from "../../src/config";
import { createSecureURL } from "../../src/url";

describe("createSecureURL: hardened construction", () => {
		it("builds a normalized https URL with RFC3986-encoded path and query", () => {
		const href = createSecureURL(
			"https://exampLE.com/base",
			["folder", "file name"],
			{ q: "a b", ok: 1 },
		);
		// Hostname canonicalized to lowercase, path segments encoded, query encoded
			expect(href).toBe(
				"https://example.com/base/folder/file%20name?q=a+b&ok=1",
			);
	});

	it("preserves a base fragment when only normalizing; explicit fragment replaces it", () => {
		const noFrag = createSecureURL("https://example.com/#frag");
		expect(noFrag).toBe("https://example.com/#frag");

		const withFrag = createSecureURL(
			"https://example.com/#frag",
			[],
			{},
			"sec#ment",
		);
		expect(withFrag).toBe("https://example.com/#sec%23ment");
	});

	it("rejects dangerous fragments under strict validation (default)", () => {
		expect(() =>
			createSecureURL("https://example.com/", [], {}, "javascript:alert(1)"),
		).toThrow(InvalidParameterError);
	});

	it("enforces requireHTTPS when requested", () => {
		expect(() =>
			createSecureURL("http://example.com/", [], {}, undefined, {
				requireHTTPS: true,
			}),
		).toThrow(InvalidParameterError);
	});

	it("enforces allowedSchemes whitelist", () => {
		expect(() =>
			createSecureURL("https://example.com/", [], {}, undefined, {
				allowedSchemes: ["mailto:"],
			}),
		).toThrow(InvalidParameterError);

		const ok = createSecureURL("https://example.com/", [], {}, undefined, {
			allowedSchemes: ["https:"],
		});
		expect(ok).toBe("https://example.com/");
	});

			it("supports opaque schemes (mailto:) and forbids fragments on them", () => {
				// Allow caller-provided schemes outside global policy for this test only
				setRuntimePolicy({ allowCallerSchemesOutsidePolicy: true });
				try {
					const mailto = createSecureURL(
						"mailto:Alice@example.com, bob@example.com",
						[],
						{ subject: "Hello world" },
						undefined,
						{ allowedSchemes: ["mailto:"] },
					);
		// Local-parts encoded; domains lowercased; query encoded
							expect(mailto).toBe(
								"mailto:Alice@example.com,bob@example.com?subject=Hello+world",
							);

					expect(() =>
						createSecureURL(
							"mailto:alice@example.com",
							[],
							{},
							"frag-not-allowed",
						),
					).toThrow(InvalidParameterError);
				} finally {
					// Restore strict default
					setRuntimePolicy({ allowCallerSchemesOutsidePolicy: false });
				}
	});

	it("rejects ambiguous IPv4 shorthand hosts during construction", () => {
		expect(() =>
			createSecureURL("http://192.168.1", ["p"], { a: 1 }),
		).toThrow(InvalidParameterError);
	});

	it("rejects traversal and separators in path segments", () => {
		expect(() => createSecureURL("https://example.com/", [".."])).toThrow(
			InvalidParameterError,
		);
		expect(() => createSecureURL("https://example.com/", ["a/b"])).toThrow(
			InvalidParameterError,
		);
		expect(() =>
			createSecureURL("https://example.com/", ["%2e%2e"]),
		).toThrow(InvalidParameterError);
	});

	it("rejects control characters and malformed encodings in query values", () => {
		expect(() =>
			createSecureURL("https://example.com/", [], { a: "line\n" }),
		).toThrow(InvalidParameterError);
		expect(() =>
			createSecureURL("https://example.com/", [], { a: "%zz" }),
		).toThrow(InvalidParameterError);
	});

	it("applies DoS caps: maxPathSegments and maxQueryParameters", () => {
		expect(() =>
			createSecureURL(
				"https://example.com/",
				["one", "two"],
				{},
				undefined,
				{ maxPathSegments: 1 },
			),
		).toThrow(InvalidParameterError);

		expect(() =>
			createSecureURL(
				"https://example.com/",
				[],
				{ a: 1, b: 2 },
				undefined,
				{ maxQueryParameters: 1 },
			),
		).toThrow(InvalidParameterError);
	});
});


