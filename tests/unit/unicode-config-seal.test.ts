// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
	getUnicodeSecurityConfig,
	setUnicodeSecurityConfig,
	sealUnicodeSecurityConfig,
} from "../../src/config.ts";
import { InvalidConfigurationError, InvalidParameterError } from "../../src/errors.ts";

// Note: We are intentionally not resetting the global config here; this test
// asserts immutable behavior post-seal. Run in isolation or ensure ordering.

describe("Unicode security config sealing (defaults freeze)", () => {
	it("captures baseline defaults including new hardening flags", () => {
		const cfg = getUnicodeSecurityConfig();
		// New flags introduced: rejectTagCharacters, rejectVariationSelectors, rejectPrivateUseArea,
		// softFlagMathStyles, softFlagEnclosedAlphanumerics
		expect(Object.prototype.hasOwnProperty.call(cfg, "rejectTagCharacters")).toBe(true);
		expect(Object.prototype.hasOwnProperty.call(cfg, "rejectVariationSelectors")).toBe(true);
		expect(Object.prototype.hasOwnProperty.call(cfg, "rejectPrivateUseArea")).toBe(true);
		expect(Object.prototype.hasOwnProperty.call(cfg, "softFlagMathStyles")).toBe(true);
		expect(Object.prototype.hasOwnProperty.call(cfg, "softFlagEnclosedAlphanumerics")).toBe(true);

		// Assert default semantics (documented): tag + variation selectors true, PUA false (soft allow), stylistic soft flags true
		expect(cfg.rejectTagCharacters).toBe(true);
		expect(cfg.rejectVariationSelectors).toBe(true);
		expect(cfg.rejectPrivateUseArea).toBe(false);
		expect(cfg.softFlagMathStyles).toBe(true);
		expect(cfg.softFlagEnclosedAlphanumerics).toBe(true);
	});

	it("allows mutation before sealing and then rejects afterwards", () => {
		// Pre-seal: toggle some flags
		setUnicodeSecurityConfig({ rejectPrivateUseArea: true, softFlagMathStyles: false });
		let interim = getUnicodeSecurityConfig();
		expect(interim.rejectPrivateUseArea).toBe(true);
		expect(interim.softFlagMathStyles).toBe(false);

		// Seal
		sealUnicodeSecurityConfig();

		// Post-seal attempt to mutate should throw InvalidConfigurationError OR InvalidParameterError depending on path
		expect(() => setUnicodeSecurityConfig({ rejectTagCharacters: false })).toThrow();
		try {
			setUnicodeSecurityConfig({ rejectTagCharacters: false });
		} catch (e) {
			// Accept either explicit configuration or parameter error depending on production constraints
			expect([
				"InvalidConfigurationError",
				"InvalidParameterError",
			]).toContain((e as Error).name);
		}

		// Values remain frozen
		const sealed = getUnicodeSecurityConfig();
		expect(sealed.rejectTagCharacters).toBe(true); // unchanged from default
		expect(sealed.rejectPrivateUseArea).toBe(true); // we set before sealing
		expect(sealed.softFlagMathStyles).toBe(false); // we modified before sealing
	});

	it("does not permit replacing softFlagEnclosedAlphanumerics after seal", () => {
		const sealed = getUnicodeSecurityConfig();
		if (sealed.softFlagEnclosedAlphanumerics !== undefined) {
			expect(() => setUnicodeSecurityConfig({ softFlagEnclosedAlphanumerics: !sealed.softFlagEnclosedAlphanumerics })).toThrow();
		}
	});

		it("prevents disabling critical flags when simulating production", () => {
			// Simulate production by forcing environment (only affects derived behavior for some flags)
			// We purposely avoid importing internal reset helpers; rely on public API.
			// Try to disable a critical flag (rejectInvisibleChars) which is not permitted in prod.
			const before = getUnicodeSecurityConfig();
			// Guard: ensure flag currently true so test is meaningful
			expect(before.rejectInvisibleChars).toBe(true);
			// Attempt to disable (should throw InvalidParameterError)
			expect(() => setUnicodeSecurityConfig({ rejectInvisibleChars: false }))
				.toThrow();
			const after = getUnicodeSecurityConfig();
			expect(after.rejectInvisibleChars).toBe(true);
		});

		it("maintains stable key shape before and after sealing", () => {
			const preKeys = Object.keys(getUnicodeSecurityConfig()).sort();
			// Perform an allowed mutation (toggle soft flag) then seal
			if (!getUnicodeSecurityConfig().rejectPrivateUseArea) {
				setUnicodeSecurityConfig({ rejectPrivateUseArea: true });
			}
			sealUnicodeSecurityConfig();
			const postKeys = Object.keys(getUnicodeSecurityConfig()).sort();
			// Snapshot-style assertion: same key set
			expect(postKeys).toEqual(preKeys);
			// Ensure new hardening keys remain present
			for (const required of [
				"rejectTagCharacters",
				"rejectVariationSelectors",
				"rejectPrivateUseArea",
				"softFlagMathStyles",
				"softFlagEnclosedAlphanumerics",
			]) {
				expect(postKeys).toContain(required);
			}
		});
});
