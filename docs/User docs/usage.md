Usage Guide — Security Kit

This document contains concrete examples and guidance for common usage scenarios.

1. Validating URLs (strict by default)

---

The URL utilities are hardened to OWASP ASVS L3. By default, the library enforces a safe scheme policy (e.g., `https:`) and rejects URLs that do not meet the policy.

Example:

```ts
import { validateURL } from "@david-osipov/security-kit";

const r = validateURL("https://example.com");
if (!r.ok) {
  // handle expected errors: InvalidParameterError, CryptoUnavailableError, etc.
  console.error(r.error.message);
} else {
  console.log(r.url.href);
}
```

## Permissive mode (opt-in)

If you must accept non-default schemes provided by callers (e.g., `mailto:`), enable the runtime policy flag. Note: do not do this unless you control and validate inputs thoroughly.

```ts
import { setRuntimePolicy } from "@david-osipov/security-kit";
setRuntimePolicy({ allowCallerSchemesOutsidePolicy: true });
```

2. Creating URLs from parts

---

Use `createSecureURL(base, pathSegments?, params?, fragment?)` to safely build URLs without introducing encoding or prototype-pollution bugs.

```ts
import { createSecureURL } from "@david-osipov/security-kit";
const url = createSecureURL("https://example.com", ["api", "v1", "users"], {
  q: "alice",
});
console.log(url); // https://example.com/api/v1/users?q=alice
```

3. Encoding & decoding utilities

---

The library provides `encodeComponentRFC3986` and `strictDecodeURIComponent` to avoid ambiguous behavior with percent-encoding and control characters.

4. Origin normalization

---

Use `normalizeOrigin(url)` to produce canonical origins suitable for CSP, CORS, or same-origin checks. This removes default ports and rejects inputs with userinfo, paths, queries, or fragments.

5. Error handling and typed errors

---

All APIs throw or return typed errors from `src/errors.ts` such as `InvalidParameterError` and `InvalidConfigurationError`. Use these types to programmatically handle different failure modes.

6. Example: Strict validation + default safe scheme

---

```ts
import { validateURL } from "@david-osipov/security-kit";

// Strict default: allowedSchemes must intersect policy
const res = validateURL("mailto:someone@example.com", {
  allowedSchemes: ["mailto:"],
});
// res.ok is false unless runtime policy allows caller schemes outside policy
```

7. Important security pointers

---

- Do not use `Math.random()` for cryptographic operations; use the library's secure helpers.
- Avoid passing untrusted objects directly to query parameter builders; the library will reject prototype-polluting keys but always sanitize inputs.
- Keep the kit sealed in production by calling `sealSecurityKit()` once at startup if you rely on immutability guarantees.

For full API reference, consult `docs/Documentation.md` and the in-source JSDoc comments.
