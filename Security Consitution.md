# The Official Security & Engineering Constitution (v6.5.9 - Living Document)

**Document Status:** Final, Mandatory
**SPDX-License-Identifier:** MIT
**SPDX-FileCopyrightText:** © 2025 David Osipov <personal@david-osipov.vision>

## 0. Introduction

### 0.1. Goals & Vision

This document codifies the security and engineering architecture for this project. Our guiding philosophy is **Zero Trust**. We do not trust the network, we do not trust third-party code, and we do not even trust our own code to be infallible. Every component is built with the assumption that other parts of the system could be compromised. Security is not a feature; it is the foundation upon which all features are built.

This constitution is a living document, designed to be prescriptive, actionable, and verifiable. It serves as a single source of truth for developers, security engineers, and automated tooling.

### 0.2. Audience & Scope

This constitution is mandatory for all personnel contributing code to the project. It applies to all frontend JavaScript, backend services, CI/CD pipelines, and infrastructure configurations. Its rules are intended to be parsed and enforced by automated systems (linters, scanners, CI gates) as well as human reviewers.

### 0.3. Change Process & Versioning

This constitution is versioned semantically (e.g., v6.0.1). Any change requires a formal security review and sign-off by at least one designated security owner. Emergency bypass procedures must be documented, logged, and followed by a retrospective analysis.

### 0.4. ASVS Alignment

This Security & Engineering Constitution aims to achieve compliance with **OWASP Application Security Verification Standard (ASVS) Version 5.0.0 Level 3**. This means the application is designed to demonstrate the highest levels of security assurance, suitable for applications handling highly sensitive data or critical business functions. All requirements marked as `MUST` in this document are intended to meet or exceed the combined requirements of ASVS Levels 1, 2, and 3 where applicable to a static web application supported by serverless functions.

---

## Part I: Core Philosophy & Principles

These are the fundamental mindsets that guide all engineering decisions.

### 1.1. Secure by Default

The default state of the application is the most secure state. Insecure actions must be explicit, deliberate, and are therefore forbidden.

### 1.2. Defense in Depth

We layer multiple, independent security controls. A failure in one layer is caught by the next. We will never rely on a single control for a critical defense. Every security-sensitive operation **must** implement multiple, independent layers of protection to account for browser implementation differences and feature support gaps (e.g., Trusted Types in Chrome vs. Firefox).

### 1.3. Principle of Least Privilege (PoLP)

Every component, module, and function must operate with the minimum level of privilege and access to data necessary to perform its function. State is encapsulated (`#private`), configuration is immutable (`Object.freeze`), and DOM access is restricted.

### 1.4. Fail Loudly, Fail Safely

In the face of an error or an unavailable security primitive (e.g., `window.crypto`), the system will throw a specific, catchable error and disable the feature. It will **never** silently fall back to an insecure alternative for a security-critical operation (e.g., `Math.random()`). For non-security-critical functions where a cryptographic source is used for performance or unpredictability (e.g., seeding a PRNG for a simulation), a fallback to a non-cryptographic source (e.g., `performance.now()`) is permissible, provided that this degraded state is explicitly logged and the resulting data is marked as such. Components must implement circuit breakers to automatically disable themselves if error thresholds are exceeded.

### 1.5. Verifiable Security

A security control is considered non-existent until it is validated by an automated, adversarial test in our CI/CD pipeline. All security claims must be provable with code.

### 1.6. Performance is a Security Feature

A performant, non-blocking UI prevents timing attacks, provides a better user experience, and reduces the likelihood of user error. We mandate the use of modern, performant APIs (`IntersectionObserver` over `onscroll`, Web Animations API over class toggling).

### 1.7. Accessibility is a Security Feature

A secure application must be usable by all, including those with disabilities. Inaccessible UIs can lead to user errors (e.g., misclicks on phishing-like elements) or exclusionary practices that erode trust. All interactive elements **MUST** meet WCAG 2.2 AA standards, including keyboard navigation, ARIA labels, and reduced motion support.

### 1.8. Documented Security Decisions (MUST)

For all security-critical controls where implementation details are context-specific (e.g., input validation rules, authorization policies, cryptographic key management, session timeouts), the application's approach and configuration **MUST** be explicitly documented. This documentation serves as a verifiable record of security design decisions, enabling appropriate implementation and assessment.

### 1.9. Hardened Simplicity (MUST)

- **Statement:** Every security control, component, and API **MUST** be implemented in the simple, most auditable manner that verifiably meets its security requirements. We aggressively reject complexity that does not provide a commensurate, verifiable security benefit.
- **Rationale:** Complexity is the single greatest threat to security. It creates a larger attack surface, hides bugs, increases cognitive load on developers and reviewers, and makes systems unpredictable. A simple, well-defined function is easy to reason about, easy to test exhaustively, and easy for an adversary to analyze—which means we can more effectively harden it. This principle codifies our "Trust is Not Transitive" mindset; we do not trust complex code to be correct, even our own. It is the practical application of "Verifiable Security": a control is only as secure as it is understandable.
- **Implementation Mandates:**
  1.  **Minimal API Surface:** Functions and modules **MUST** expose the smallest possible API necessary to perform their security function. Optional parameters and multi-mode behaviors are discouraged in favor of distinct, purpose-built functions.
  2.  **Explicitness Over Magic:** Configuration and state changes **MUST** be explicit. We forbid dynamic, "magical" behaviors that depend on runtime conditions or hidden states (e.g., auto-detecting and importing Node.js modules). Consumers of a module **MUST** explicitly provide dependencies (injection) rather than the module discovering them.
  3.  **Single, Verifiable Responsibility:** Each function and module **MUST** have a single, well-defined security responsibility. A function that generates a random ID should not also handle formatting or data validation. This makes its security properties easier to prove.
  4.  **Dependency Scrutiny:** Adding a new third-party dependency to solve a simple problem is a security anti-pattern. If a security task can be accomplished with a few dozen lines of well-audited native code, that is strongly preferred over importing a multi-kilobyte library with its own transitive dependencies.
  5.  **Refactoring Mandate:** If a security-critical function grows so complex that its complete behavior cannot be held in a reviewer's head, it **MUST** be considered a candidate for immediate refactoring into simpler, composable parts.
- **Forbidden Patterns:**
  - **"Clever" Code:** Obfuscated one-liners, complex bitwise operations where standard arithmetic is clearer, or overly abstract patterns that obscure the direct flow of logic. If it requires a comment to explain _what_ it does, it's too complex. But, if we can use hybrid approach in between complex and more simpler code, which marginally increases security, performance, accessibility or other beneficial aspects, we should prefer that.
  - **Over-Engineering:** Implementing complex, multi-pass algorithms (e.g., multi-pattern memory wiping) or heavy telemetry hooks when a simpler, single-pass implementation is sufficient to mitigate the documented threat in the given context.
  - **Feature Creep:** Adding features to a security primitive that are not essential to its core function (e.g., adding caching to a secure comparison function).
  - **Premature Abstraction:** Creating deeply nested or overly generic abstractions before a clear, repeated pattern has emerged from at least three concrete use cases.

This principle serves as the ultimate tie-breaker. When faced with two potential solutions that both meet a security requirement, we **MUST** choose the simpler one. If there is a possibility to engineer a hybrid approach, which increases security, performance, accessibility or other beneficial aspects by at least estimated 25%, we **MUST** prefer the hybrid one.

---

### 2.11. Data Integrity on Visibility Change (MUST)

- **Statement:** Any long-running or measurement-sensitive task MUST be aborted if the document's visibility state changes to hidden.
- **Rationale:** Browsers aggressively throttle background tabs, which can corrupt data, break timing assumptions, and lead to inconsistent application states. Aborting the task adheres to the "Fail Loudly, Fail Safely" principle by preventing the silent collection and processing of invalid data.
- **Implementation:**
  ```javascript
  IGNORE_WHEN_COPYING_START;
  const runAbort = new AbortController();
  document.addEventListener(
    "visibilitychange",
    () => {
      if (document.visibilityState === "hidden") {
        runAbort.abort(); // Aborts associated fetch, listeners, etc.
      }
    },
    { signal: runAbort.signal },
  );
  IGNORE_WHEN_COPYING_END;
  ```

### 2.12. Privacy-Preserving Telemetry (MUST)

- **Statement:** Telemetry payloads sent to a remote collector MUST be stripped of all high-entropy or potentially identifying user data by default. The inclusion of such data MUST be strictly opt-in and limited to non-production/debug builds.
- **Rationale:** This enforces the "Principle of Least Privilege" and "Zero Trust" for data collection. We assume any collection endpoint could be breached and therefore minimize the data exposed. High-entropy data (e.g., precise timings, PRNG seeds, detailed hardware specs) can be used for fingerprinting.
- **Implementation:**
  - Build payloads from an allowlist of safe, aggregate properties.
  - Encapsulate any sensitive or detailed debug data inside a conditional block (e.g., `if (CONFIG.debugMode === true) { ... }`).
  - Raw PRNG seeds MUST NEVER be transmitted. If a run identifier is needed, a non-reversible hash of the seed MAY be sent in debug builds.

#### 2.12.1. Secure Client-Side Monitoring (MUST)

- **Statement:** Client-side errors and performance metrics **MUST** be reported using `navigator.sendBeacon()` to a secure endpoint. Raw data **MUST** be anonymized and aggregated.
- **Rationale:** Enhances "Observability & Metrics" (6.2) without blocking page unload, preventing data loss. Aligns with "Privacy-Preserving Telemetry" by minimizing PII.
- **Implementation:**
  ```javascript
  window.addEventListener("error", (event) => {
    const payload = { message: event.message, url: location.href }; // No PII
    navigator.sendBeacon("/telemetry", JSON.stringify(payload));
  });
  ```
- **Forbidden:** Using third-party trackers without isolation (e.g., via Worker as in 2.10).
- **CI Check:** Linter flags direct `console.error` in prod code; recommend beacon wrapper.

### 2.13. Build-Time Static Output Sanitization (MUST)

- Statement: The build pipeline MUST include a report-only sanitization check on generated static HTML to fail fast on high-risk patterns before deployment.
- Rationale: Defense-in-depth for static sites. Even with strict CSP, Trusted Types, and content pipeline controls, accidental inline event handlers or javascript: URIs can slip into templates or third-party content. Catching these at build time reduces runtime attack surface and prevents bad artifacts from reaching the CDN.
- Implementation:

1.  A verification script scans the built output and exits non-zero on unsafe constructs without mutating files (to preserve CSP hash integrity):
    - Path: `scripts/verify-sanitize-dist.mjs`
    - Scope: `dist/**/*.html` (overridable via `SANITIZE_DIST_GLOB`)
    - Checks:
      - Inline event handler attributes (`on*`) inside tags
      - `javascript:` URLs in `href`/`src`
    - Non-goals: Does not strip or rewrite content; JSON-LD `<script type="application/ld+json">` is allowed; relies on CSP/TT for script control.

2.  CI hook (post-build):
    - `npm run verify:sanitize` — runs the verification script
    - `npm run build:secure:verify:sanitize` — runs secure build + CSP/structured-data verification, then sanitizer

3.  Failure policy: Any finding MUST block deployment and trigger manual review. Findings SHOULD be remediated at the content/template source rather than patched in `dist`.

- Notes:

* This check complements (does not replace) CSP, Trusted Types, SRI, and content pipeline sanitizers.
* For Markdown/MDX content, sanitizer plugins (e.g., rehype-sanitize) MAY be added at render time; however, JSX logic is out of scope for HTML sanitizers and MUST be guarded by TT/CSP at runtime.

### 2.14. Cross-Origin Isolation (MUST)

- **Statement:** The application **MUST** enable cross-origin isolation by setting COOP and COEP headers. This is required for secure use of powerful APIs like SharedArrayBuffer in Workers.
- **Rationale:** Prevents cross-origin window communication exploits and side-channel attacks (e.g., Spectre). Complements CSP by isolating the execution context.
- **Implementation:** Add to `_headers` file or Cloudflare dashboard:
  ```
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp
  ```
- **Fallback:** If isolation breaks third-party embeds, use `credentialless` for COEP where supported.
- **CI Check:** Validate headers in post-build verification script.

## Part II: Architectural Mandates

These are non-negotiable, environment-level security controls enforced at the browser and server level.

### 2.1. Content Security Policy (CSP)

- **Statement:** The application **MUST** be served with a strict, hash-based CSP to mitigate XSS and data injection attacks.
- **Rationale:** This is our first and most powerful line of defense. It instructs the browser to only trust and execute scripts and styles that we have explicitly authorized via hashes calculated at build time.
- **Implementation:** The following HTTP header **MUST** be sent with every page response:
  ```http
  Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'sha256-...' 'sha256-...'; /* Add hashes of inline scripts generated by Astro build */
    style-src 'self' 'sha256-...' 'sha256-...'; /* Add hashes of inline styles generated by Astro build */
    img-src 'self' data:;
    font-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    require-trusted-types-for 'script';
    trusted-types app-policy default;
  ```
- **Forbidden:** Using `'unsafe-inline'` (without hashes), `'unsafe-eval'`, or wildcard sources like `*`.

#### 2.1.1. CSP Hash/Nonce Automation (MUST)

- **Statement:** The build pipeline **MUST** automatically compute script/style hashes and (optionally) per-request nonces and inject the resulting values into the deployed HTTP headers or meta tags as part of build output.
- **Rationale:** Manual maintenance of CSP hashes is error-prone and will drift. Automated generation preserves hash-based CSP integrity and makes the "fail fast at build" model practical. (complements existing CSP rules). :contentReference[oaicite:1]{index=1}
- **Implementation (build):**
  - Add script: `scripts/generate-csp-hashes.mjs` — compute sha256 for inline `<script>` and `<style>` and emit `csp.json` or an environment artifact used by the host.
  - CI: run this after `npm run build`; fail the pipeline when computed CSP differs from the header being deployed.
- **Example (Node.js sketch):**

```js
// scripts/generate-csp-hashes.mjs (very small sketch)
import { promises as fs } from "fs";
import crypto from "crypto";
import glob from "glob";

function sha256Base64(str) {
  return (
    "sha256-" + crypto.createHash("sha256").update(str, "utf8").digest("base64")
  );
}

const files = glob.sync("dist/**/*.html");
const hashes = new Set();
for (const f of files) {
  const html = await fs.readFile(f, "utf8");
  // quick regex to capture inline scripts/styles (safelist per project)
  for (const m of html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)) {
    const code = m[1].trim();
    if (code) hashes.add(sha256Base64(code));
  }
  for (const m of html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)) {
    const css = m[1].trim();
    if (css) hashes.add(sha256Base64(css));
  }
}
await fs.writeFile(
  "build/csp-hashes.json",
  JSON.stringify(Array.from(hashes), null, 2),
);
```

#### 2.1.2. CSP Reporting & Rate-limited Collector (SHOULD / MUST)

- **Statement:** A dedicated, rate-limited, privacy-preserving CSP report endpoint (`/__csp-report`) **SHOULD** be configured. Reports arriving to this endpoint **MUST** be redacted for PII and rate-limited to avoid DoS and log flooding.
- **Rationale:** `report-uri` / `report-to` provides early visibility for CSP violations — but uncontrolled collectors create privacy and availability risks. This complements your telemetry and logging policies.
- **Implementation (high level):**
  - Build-time: add `report-to` group to policy and include in the CSP header JSON output.
  - Runtime: implement a tiny serverless collector (BFF/Worker) that:
    - strips cookies, user IP, and high-entropy fields,
    - enforces a per-origin and per-IP rate limit,
    - emits structured telemetry events or alerts for repeated/critical violations.

- **Example collector pseudo:**

```js
// Example: Cloudflare Worker / serverless pseudo
export default {
  async fetch(request) {
    if (request.method !== "POST")
      return new Response("Only POST", { status: 405 });
    const body = await request.json().catch(() => null);
    const report = body?.["csp-report"] || {};
    // redaction + structured log
    const redacted = {
      blocked_uri: report.blocked_uri,
      effective_directive: report.effective_directive,
      user_agent_group: summarizeUserAgent(report.user_agent),
      // DO NOT store raw request headers or cookies
    };
    // enforce rate-limit logic here...
    await forwardToSecureLogging(redacted);
    return new Response(null, { status: 204 });
  },
};
```

### 2.2. Trusted Types

- **Statement:** All assignments to dangerous DOM sinks (`innerHTML`, `outerHTML`, `script.src`, etc.) **MUST** use a `TrustedType` object. Direct string assignment is forbidden by the CSP.
- **Rationale:** CSP does not protect against DOM-based XSS. Trusted Types moves sink protection from the server to the client, making such attacks impossible by default in supporting browsers. The reference implementation for creating `TrustedType` objects is `DOMPurify` (see Appendix C).
- **Implementation:** Use a centralized `app-policy` that sanitizes input (e.g., with DOMPurify) before creating a `TrustedHTML` object. A `default` policy must be in place to block and log any direct string assignments.

### 2.3. Subresource Integrity (SRI)

- **Statement:** All third-party assets (JS, CSS) loaded from external domains (CDNs) **MUST** include the `integrity` attribute.
- **Rationale:** Mitigates supply chain attacks where a CDN could be compromised. SRI guarantees that the browser will only execute the exact file we intended.
- **Example:**
  ```html
  <script
    src="https://cdn.example.com/library.js"
    integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wJ"
    crossorigin="anonymous"
  ></script>
  ```

### 2.4. Hardened HTTP Headers

- **Statement:** The server **MUST** send additional security headers to disable insecure browser features.
- **Rationale:** These headers close various attack vectors, from clickjacking to MIME-type sniffing.
- **Implementation:**
  ```http
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: geolocation=(), microphone=(), camera=()
  ```
- All HTTP responses containing sensitive data (e.g., API responses with user profiles, authenticated content) **MUST** include `Cache-Control: no-store` and `Pragma: no-cache` headers to prevent caching by browsers and intermediate proxies.
  ```http
  Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate
  Pragma: no-cache
  Expires: 0
  ```
- **ASVS Reference:** V14.3.2 (Application sets sufficient anti-caching HTTP response header fields).
- **CI Check:** Automated E2E tests or security scans should verify the presence of these headers on responses from sensitive endpoints.

### 2.5. Runtime Environment Assertions

- **Statement:** At startup, the application **MUST** assert the presence of required browser security primitives (e.g., `window.trustedTypes`, `window.crypto.subtle`).
- **Rationale:** A misconfigured environment or unsupported browser could lead to silent security failures. We must fail loudly and safely.
- **Implementation:**
  ```javascript
  if (typeof window.trustedTypes === "undefined") {
    console.error(
      "[Security]: Trusted Types API not available. Critical DOM features will be disabled.",
    );
    // Activate a circuit-breaker to disable features relying on Trusted Types.
  }
  ```

#### 2.6. Source Map Security (MUST NOT)

- **Statement:** Source maps (`.map` files) **MUST NOT** be deployed to public production environments.
- **Rationale:** While invaluable for debugging, source maps expose the original, unminified source code. This includes comments, variable names, and the original file structure, which provides a detailed roadmap for attackers looking to find vulnerabilities in the application logic, abuse developer-centric features.
- **Implementation:**
  - The production build process **MUST** be configured to disable source map generation or prevent the `.map` files from being uploaded to the public web server.
  - If source maps are required for production error monitoring (e.g., for a service like Sentry), they **MUST** be uploaded directly to that secure, private service and not be publicly accessible via a URL.

#### **2.7. Client-Side Secret Prohibition (MUST NOT)**

- **Statement:** API keys, tokens, or any other secrets **MUST NOT** be embedded in the client-side JavaScript bundle.
- **Rationale:** All code and assets on a static site are publicly downloadable and inspectable. Embedding secrets in the JavaScript source is equivalent to publishing them publicly. This can lead to immediate abuse of third-party service quotas and unauthorized access to protected APIs.
- **Implementation:**
  - For interactions with protected APIs, a "Backend for Frontend" (BFF) pattern **MUST** be used. This typically involves a lightweight serverless function (e.g., AWS Lambda, Cloudflare Worker) that acts as a proxy.
  - The serverless function holds the secret and makes the request to the third-party API on behalf of the client. The static site communicates only with this trusted serverless function.
  - This pattern ensures that secrets never leave the secure server-side environment.

This architectural rule is non-negotiable for any static site that needs to interact with a protected API.

### 2.8. Cross-Origin Resource Sharing (CORS) Policy (MUST)

- **Statement:** The frontend application **MUST** be built with the expectation that all cross-origin APIs adhere to a strict, non-wildcard CORS policy. Any Backend-for-Frontend (BFF) or serverless function supporting the application **MUST** implement a specific, allowlisted origin policy.
- **Rationale:** While CORS is a server-enforced mechanism, a secure frontend architecture relies on it being configured correctly. Assuming a strict policy prevents the development of features that would fail in a secure environment and reinforces our Zero Trust model for network interactions. A wildcard (`*`) policy is forbidden for any API that handles authenticated or sensitive requests, as it can expose the application to cross-site data theft.
- **Implementation:**
  1.  All cross-origin `fetch()` requests that require authentication (e.g., to a BFF) **MUST** include the `credentials: 'include'` option.
  2.  The application **MUST** expect the server to respond with a specific `Access-Control-Allow-Origin` header (e.g., `https://your-site.com`), not a wildcard (`*`), when credentials are included.
  3.  Automated integration tests **SHOULD** verify that API calls fail as expected if the server were to return an invalid CORS header.

### 2.9. Secure Cross-Context Communication (postMessage) (MUST)

- **Statement:** All communication between different window contexts (e.g., `window` and an `<iframe>`) **MUST** use the `postMessage` API with strict origin validation.
- **Rationale:** Directly accessing content between frames from different origins is blocked by the Same-Origin Policy. The `postMessage` API provides a secure channel for this communication, but it can be abused if not implemented correctly. Failing to validate the origin of an incoming message can allow a malicious page to impersonate a trusted source and exfiltrate data or trigger unwanted actions. (Из Главы 8, "Patterns for secure frame/native WebView bridge messaging").
- **Implementation (Receiving Messages):**
  1.  An allowlist of trusted origins **MUST** be maintained.
  2.  The `event.origin` property of every incoming message **MUST** be checked against this allowlist before any data is processed.

  ```javascript
  const ALLOWED_MESSAGE_ORIGINS = ["https://trusted-partner.com"];

  window.addEventListener("message", (event) => {
    // CRITICAL: Always verify the sender's origin.
    if (!ALLOWED_MESSAGE_ORIGINS.includes(event.origin)) {
      console.warn(
        `[Security]: Dropping message from non-allowlisted origin: ${event.origin}`,
      );
      return;
    }

    // Now it's safe to process event.data
    const { type, payload } = JSON.parse(event.data);
    // ...
  });
  ```

- **Implementation (Sending Messages):**
  1.  When sending a message via `targetWindow.postMessage()`, the `targetOrigin` parameter **MUST** be set to a specific origin (e.g., `https://trusted-partner.com`), not a wildcard (`*`).

  ```javascript
  // GOOD: Ensures the message is only sent if the recipient is at the expected origin.
  const targetOrigin = "https://trusted-partner.com";
  iframe.contentWindow.postMessage("sensitive-data", targetOrigin);

  // BAD: Leaks data to any origin the iframe may have navigated to.
  iframe.contentWindow.postMessage("sensitive-data", "*");
  ```

#### 2.10. Progressive Web App (PWA) Mandates. Service Worker Security (MUST)

- **Statement:** Any Service Worker script (`sw.js`) **MUST** be implemented with strict security controls to prevent scope hijacking and cache poisoning.
- **Rationale:** A Service Worker acts as a powerful, programmable network proxy for your application. A compromised Service Worker can intercept requests, serve malicious content, and remain active even after the user has left the site. Its security is therefore paramount, as detailed in **Chapter 8.7** of "Mastering JavaScript Secure Web Development".
- **Implementation:**
  1.  **Scope Limitation:** The Service Worker **MUST** be registered with the narrowest possible scope required for its functionality (e.g., `/app/` instead of `/`). This prevents it from controlling pages it shouldn't, like an admin login page served from the same domain.
  2.  **Secure Caching:** Sensitive or user-specific API responses **MUST NOT** be stored in the Service Worker cache unless encrypted. All cached assets must be served over HTTPS.
  3.  **Secure Updates:** The update process for a Service Worker **MUST** be secure. Any script that triggers an update (`registration.update()`) must ensure the new `sw.js` file is loaded from a trusted, secure origin.
  4.  **Input Sanitization:** All data received from `postMessage` or Push API events **MUST** be sanitized and validated before being acted upon, to prevent injection attacks targeting the Service Worker itself.
  5.  **Cache Poisoning Prevention:** The Service Worker **MUST** validate the integrity of responses before caching them, especially for resources from third-party origins. Responses that are opaque or have error status codes (e.g., not in the 2xx range) **MUST NOT** be cached to prevent serving broken or malicious content while offline.
  6.  **Secure Script Location:** The Service Worker script (`sw.js`) **MUST** be served from the root of its scope and its location **MUST NOT** be controllable by user input (e.g., via a URL parameter) to prevent loading a malicious script.
      7 **COOP for SW:** Ensure SW registration respects COOP; test for isolation conflicts.

#### 2.10.1. Service Worker Update Integrity Verification (MUST)

- **Statement:** The client **MUST** verify the integrity of any newly fetched `sw.js` before calling `registration.update()` or allowing it to take control. The build process **MUST** publish a signed manifest of worker hashes (e.g., `sw-manifest.json`) that the client verifies at registration time.
- **Rationale:** A stolen or swapped service worker is a high-impact compromise. Validating the worker content against a build-signed manifest prevents silent takeover in case of CDN or pipeline compromise.&#x20;
- **Implementation sketch:**
  - Build produces `sw-manifest.json` → `{ "sw.js":"sha256-..." }`.
  - At install/update: fetch `sw.js`, compute SHA-256 in the client, compare to manifest value before passing to `navigator.serviceWorker.register()` or `update()`.

- **Snippet (browser):**

```js
async function verifyAndRegisterSW(
  manifestUrl = "/sw-manifest.json",
  swUrl = "/sw.js",
) {
  const manifest = await fetch(manifestUrl).then((r) => r.json());
  const expected = manifest["sw.js"];
  const resp = await fetch(swUrl, { cache: "no-store" });
  const buf = await resp.arrayBuffer();
  const hash =
    "sha256-" +
    btoa(
      String.fromCharCode(
        ...new Uint8Array(await crypto.subtle.digest("SHA-256", buf)),
      ),
    );
  if (hash !== expected) throw new Error("ServiceWorker integrity mismatch");
  // proceed with navigator.serviceWorker.register(swUrl) if integrity ok
}
```

### 2.11. Cross-Origin Request Forgery (CSRF) Protection (MUST)

- **Statement:** All state-changing requests (e.g., POST, PUT, DELETE) sent to a backend service (BFF) **MUST** be protected against CSRF using a combination of SameSite cookies and a custom request header verification method.
- **Rationale:** CSRF attacks trick an authenticated user's browser into sending a malicious request to your application. While the Same-Origin Policy prevents a malicious site from reading the response, it does not prevent it from sending the request. We use multiple layers to defend against this, as per our "Defense in Depth" principle.
- **Implementation:**
  1.  **SameSite Cookies:** Any session cookies issued by the BFF **MUST** use the `SameSite=Strict` attribute. This is the first line of defense, preventing the browser from sending the cookie on most cross-origin requests.
  2.  **Custom Header Verification:** The frontend application **MUST** send a custom, non-standard HTTP header (e.g., `X-CSRF-Token`) with every state-changing request. The BFF **MUST** be configured to reject any state-changing request that does not contain this header. This defense relies on the fact that while cross-origin requests can be _sent_, they cannot be sent with custom headers without a successful CORS preflight, which a simple malicious HTML form cannot trigger.
- **Example (Frontend):**
  ```javascript
  // The BFF would set a cookie with the token value on login.
  // The client reads this cookie and sets it as a header.
  const csrfToken = getCookie("csrf-token");
  fetch("/api/update-profile", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({
      /* ... */
    }),
  });
  ```

### 2.12. Platform-Specific Mandates (Cloudflare Pages) (MUST)

- **Statement:** All deployments to Cloudflare Pages **MUST** configure security features via the `_headers` file or dashboard. This includes enforcing HTTPS redirects, enabling WAF rules for XSS/SQLi, and setting rate limiting for API endpoints if a BFF is used.
- **Rationale:** Cloudflare provides managed security layers that complement our client-side controls, adhering to "Defense in Depth." Misconfiguration could expose the static site to attacks like DDoS or content tampering.
- **Implementation:**
  - Use the `_headers` file to set all headers from 2.4 (e.g., CSP, HSTS).
  - Enable Cloudflare's Managed Ruleset for OWASP Core Rules in the WAF.
  - For any dynamic routes (e.g., via Functions), apply rate limiting (e.g., 100 requests/min per IP).
  - **Forbidden:** Disabling Cloudflare's automatic HTTPS or Bot Management without security team approval.
- **CI Check:** A deployment script **MUST** validate the `_headers` file against a baseline template before pushing to Cloudflare.

### 2.13. Astro-Specific Security Mandates (MUST)

- **Statement:** All Astro integrations (e.g., MDX, Image) **MUST** use secure defaults. MDX rendering **MUST** include `rehype-sanitize` with a strict schema.
- **Rationale:** Prevents injection in content pipelines; Astro's build can introduce dynamic risks.
- **Implementation:**
  - In `astro.config.mjs`: `markdown: { rehypePlugins: [['rehype-sanitize', { tagNames: ['p', 'strong'] }]] }`
  - For Images: Use local optimization only; forbid remote sources without SRI.
- **CI Check:** Scan `astro.config` for required plugins.

## Part II-B: Backend / Serverless Function Mandates

These rules apply to any server-side logic, such as a Backend-for-Frontend (BFF) or serverless functions, that supports the static client.

### RULE: Server-Side Input Validation (MUST)

- **Statement:** All input received by any backend service (BFF, serverless function) **MUST** be validated at the trusted service layer to enforce business or functional expectations. This validation **MUST** use positive validation (allowlist) against expected values, patterns, and ranges, or be based on a strict schema.
- **Rationale:** Client-side validation is easily bypassed. Server-side validation is a critical first line of defense against various injection attacks, logic flaws, and unexpected data that could lead to crashes or vulnerabilities. This directly addresses ASVS V2.2.1 and V2.2.2.
- **Implementation (Good - Using a schema validator like Zod):**

  ```typescript
  import { z } from "zod";

  const createItemSchema = z.object({
    name: z.string().min(3).max(50),
    quantity: z.number().int().min(1).max(100),
    category: z.enum(["electronics", "books", "clothing"]),
  });

  // In the serverless function handler:
  try {
    const validatedInput = createItemSchema.parse(request.body);
    // Process validatedInput
  } catch (error) {
    return new Response(
      JSON.stringify({ message: "Invalid input", details: error.errors }),
      { status: 400 },
    );
  }
  ```

- **Forbidden:** Relying solely on client-side validation or using negative validation (blocklist) for security-critical fields.
- **ASVS Reference:** V2.2.1 (Input is validated to enforce business or functional expectations), V2.2.2 (Application is designed to enforce input validation at a trusted service layer).
- **CI Check:** API integration tests **MUST** include cases with invalid, malformed, and out-of-range inputs to verify server-side validation correctly rejects them.

### RULE: HTTP Method Enforcement (MUST)

- **Statement:** All API endpoints **MUST** explicitly define and enforce the HTTP methods they support. Requests using unsupported methods **MUST** be rejected with an `HTTP 405 Method Not Allowed` status.
- **Rationale:** This prevents attackers from interacting with endpoints using unintended HTTP verbs (e.g., sending a GET request to a POST-only endpoint), which could bypass security controls or trigger unexpected behavior. This aligns with the "Principle of Least Privilege" for API interaction.
- **Implementation (Good - Express/Cloudflare Workers):**

  ```javascript
  // Cloudflare Worker example
  async function handleRequest(request) {
    if (request.method === "POST") {
      // ... handle POST request ...
    } else {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "POST" },
      });
    }
  }

  // Express.js example
  app.post("/api/resource", (req, res) => {
    /* ... */
  });
  app.all("/api/resource", (req, res) =>
    res.status(405).set("Allow", "POST").send("Method Not Allowed"),
  );
  ```

- **ASVS Reference:** V4.1.4 (Only HTTP methods that are explicitly supported by the application or its API can be used and that unused methods are blocked).
- **CI Check:** Integration tests should attempt to access endpoints with various unsupported HTTP methods (e.g., GET on a POST-only endpoint) and verify a 405 response.

### RULE: HTTP Message Structure Validation (MUST)

- **Statement:** Any backend service (BFF, serverless function) that processes incoming HTTP messages **MUST** correctly determine message boundaries and validate HTTP message structure to prevent HTTP request smuggling, response splitting, and header injection attacks.
- **Rationale:** HTTP desynchronization attacks (request smuggling) can lead to severe vulnerabilities, allowing attackers to bypass security controls, access sensitive data, or poison caches. Correctly parsing `Content-Length` and `Transfer-Encoding` headers, especially when different HTTP versions are involved, is critical.
- **Implementation:**
  - Rely on robust, up-to-date HTTP server frameworks (e.g., Node.js `http` module, Cloudflare Workers' built-in request parsing) that are known to correctly handle HTTP message framing.
  - Avoid custom HTTP parsing logic.
  - Ensure that HTTP/2 or HTTP/3 messages do not contain connection-specific header fields or CR/LF sequences in header values.
- **ASVS Reference:** V4.2.1 (All application components determine boundaries of incoming HTTP messages), V4.2.2 (Content-Length header field does not conflict with content length), V4.2.3 (Does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields), V4.2.4 (Only accepts HTTP/2 and HTTP/3 requests where header fields and values do not contain any CR, LF, or CRLF sequences).
- **CI Check:** Automated security scanners (e.g., OWASP ZAP, Burp Suite) should be run against BFF/serverless endpoints to detect HTTP request smuggling vulnerabilities.

### RULE: Data Minimization in Responses (MUST)

- **Statement:** All API responses and data rendered to the client **MUST** adhere to the principle of data minimization, returning only the absolute minimum required sensitive data for the application's functionality. Over-fetching or returning entire data objects with potentially sensitive fields is forbidden.
- **Rationale:** This prevents accidental information leakage, reduces the attack surface, and aligns with the "Principle of Least Privilege" for data exposure. For example, only returning the last four digits of a credit card number instead of the full number.
- **Implementation (Good):**

  ```typescript
  // In a serverless function
  const user = await db.getUser(userId);
  if (!user) {
    /* ... */
  }

  // Explicitly select safe, minimal fields for the response
  const publicUser = {
    id: user.id,
    name: user.name,
    email: user.email, // Assuming email is public for this context
    // Do NOT include user.passwordHash, user.isAdmin, user.privateNotes
  };
  return new Response(JSON.stringify(publicUser), { status: 200 });
  ```

- **Forbidden:** Returning `SELECT *` from a database query directly to the client, or serializing entire internal objects without explicit field selection.
- **ASVS Reference:** V14.2.6 (Verify that the application only returns the minimum required sensitive data for the application’s functionality).
- **CI Check:** API integration tests should verify that responses from sensitive endpoints do not contain unexpected or excessive data fields.

### RULE: Mass Assignment Prevention (MUST)

- **Statement:** Any function that processes incoming data (e.g., from a POST body) to create or update a data model **MUST NOT** use automatic binding of incoming data to internal objects. Data **MUST** be mapped explicitly or through a Data Transfer Object (DTO) with an allowlist of properties.
- **Rationale:** Mass assignment vulnerabilities occur when a framework automatically binds all incoming request parameters to an object. An attacker can inject unexpected parameters (e.g., `isAdmin=true`) to modify object properties that should not be user-controllable, leading to privilege escalation. Explicitly mapping only the expected fields mitigates this.
- **Implementation (Good - DTO with a schema validator):**

  ```typescript
  // Using Zod to define a DTO schema
  const userUpdateSchema = z.object({
    name: z.string(),
    email: z.string().email(),
    // Note: 'isAdmin' or 'role' is NOT included in the schema.
  });

  // In the serverless function handler:
  const validatedData = userUpdateSchema.parse(request.body);
  // Only validatedData properties are used to update the database model.
  db.updateUser(userId, validatedData);
  ```

- **Implementation (Bad - Direct Binding):**
  ```javascript
  // VULNERABLE: The entire request body is passed to the update function.
  // If the body contains `{"isAdmin": true}`, it could be written to the DB.
  db.updateUser(userId, request.body);
  ```

### RULE: OS Command Injection Prevention (MUST)

- **Statement:** Calling OS commands from server-side logic is forbidden by default. If absolutely necessary, it **MUST** be done using APIs that support parameterization and **MUST NOT** involve shell interpretation. User-supplied input **MUST NEVER** be concatenated directly into a command string.
- **Rationale:** Directly executing OS commands with user input is a primary vector for remote code execution. An attacker can inject shell metacharacters (`&`, `|`, `;`, `$()`) to execute arbitrary commands on the server.
- **Implementation (Good - Using `child_process.execFile` in Node.js):**

  ```javascript
  import { execFile } from "node:child_process";

  // The command is fixed, and user input is passed as an array of arguments.
  // The arguments are not interpreted by a shell.
  execFile("ls", ["-la", userInput.directory], (error, stdout, stderr) => {
    // ...
  });
  ```

- **Implementation (Bad - Using `exec` with string concatenation):**

  ```javascript
  import { exec } from "node:child_process";

  // VULNERABLE: If userInput.directory is "; rm -rf /", disaster strikes.
  exec(`ls -la ${userInput.directory}`, (error, stdout, stderr) => {
    // ...
  });
  ```

### RULE: Secrets-in-Edge & Deploy-time Secrets (MUST)

- **Statement:** Serverless / edge secrets **MUST** be stored in the hosting provider's secret manager (e.g., Cloudflare Pages/Workers secrets or equivalent) and never committed to source or embedded in static bundles. Access to secrets must be audited and rotated per policy.
- **Rationale:** Mirrors existing client-side secret prohibition and ensures secrets used by BFF/Workers are tightly scoped.&#x20;
- **Implementation notes:** Document in the repo a `SECURE_SECRETS.md` describing the provider-specific secret injection mechanism. Add a CI check that fails on accidental secret-like strings in artifacts.

### RULE: SQL Injection Prevention (MUST)

- **Statement:** Any function that interacts with a SQL database **MUST** use parameterized queries (also known as prepared statements). Dynamic query construction using string concatenation with user input is strictly forbidden.
- **Rationale:** This is a direct application of the principles in the OWASP Query Parameterization Cheat Sheet. SQL Injection is a critical vulnerability that allows an attacker to execute arbitrary SQL commands on the database, leading to data exfiltration, modification, or destruction. Parameterization ensures that user input is always treated as data, never as executable code.
- **Implementation (Good - Parameterized Query in Node.js with `pg`):**

  ```javascript
  const { Pool } = require("pg");
  const pool = new Pool();

  // User input is passed as a separate array of values.
  const query = "SELECT * FROM users WHERE id = $1";
  const values = [userInput.id];
  const { rows } = await pool.query(query, values);
  ```

- **Implementation (Bad - String Concatenation):**
  ```javascript
  // VULNERABLE: An attacker can set userInput.id to "1 OR 1=1"
  const query = `SELECT * FROM users WHERE id = ${userInput.id}`;
  const { rows } = await pool.query(query);
  ```

### RULE: Server-Side Request Forgery (SSRF) Prevention (MUST)

- **Statement:** Any server-side function that makes a network request to a URL based on user-provided input **MUST** validate that URL against a strict allowlist of permitted hosts, IPs, and ports.
- **Rationale:** As detailed in the OWASP SSRF Prevention Cheat Sheet, failing to validate user-supplied URLs can allow an attacker to force the server to make requests to internal, protected resources (like metadata services in a cloud environment) or to scan the internal network. This turns your server into a proxy for the attacker.
- **Implementation:**
  1.  Maintain an explicit allowlist of domains or IP addresses the service is allowed to contact.
  2.  Parse the user-provided URL and verify that its hostname and port match an entry in the allowlist.
  3.  Disable redirects in the HTTP client to prevent an attacker from redirecting a valid request to a forbidden internal resource.
- **Implementation (Good - Allowlist Check in Node.js):**

  ```javascript
  const ALLOWED_HOSTS = new Set(["api.trustedpartner.com", "images.cdn.com"]);

  function isUrlAllowed(url) {
    try {
      const parsedUrl = new URL(url);
      return ALLOWED_HOSTS.has(parsedUrl.hostname);
    } catch (e) {
      return false;
    }
  }

  if (isUrlAllowed(userInput.imageUrl)) {
    // Proceed with the fetch, ensuring redirects are disabled.
  }
  ```

- **Implementation (Bad - Direct Fetch):**
  ```javascript
  // VULNERABLE: userInput.imageUrl could be "http://169.254.169.254/latest/meta-data/"
  // which is the AWS metadata service.
  const response = await fetch(userInput.imageUrl);
  ```

### RULE: Secure Session Management (MUST)

- **Statement:** If the BFF manages user sessions, it **MUST** adhere to strict session management hygiene. This includes regenerating session IDs upon login and using secure cookie attributes.
- **Rationale:** The OWASP Session Management Cheat Sheet highlights that improper session handling can lead to session fixation and hijacking. A compromised session is equivalent to compromised credentials.
- **Implementation:**
  1.  **Session ID Regeneration:** Upon any change in privilege level (especially login), the existing session ID **MUST** be invalidated and a new, cryptographically random session ID **MUST** be generated.
  2.  **Secure Cookie Attributes:** Any session cookie issued by the BFF **MUST** use the `HttpOnly`, `Secure`, and `SameSite=Strict` attributes.
      - `HttpOnly`: Prevents client-side scripts from accessing the cookie.
      - `Secure`: Ensures the cookie is only sent over HTTPS.
      - `SameSite=Strict`: Provides strong protection against CSRF.
  3.  **Session Expiration:** Sessions **MUST** have both an idle timeout (e.g., 15 minutes) and an absolute timeout (e.g., 8 hours).

### RULE: API Rate Limiting (MUST)

- **Statement:** All API endpoints, especially those that are unauthenticated or perform resource-intensive operations, **MUST** be protected by a robust rate-limiting strategy.
- **Rationale:** As detailed in Chapter 5.6 ("Rate Limiting and Throttling"), rate limiting is a critical defense against Denial of Service (DoS) attacks, brute-force attempts on authentication endpoints, and general API abuse. It ensures service availability, protects backend resources from being overwhelmed, and provides a mechanism for fair resource allocation among clients.
- **Implementation:**
  1.  A middleware **MUST** be used to track and limit the number of requests from a single IP address (or authenticated user) within a given time window.
  2.  For distributed environments (like serverless functions), the rate-limiting state **MUST** be stored in a centralized, low-latency store (e.g., Redis) to ensure limits are applied consistently across all instances.
  3.  When a client exceeds the rate limit, the server **MUST** respond with an `HTTP 429 Too Many Requests` status code and **SHOULD** include a `Retry-After` header.
- **Implementation (Good - Using `express-rate-limit` with Redis):**

  ```javascript
  import rateLimit from "express-rate-limit";
  import RedisStore from "rate-limit-redis";
  import { createClient } from "redis";

  const redisClient = createClient({
    // Redis configuration...
  });
  await redisClient.connect();

  const apiLimiter = rateLimit({
    store: new RedisStore({
      sendCommand: (...args) => redisClient.sendCommand(args),
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Apply to all API routes
  app.use("/api/", apiLimiter);
  ```

- **Implementation (Bad - No Rate Limiting):**
  ```javascript
  // VULNERABLE: An attacker can flood this endpoint with requests,
  // potentially overwhelming the database or causing a DoS.
  app.post("/api/login", (req, res) => {
    // ... authentication logic ...
  });
  ```

### RULE: Unintended Content Interpretation Prevention (MUST)

- **Statement:** Security controls **MUST** be in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API response, a user-uploaded file, or another resource is requested directly but rendered as HTML). Possible controls include: not serving the content unless HTTP request header fields (such as `Sec-Fetch-*`) indicate it is the correct context, using the `sandbox` directive of the `Content-Security-Policy` header field, or using the `attachment` disposition type in the `Content-Disposition` header field.
- **Rationale:** Malicious actors can trick browsers into interpreting content in an unintended way (e.g., an image file as a script), leading to XSS or other attacks. Explicitly controlling content interpretation is a critical defense.
- **ASVS Reference:** V3.2.1 (Security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context).

### RULE: Safe Rendering of Text Content (MUST)

- **Statement:** Content intended to be displayed as text, rather than rendered as HTML, **MUST** be handled using safe rendering functions (suchg as `createTextNode` or `textContent`) to prevent unintended execution of content such as HTML or JavaScript.
- **Rationale:** This is a fundamental defense against XSS. Directly assigning untrusted strings to `innerHTML` or similar properties without proper escaping or sanitization allows malicious scripts to execute.
- **ASVS Reference:** V3.2.2 (Content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions).

### RULE: HTTP Methods for Sensitive Functionality (MUST)

- **Statement:** HTTP requests to sensitive functionality (e.g., state-changing operations, resource-demanding functionality) **MUST** use appropriate HTTP methods such as `POST`, `PUT`, `PATCH`, or `DELETE`, and **MUST NOT** use methods defined by the HTTP specification as "safe" (e.g., `HEAD`, `OPTIONS`, or `GET`). Alternatively, strict validation of `Sec-Fetch-*` request header fields can be used to ensure the request did not originate from an inappropriate cross-origin call, navigation, or resource load.
- **Rationale:** Using "safe" HTTP methods for state-changing operations can lead to CSRF vulnerabilities or unintended side effects if a browser pre-fetches or caches the resource. Enforcing appropriate methods aligns with the "Principle of Least Privilege" and prevents accidental or malicious state changes.
- **ASVS Reference:** V3.5.3 (HTTP requests to sensitive functionality use appropriate HTTP methods).

### RULE: No Authorization Data in Script Responses (MUST NOT)

- **Statement:** Data requiring authorization **MUST NOT** be included in script resource responses (e.g., JavaScript files).
- **Rationale:** Including sensitive, authenticated data directly within JavaScript files can lead to Cross-Site Script Inclusion (XSSI) attacks, where a malicious site can load your script and extract the embedded sensitive data.
- **ASVS Reference:** V3.5.7 (Data requiring authorization is not included in script resource responses, like JavaScript files).

### RULE: Controlled Loading of Authenticated Resources (MUST)

- **Statement:** Authenticated resources (such as images, videos, scripts, and other documents) **MUST** be loaded or embedded on behalf of the user only when explicitly intended. This **MUST** be accomplished by strict validation of the `Sec-Fetch-*` HTTP request header fields to ensure the request did not originate from an inappropriate cross-origin call, or by setting a restrictive `Cross-Origin-Resource-Policy` HTTP response header field to instruct the browser to block returned content.
- **Rationale:** Prevents attackers from embedding authenticated resources (e.g., a user's profile picture) on their own malicious sites, potentially leading to information leakage or tracking.
- **ASVS Reference:** V3.5.8 (Authenticated resources can be loaded or embedded on behalf of the user only when intended).

### RULE: Supported Client-Side Technologies (MUST)

- **Statement:** The application **MUST** only use client-side technologies that are still supported and considered secure. Technologies such as NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets are strictly forbidden.
- **Rationale:** Using deprecated or insecure client-side technologies introduces known vulnerabilities and increases the attack surface. This aligns with the "Secure by Default" principle.
- **ASVS Reference:** V3.7.1 (Application only uses client-side technologies which are still supported and considered secure).

### RULE: External Redirect Notification (SHOULD)

- **Statement:** The application **SHOULD** show a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation.
- **Rationale:** This provides an additional layer of protection against phishing and open redirect vulnerabilities by giving the user a chance to review and cancel an unexpected external navigation.
- **ASVS Reference:** V3.7.3 (Application shows a notification when the user is being redirected to a URL outside of the application’s control).

### RULE: HSTS Preload List Submission (MUST)

- **Statement:** The application's top-level domain (e.g., `site.tld`) **MUST** be added to the public preload list for HTTP Strict Transport Security (HSTS).
- **Rationale:** This ensures that the use of TLS for the application is built directly into major browsers, rather than relying only on the `Strict-Transport-Security` response header field. It provides the strongest possible guarantee against SSL stripping attacks from the very first visit.
- **ASVS Reference:** V3.7.4 (Application’s top-level domain is added to the public preload list for HTTP Strict Transport Security (HSTS)).

### RULE: Self-Contained Token Validation (MUST)

- **Statement:** If the BFF or any serverless function consumes self-contained tokens (e.g., JWTs, SAML assertions), it **MUST** perform comprehensive validation before accepting the token's contents or making security decisions based on them.
- **Rationale:** Self-contained tokens are powerful but prone to misuse if not validated correctly. This rule ensures the token's authenticity, integrity, and intended use, preventing various attacks like token tampering, replay, or cross-service misuse.
- **Implementation:**
  1.  **Digital Signature/MAC Validation (MUST):** The token's digital signature or Message Authentication Code (MAC) **MUST** always be validated to protect against tampering. Any unsigned or invalidly signed token **MUST** be rejected.
      - **ASVS Reference:** V9.1.1 (Self-contained tokens are validated using their digital signature or MAC).
  2.  **Algorithm Allowlist (MUST):** Only algorithms on an explicit allowlist **MUST** be used to create and verify self-contained tokens for a given context. The allowlist **MUST NOT** include the 'None' algorithm. If both symmetric and asymmetric algorithms must be supported, additional controls **MUST** be in place to prevent key confusion.
      - **ASVS Reference:** V9.1.2 (Only algorithms on an allowlist can be used to create and verify self-contained tokens).
  3.  **Trusted Key Material Sources (MUST):** Key material used to validate self-contained tokens **MUST** come from trusted, pre-configured sources for the token issuer. Attackers **MUST NOT** be able to specify untrusted sources or keys (e.g., for JWTs, headers like 'jku', 'x5u', and 'jwk' **MUST** be validated against an allowlist).
      - **ASVS Reference:** V9.1.3 (Key material that is used to validate self-contained tokens is from trusted pre-configured sources).
  4.  **Validity Period (MUST):** If a validity time span is present in the token data (e.g., JWT 'nbf' and 'exp' claims), the token and its content **MUST** only be accepted if the verification time is within this validity time span.
      - **ASVS Reference:** V9.2.1 (If a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span).
  5.  **Token Type and Purpose (MUST):** The service receiving a token **MUST** validate the token to be the correct type and intended purpose before accepting its contents (e.g., only access tokens for authorization, only ID Tokens for user authentication).
      - **ASVS Reference:** V9.2.2 (Service receiving a token validates the token to be the correct type and is meant for the intended purpose).
  6.  **Audience Validation (MUST):** The service **MUST** only accept tokens that are intended for use with that specific service (audience). For JWTs, this **MUST** be achieved by validating the 'aud' claim against an allowlist defined in the service.
      - **ASVS Reference:** V9.2.3 (Service only accepts tokens which are intended for use with that service (audience)).

---

## Part III: Secure Implementation Rules

This section provides prescriptive, code-level rules for all developers. Each rule follows a standard format for clarity and automated enforcement.

### A. DOM Interaction & Rendering

#### RULE: Selector Safety (MUST)

- **Statement:** Never interpolate unescaped user or server data into `querySelector` strings.
- **Rationale:** Prevents selector injection vulnerabilities and `DOMException` errors from malformed selectors.
- **Good (Attribute Matching):**
  ```javascript
  // Safe: Avoid composing selector strings from untrusted input.
  const headingId = sanitizeId(id); // Use a deterministic sanitizer.
  const activeLink = Array.from(container.querySelectorAll(".toc-link")).find(
    (l) => l.getAttribute("data-heading-id") === headingId,
  );
  ```
- **Good (CSS.escape):**
  ```javascript
  const escapedId = CSS.escape(id);
  const activeElement = container.querySelector(
    `[data-heading-id="${escapedId}"]`,
  );
  ```
- **Bad:**
  ```javascript
  // VULNERABLE: `id` could contain "]", breaking the selector.
  const activeElement = container.querySelector(`[data-heading-id="${id}"]`);
  ```
- **Tests:** Unit tests must feed malicious IDs containing `"` and `]` and verify lookup works correctly without throwing exceptions.
- **CI Check:** ESLint rule (`no-queryselector-interpolation`) that warns on string interpolation inside `querySelector` calls.

#### RULE: DOM Clobbering Prevention (MUST)

- **Statement:** Application logic **MUST** be resilient against DOM Clobbering. This is achieved by avoiding reliance on global variables for security-critical checks, using lexical scoping (`let`, `const`), and freezing critical objects.
- **Rationale:** DOM Clobbering is an attack where an attacker injects HTML (e.g., `<form id="criticalConfigObject">`) that creates a property on the `window` object. If your code insecurely references a global variable (e.g., `window.criticalConfigObject`), the attacker can overwrite it with a reference to an HTML element, leading to unexpected behavior and security bypasses.
- **Implementation:**
  - Never use `var` at the top level of a script; prefer modules and `const`/`let` inside closures or functions to avoid creating properties on the `window` object.
  - If a global configuration object is absolutely necessary, it **MUST** be frozen at startup to prevent modification.
- **Good (Frozen Object):**

  ```javascript
  const AppConfig = {
    apiUrl: "https://api.example.com",
    featureFlags: { canDelete: false },
  };
  Object.freeze(AppConfig);
  Object.freeze(AppConfig.featureFlags);

  // An attacker injecting <form id="AppConfig"> cannot overwrite the frozen object.
  ```

- **Bad (Vulnerable Global):**

  ```javascript
  // VULNERABLE: An attacker can inject <a id="CONFIG" href="javascript:alert(1)">
  // and window.CONFIG will now be a reference to the anchor element, not the object.
  var CONFIG = { isSecure: true };

  if (CONFIG.isSecure) {
    // This check can be bypassed.
  }
  ```

- **CI Check:** A linter rule **SHOULD** be configured to ban the use of `var` in the global scope.

#### RULE: Secure MDX Rendering (MUST)

- **Statement:** All MDX or Content Collection output **MUST** be processed through a sanitizer pipeline during Astro's build or render phase. Direct rendering of unsanitized MDX is forbidden.
- **Rationale:** MDX can embed HTML/JS, creating an XSS vector. This enforces "Defense in Depth" by combining build-time sanitization with runtime Trusted Types.
- **Implementation:**
  - Use `rehype-sanitize` in Astro's MDX config with a strict schema (e.g., GitHub-flavored Markdown allowlist).
  - For dynamic content, wrap rendered HTML in DOMPurify before DOM insertion.
  ```javascript
  import { remark } from "remark";
  import rehypeSanitize from "rehype-sanitize";
  // In Astro config or component
  const processed = await remark().use(rehypeSanitize).process(rawMDX);
  const safeHTML = DOMPurify.sanitize(processed.toString());
  ```
- **Tests:** Fuzz MDX inputs with malicious HTML/JS and assert sanitizer blocks them.
- **CI Check:** Scan Astro config files for MDX plugins and flag absences of sanitizers.

#### RULE: Secure & Performant Script Loading (MUST)

- **Statement:** All external third-party scripts **MUST** be loaded using either the `defer` or `async` attribute to prevent render-blocking. `defer` is preferred for scripts that need the DOM to be ready, while `async` is for independent, self-contained scripts. If it is possible, offload non-essential scripts to a worker thread.
- **Rationale:** A standard `<script>` tag blocks HTML parsing while it is being fetched and executed. This creates a poor user experience and can be a vector for performance degradation. Using `defer` ensures scripts execute in order after the document is parsed but before `DOMContentLoaded`, making it the safest default. `async` executes as soon as the script is downloaded, which can be useful but risks unpredictable execution order. This aligns with the asset loading optimizations discussed in Chapter 10.
- **Good (Preferred):**
  ```html
  <!-- Non-critical analytics or UI script that should not block rendering. -->
  <script src="https://analytics.example.com/tracker.js" defer></script>
  ```
- **Good (For independent scripts):**
  ```html
  <!-- A third-party script that has no dependencies on the DOM or other scripts. -->
  <script src="https://ads.example.com/ad-loader.js" async></script>
  ```
- **Bad:**
  ```html
  <!-- VULNERABLE: Blocks page rendering, degrading performance and user experience. -->
  <script src="https://widget.example.com/main.js"></script>
  ```
- **CI Check:** A CI job or linter **SHOULD** scan the final HTML output for `<script>` tags lacking either an `async` or `defer` attribute and flag them for review.

#### RULE: Third-Party Script Isolation (SHOULD)

- **Statement:** Non-essential third-party scripts, especially those for analytics, marketing, or advertising, **SHOULD** be executed in a Web Worker to isolate them from the main thread and the primary DOM.
- **Rationale:** Third-party scripts are a significant supply chain risk. Executing them on the main thread gives them access to the `window` object, sensitive DOM content, and the ability to degrade application performance. Moving them to a worker thread via a library like Partytown severely restricts their access (e.g., no direct DOM access, proxied `localStorage`), creating a sandbox that mitigates the risk of data exfiltration and main-thread blocking. This is a practical application of executing code off the main thread as detailed in Chapter 10.
- **Implementation:**
  - Utilize a framework feature (like Next.js's experimental `strategy="worker"`) or a library like Partytown to manage the proxying of third-party scripts to a worker.
  - The CSP **MUST** be configured to allow the worker scripts and any necessary `blob:` or `data:` URLs that the proxy library requires.
- **Good:**
  ```html
  <!-- Using a library like Partytown to proxy the script -->
  <script
    type="text/partytown"
    src="https://analytics.google.com/gtm.js"
  ></script>
  ```
- **Bad:**
  ```html
  <!-- High Risk: Script runs on the main thread with full DOM access. -->
  <script src="https://analytics.google.com/gtm.js" async></script>
  ```
- **Tests:** Verify that third-party scripts are correctly loaded and that their network requests originate from the worker context, not the main window context.

#### RULE: Delegated Click Handling (MUST)

- **Statement:** Always use `event.target.closest(selector)` for delegated event handlers; `event.target.matches(selector)` is forbidden for this purpose.
- **Rationale:** `matches()` fails if the user clicks on a nested element (e.g., a `<span>` inside an `<a>`), breaking functionality and security assumptions. `closest()` correctly traverses up the DOM tree to find the intended target.
- **Good:**
  ```javascript
  container.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const link = event.target.closest("a.some-delegated-link");
    if (link) {
      event.preventDefault();
      // Handle click...
    }
  });
  ```
- **Bad:**
  ```javascript
  // FRAGILE: Fails if the click target is a child of the anchor.
  container.addEventListener("click", (event) => {
    if (event.target.matches("a.some-delegated-link")) {
      // This block may never be reached.
    }
  });
  ```
- **Tests:** Integration test that simulates a click on a child element within the delegated parent and asserts the handler fires correctly.
- **CI Check:** Custom ESLint rule to flag usage of `event.target.matches()` inside event listeners.

#### RULE: Separation of Pure Logic from Impure Actions (MUST)

- **Statement:** Business logic and data transformation functions **MUST** be pure. All side effects (DOM manipulation, network requests, `localStorage` access, `console.log`) **MUST** be isolated at the boundaries of the application (e.g., in event handlers or dedicated "effect" modules).
- **Rationale:** This principle, drawn from the core of functional programming (Chapter 4), drastically reduces the attack surface. Pure functions are deterministic, easily testable, and cannot be sources of side-effect-based vulnerabilities. By isolating impurity, we can focus our most stringent security reviews on a much smaller, well-defined part of the codebase.
- **Implementation:**
  - A "core" module should export pure functions that take data and return new data.
  - An "event handler" or "controller" module imports these pure functions, calls them with the necessary state, and then uses the return value to perform the impure action (e.g., updating the DOM).
- **Good:**

  ```javascript
  // --- pure-logic.js ---
  // Pure, testable, no side effects.
  export function createGreeting(name) {
    return `Hello, ${name}!`;
  }

  // --- event-handler.js ---
  import { createGreeting } from "./pure-logic.js";
  // Impure action is isolated here.
  document.getElementById("btn").addEventListener("click", () => {
    const greeting = createGreeting("World");
    document.getElementById("output").textContent = greeting; // Side effect
  });
  ```

- **Bad:**
  ```javascript
  // VULNERABLE & HARD TO TEST: Logic and side effects are mixed.
  function createAndDisplayGreeting(name) {
    const greeting = `Hello, ${name}!`;
    // Side effect is mixed with logic.
    document.getElementById("output").textContent = greeting;
  }
  ```
- **CI Check:** A linter rule **SHOULD** be configured to flag the use of global objects like `document` or `window` in files located in a designated `pure-logic/` directory.

#### RULE: Secure Hook Implementation (MUST)

- **Statement:** Using `DOMPurify.addHook()` is a security-critical operation that can bypass the sanitizer's core logic. All hooks **MUST** be reviewed and approved by the security team. Hooks **MUST NOT** perform unsafe operations that re-introduce vulnerabilities.
- **Rationale:** A poorly written hook can undermine the entire sanitization process. The official documentation warns of dangerous patterns where hooks can add unsanitized attributes, move nodes out of the sanitization path, or perform unsafe string modifications that create vulnerabilities after the sanitizer's checks have passed. This rule establishes a "trust but verify" policy for all hooks.
- **Forbidden Patterns in Hooks:**
  1.  **Adding Unsanitized Attributes:** A hook **MUST NOT** use `currentNode.setAttribute()` to add a new attribute. The new attribute will not be processed by the sanitizer.
  2.  **Unsafe Node Manipulation:** A hook **MUST NOT** move a node to a position in the DOM that the sanitizer's iterator has already passed, as this will cause the node and its children to escape sanitization.
  3.  **Unsafe String Modifications:** A hook **MUST NOT** use string transformations (e.g., `.toUpperCase()`, `.replaceAll()`) that can be abused through Unicode normalization or character cleanup to form forbidden tags or attributes _after_ sanitization checks.
- **Implementation:**
  - All hooks **MUST** be defined in a central, security-audited file.
  - Each hook **MUST** have a clear comment explaining its purpose and why it is safe.
  - **Example of a SAFER hook (from documentation):** Adding `target="_blank"` is generally safe because it modifies a known-safe attribute on elements that have already been vetted.
    ```javascript
    // This hook is considered safer because it operates on vetted nodes
    // and modifies attributes in a predictable, secure way.
    DOMPurify.addHook("afterSanitizeAttributes", function (node) {
      if ("target" in node) {
        node.setAttribute("target", "_blank");
        node.setAttribute("rel", "noopener noreferrer"); // Also add rel for security
      }
    });
    ```

#### RULE: Safe External Links (MUST)

- **Statement:** Any `<a>` or `<area>` element using `target="_blank"` **MUST** include `rel="noopener noreferrer"`.
- **Rationale:** Without `noopener`, a newly opened tab can access the original window via `window.opener` and potentially replace it with a malicious page (phishing the user):contentReference[oaicite:2]{index=2}. Using `noopener noreferrer` severs this link.
- **Implementation:** Always pair `target="_blank"` with `rel="noopener noreferrer"`. Example:

  ```html
  <!-- Good: -->
  <a href="https://example.com" target="_blank" rel="noopener noreferrer"
    >Link</a
  >

  <!-- Bad: -->
  <a href="https://example.com" target="_blank">Link</a>
  ```

- **CI Check:** A linter or HTML validator **MUST** flag any `target="_blank"` missing `rel="noopener"`.

##### **RULE: Batched DOM Updates (SHOULD)**

- **Statement:** DOM manipulations, especially those occurring in loops or in response to frequent events (e.g., `scroll`, `resize`), **SHOULD** be batched to avoid layout thrashing.
- **Rationale:** Interleaving DOM reads (e.g., `element.offsetWidth`) and writes (e.g., `element.style.width = '...'`) forces the browser to perform repeated, synchronous layout calculations, which can block the main thread. A blocked UI is not only a poor user experience but can also make the application more susceptible to timing attacks. (Из Главы 7.1).
- **Good (Batching with `documentFragment`):**
  ```javascript
  const fragment = document.createDocumentFragment();
  for (let i = 0; i < 100; i++) {
    const el = document.createElement("div");
    fragment.appendChild(el);
  }
  // Single write operation
  document.body.appendChild(fragment);
  ```
- **Good (Separating Reads/Writes with `requestAnimationFrame`):**

  ```javascript
  // Read
  const currentWidth = element.offsetWidth;

  // Schedule Write
  requestAnimationFrame(() => {
    element.style.width = currentWidth / 2 + "px";
  });
  ```

- **CI Check:** While difficult to enforce automatically, a linter rule could flag DOM manipulations inside loops and recommend batching patterns. This is primarily enforced during code review.

#### RULE: Predictable Error Handling via Result Types (SHOULD)

- **Statement:** Functions that can fail for predictable reasons (e.g., parsers, validators, data extractors) **SHOULD** return a result type (e.g., an object like `{ ok: true, value: ... }` or `{ ok: false, error: ... }`) instead of throwing exceptions.
- **Rationale:** Inspired by functional data types like `Maybe` and `Either` (Chapter 12), this pattern makes error handling explicit and declarative. It forces the calling code to handle the failure case, preventing unhandled exceptions that can lead to inconsistent application states or leak sensitive information through stack traces. It transforms error handling from an imperative `try/catch` side effect into a predictable data flow.
- **Implementation:**

  ```typescript
  type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };

  function parseJSON(raw: string): Result<object, Error> {
    try {
      return { ok: true, value: JSON.parse(raw) };
    } catch (e) {
      return { ok: false, error: e };
    }
  }
  ```

- **Good:**
  ```javascript
  const result = parseJSON('{ "invalid" }');
  if (result.ok) {
    // Use result.value
  } else {
    // Handle result.error
    console.error("Parsing failed:", result.error.message);
  }
  ```
- **Bad:**
  ```javascript
  // Can lead to unhandled exceptions if not wrapped in try/catch everywhere.
  try {
    const data = JSON.parse('{ "invalid" }');
  } catch (e) {
    // ...
  }
  ```
- **CI Check:** This is a pattern to be enforced during code review, especially for utility and data processing functions.

#### RULE: Selector Normalization (MUST)

- **Statement:** Any DOM selector derived from a URL (`href`, `src`) **MUST** be normalized to its fragment/hash before validation and use.
- **Rationale:** Raw `href` attributes can be relative or absolute URLs. Passing a full URL to a selector validator that expects a hash (e.g., `#id`) will cause incorrect validation failures and block legitimate functionality.
- **Good:**

  ```javascript
  const href = linkElement.getAttribute("href"); // e.g., "/page.html#ref-123"
  if (!href) return;

  let fragment;
  try {
    // Normalizes to "#ref-123" regardless of base URL.
    fragment = new URL(href, document.baseURI).hash;
  } catch (e) {
    console.error("Invalid URL for selector normalization", e);
    return;
  }

  if (fragment && SecureDOMValidator.validateSelector(fragment)) {
    const target = document.querySelector(fragment);
    // ...
  }
  ```

- **Bad:**
  ```javascript
  // WRONG: Passes a full URL to a validator expecting a hash.
  const href = linkElement.getAttribute("href");
  if (SecureDOMValidator.validateSelector(href)) {
    // This will likely fail.
  }
  ```
- **Tests:** Unit tests that pass relative, absolute, and malformed URLs to the normalization logic and assert correct fragment extraction or graceful error handling.
- **CI Check:** A linter rule could heuristically check for `getAttribute('href')` being passed directly to a function named `validateSelector` or `querySelector`.

#### RULE: Prefer Direct Attribute Checking (SHOULD)

- **Statement:** You **SHOULD** prefer safe DOM traversal and direct attribute equality checks over building dynamic attribute selectors from variables.
- **Rationale:** Dynamically constructing attribute selectors (e.g., `[href="#${id}"]`) is brittle and can re-introduce risks of injection or escaping errors, even with sanitization. Direct attribute checking is simpler and more robust. If you **MUST** build a dynamic selector, you **MUST** adhere to the 'Selector Safety' rule using `CSS.escape()`.
- **Good:**
  ```javascript
  const targetId = `#${sanitizedCitationId}`;
  const candidates = Array.from(targetElement.getElementsByTagName("a"));
  const returnLink = candidates.find(
    (link) => link.getAttribute("href") === targetId,
  );
  if (returnLink) {
    // Activate link...
  }
  ```
- **Acceptable (but not preferred):**
  ```javascript
  // This is only acceptable if the 'Good' pattern is not feasible.
  // It MUST use CSS.escape() as per the 'Selector Safety' rule.
  const escapedId = CSS.escape(sanitizedCitationId);
  const returnSelector = `a[href="#${escapedId}"]`;
  const returnLink = targetElement.querySelector(returnSelector); // Less robust than direct checking
  ```
- **Tests:** Adversarial tests where `sanitizedCitationId` contains characters that could break an attribute selector.
- **CI Check:** Flag `querySelectorAll` or `querySelector` calls that use template literals in the attribute selector part, and recommend the direct checking pattern.

#### RULE: DOM-Attached Data (SHOULD NOT)

- **Statement:** Do not add application state directly to DOM nodes (e.g., `element._myAppState`). Use `WeakMap<Element, State>` instead.
- **Rationale:** Direct property assignment pollutes the DOM, can cause memory leaks if not cleaned up, and risks collisions with other scripts or future browser APIs. `WeakMap` handles garbage collection automatically.
- **Good:**

  ```javascript
  const elementStateMap = new WeakMap();

  function attachState(element, state) {
    elementStateMap.set(element, state);
  }

  function getState(element) {
    return elementStateMap.get(element);
  }
  ```

- **Bad:**
  ```javascript
  // LEAKY & COLLISION-PRONE
  element._myComponentState = { active: true };
  ```
- **Tests:** Ensure components that are removed from the DOM do not retain references in memory.
- **CI Check:** ESLint rule to ban assignment to new properties on `Element` instances.

#### RULE: Prototype Pollution Prevention (MUST NOT)

- **Statement:** Any function that recursively merges or clones objects **MUST** explicitly check for and block keys named `__proto__`, `constructor`, or `prototype`.
- **Rationale:** Prototype Pollution is a critical vulnerability where an attacker can inject properties into `Object.prototype`, affecting all objects throughout the application. This can lead to privilege escalation, logic bypasses, and XSS. This rule is a direct defense against this underestimated threat. (Inspired by the "Prototype Pollution: The Hidden Menace" section of the security article).
- **Good (Explicit Check):**
  ```javascript
  function secureMerge(target, source) {
    for (const key in source) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        console.error(
          `[Security]: Prototype pollution attempt detected for key: ${key}`,
        );
        continue; // Skip the dangerous key
      }
      if (typeof source[key] === "object" && source[key] !== null) {
        if (!target[key]) target[key] = {};
        secureMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
  ```
- **Bad:**
  ```javascript
  // VULNERABLE: No checks for malicious keys.
  function vulnerableMerge(target, source) {
    for (const key in source) {
      if (typeof source[key] === "object") {
        if (!target[key]) target[key] = {};
        vulnerableMerge(target[key], source[key]); // Recursive call without validation
      } else {
        target[key] = source[key];
      }
    }
  }
  ```
- **CI Check:** SAST tools should be configured to flag recursive object-merging functions that lack checks for forbidden keys. Unit tests for these functions **MUST** include payloads designed to cause prototype pollution and assert that they are correctly handled.

#### RULE: Animation Validation & Safety (SHOULD)

- **Statement:** Validate keyframes and options before using the Web Animations API. Use a type-checked allowlist for properties and values.
- **Rationale:** Unvalidated input passed to the WAAPI can lead to unexpected behavior or be a vector for injecting malicious CSS values (e.g., `url(...)`).
- **Good:**

  ```javascript
  const ALLOWED_PROPS = new Set(["transform", "opacity", "backgroundColor"]);

  function isValidKeyframe(frame) {
    for (const prop in frame) {
      if (!ALLOWED_PROPS.has(prop)) return false;
    }
    if ("opacity" in frame) {
      const v = Number(frame.opacity);
      if (Number.isNaN(v) || v < 0 || v > 1) return false;
    }
    return true;
  }

  if (isValidKeyframe(userKeyframe)) {
    element.animate([userKeyframe], { duration: 500 });
  }
  ```

- **Tests:** Fuzz testing that feeds malicious CSS values like `url(javascript:...)` into the validator and asserts they are rejected.
- **CI Check:** Heuristic check for `element.animate` calls where keyframes are not statically defined or passed through a known validator function.

### B. State & Lifecycle Management

#### RULE: Event Listener Cleanup (MUST)

- **Statement:** Prefer `AbortController` and its `signal` option for managing event listener lifecycles. Fall back to explicit `removeEventListener` only when `signal` is not supported.
- **Rationale:** `AbortController` provides a robust, centralized, and leak-proof mechanism to clean up multiple event listeners at once, which is critical in single-page applications.
- **Good:**

  ```javascript
  class MyComponent {
    #abortController = new AbortController();

    constructor(element) {
      const signal = this.#abortController.signal;
      element.addEventListener("click", this.onClick, { signal });
      element.addEventListener("mouseover", this.onMouseOver, { signal });
    }

    destroy() {
      this.#abortController.abort(); // Removes all listeners instantly.
    }
  }
  ```

- **Tests:** Unit test that creates a component, calls `destroy()`, and asserts that no event handlers run afterward.
- **CI Check:** Lint rule that encourages using `{ signal }` when available.

#### RULE: Passive Listener Safety (MUST)

- **Statement:** If a delegated handler may call `event.preventDefault()`, its listener **MUST** be non-passive (`{ passive: false }`). Alternatively, check `event.cancelable` before calling `preventDefault()`.
- **Rationale:** Calling `preventDefault()` inside a passive listener is a runtime error that will be thrown by the browser. This can lead to unpredictable behavior.
- **Good (Separate Handlers):**
  ```javascript
  // Active listener for actions that need preventDefault
  container.addEventListener("click", activeHandler, { passive: false });
  // Passive listener for scrolling/observation
  container.addEventListener("scroll", passiveHandler, { passive: true });
  ```
- **Good (Cancelable Check):**
  ```javascript
  function mixedHandler(event) {
    if (someCondition && event.cancelable) {
      event.preventDefault();
    }
  }
  container.addEventListener("click", mixedHandler, { passive: false });
  ```
- **Bad:**
  ```javascript
  // THROWS ERROR: Calling preventDefault in a passive listener.
  container.addEventListener("click", (e) => e.preventDefault(), {
    passive: true,
  });
  ```
- **Tests:** Integration test that verifies no console errors are thrown when interacting with components that use mixed listener types.
- **CI Check:** A linter could flag `preventDefault()` calls inside functions attached as passive listeners, though this may be difficult to track statically.

#### RULE: Client-Side Data Clearing (MUST)

- **Statement:** Authenticated data and any other sensitive information stored client-side (e.g., in browser DOM, `sessionStorage`, `IndexedDB`, or non-HttpOnly cookies) **MUST** be cleared upon user logout or session termination.
- **Rationale:** This prevents sensitive data from persisting on the client, reducing the risk of exfiltration if the device is later compromised or used by another individual. It complements server-side session termination.
- **Implementation:**

  ```javascript
  function clearClientSensitiveData() {
    // Clear specific localStorage/sessionStorage keys
    localStorage.removeItem("userProfile");
    sessionStorage.clear(); // Or selectively remove items
    // Clear IndexedDB stores if used
    indexedDB.deleteDatabase("mySensitiveDB");
    // For non-HttpOnly cookies, set expiration to past
    document.cookie =
      "mySensitiveCookie=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    // Clear any sensitive data from the DOM if it was directly rendered
    document.getElementById("sensitive-display")?.textContent = "";
    // Use Clear-Site-Data header from server if possible for broader effect
  }

  // Call this function on logout, session expiration, or account deletion
  eventBus.subscribe("user:logout", clearClientSensitiveData);
  ```

- **ASVS Reference:** V14.3.1 (Authenticated data is cleared from client storage).
- **CI Check:** Integration tests should simulate logout and verify that client-side storage is empty of sensitive data.

#### RULE: Event Bus Contracts (MUST)

- **Statement:** Any `subscribe()` method on an event bus **MUST** return an `unsubscribe()` function. Components **MUST** call this function in their `destroy()` method.
- **Rationale:** Failure to unsubscribe from a global or shared event bus is a common source of memory leaks and logic errors, where "dead" components continue to react to events.
- **Good:**
  ```javascript
  class MyComponent {
    #unsubscribe;
    constructor() {
      this.#unsubscribe = eventBus.subscribe("user:logout", () =>
        this.cleanup(),
      );
    }
    destroy() {
      if (this.#unsubscribe) {
        this.#unsubscribe();
      }
    }
  }
  ```
- **Tests:** Contract test for the event bus to ensure `subscribe` returns a function. Component tests must verify `unsubscribe` is called on destruction.
- **CI Check:** Enforce that components with `eventBus.subscribe` also have a `destroy` method that calls the returned function.

#### RULE: Global API Exposure (SHOULD NOT)

- **Statement:** Do not pollute the `window` object. If a global handle is absolutely necessary (e.g., for cleanup), use `Symbol.for('my-app.feature')` as the key.
- **Rationale:** Attaching properties to `window` creates a high risk of collision with third-party scripts or other parts of the application, leading to unpredictable bugs. Symbols provide a non-colliding namespace.
- **Good:**
  ```javascript
  const CLEANUP_KEY = Symbol.for("my-app.citationCleanup");
  Object.defineProperty(window, CLEANUP_KEY, {
    value: cleanupFunction,
    configurable: true, // Allow deletion
  });
  ```
- **Bad:**
  ```javascript
  // HIGH COLLISION RISK
  window.__citationCleanup = cleanupFunction;
  ```
- **Tests:** Ensure that global handles are correctly set and removed, and do not persist across test suites.
- **CI Check:** ESLint rule (`no-restricted-globals`) to ban direct assignment to `window`.

#### RULE: Client-Side Rate Limiting (SHOULD)

- **Statement:** Event handlers that trigger frequent or resource-intensive operations (especially network requests) **SHOULD** be rate-limited using `debounce` or `throttle`.
- **Rationale:** High-frequency events like `keyup`, `resize`, or `scroll` can trigger hundreds of handler executions per second. If these handlers perform expensive work like making API calls, it can degrade the user experience and place unnecessary load on backend services, potentially leading to a client-side Denial of Service (DoS). Throttling or debouncing ensures the handler logic is executed in a more controlled and performant manner. (Из Главы 7, "Throttling, debouncing, and batching asynchronous operations").
- **Good (Debounce for "search-as-you-type"):**

  ```javascript
  // Debounce waits for a pause in user input before firing.
  const debouncedSearch = debounce(async (query) => {
    const results = await fetch(`/api/search?q=${query}`);
    // update UI...
  }, 300); // 300ms delay

  searchInput.addEventListener("keyup", (e) => {
    debouncedSearch(e.target.value);
  });
  ```

- **Good (Throttle for scroll tracking):**

  ```javascript
  // Throttle ensures the function runs at most once per interval.
  const throttledScrollHandler = throttle(() => {
    // track scroll position...
  }, 100); // Max once every 100ms

  window.addEventListener("scroll", throttledScrollHandler, { passive: true });
  ```

- **CI Check:** While hard to enforce statically, a linter rule can flag event listeners for `keyup`, `scroll`, and `resize` that directly contain a `fetch()` call and recommend wrapping it in a rate-limiting function.

#### RULE: Idempotent Initialization (MUST)

- **Statement:** Initialization logic, especially for global listeners, **MUST** be idempotent to prevent duplicate handlers and memory leaks.
- **Rationale:** In modern frontend environments (HMR, SPAs, island hydration), a script can be executed multiple times. Non-idempotent initialization will attach duplicate listeners, leading to performance degradation and bugs.
- **Good:**
  ```javascript
  const INIT_FLAG = Symbol.for("my-app.isInitialized");
  if (!document[INIT_FLAG]) {
    document.addEventListener("astro:page-load", safeInitialize);
    Object.defineProperty(document, INIT_FLAG, {
      value: true,
      configurable: true,
    });
  }
  ```
- **Tests:** Run the initialization function multiple times in a test and assert that event listeners are only attached once.
- **CI Check:** This is a pattern that is best enforced through code review, though linters can encourage the use of module-scope flags.

#### RULE: Storage Key Policy (MUST)

- **Statement:** Only approved key patterns are allowed for `localStorage` and `sessionStorage`. All storage access **MUST** go through a helper that enforces these patterns.
- **Rationale:** Unstructured storage keys lead to collisions, difficulty in debugging, and no clear ownership. A policy prevents these issues.
- **Good:**
  ```javascript
  // Helper library
  const ALLOWED_PREFIXES = /^(ui-|settings-|cache-)/;
  function safeSetStorage(key, value) {
    if (!ALLOWED_PREFIXES.test(key)) {
      throw new Error(`Invalid storage key: ${key}`);
    }
    localStorage.setItem(key, JSON.stringify(value));
  }
  ```
- **Tests:** Fuzz the `safeSetStorage` helper with invalid keys and assert that it throws an error and does not write to storage.
- **CI Check:** Ban direct calls to `localStorage.setItem` and `sessionStorage.setItem`, forcing use of the helper.

#### RULE: Secure Token Storage (MUST NOT)

- **Statement:** Sensitive tokens, such as session JWTs or API keys, **MUST NOT** be stored in `localStorage`.
- **Rationale:** Data in `localStorage` persists across browser sessions and has no built-in expiration mechanism. Crucially, it is accessible via JavaScript, making it a prime target for exfiltration in a Cross-Site Scripting (XSS) attack. Storing session tokens here completely negates the value of `httpOnly` cookies.
- **Implementation:**
  - For short-lived sessions, tokens **SHOULD** be stored in memory within a JavaScript closure or module scope.
  - If persistence across page reloads (but not browser closing) is required, `sessionStorage` is a permissible but less-preferred alternative.
  - The most secure pattern for session management is using a secure, `httpOnly`, `SameSite=Strict` cookie managed by a BFF, which is not directly accessible to JavaScript.
- **CI Check:** An ESLint rule **MUST** be configured to ban `localStorage.setItem` for keys matching a pattern like `/token|secret|key/i`.

### C. Data & Logic

#### RULE: Secure and Component-Aware URI Handling (MUST)

- Statement: All dynamic data for URIs MUST use the appropriate component-aware helper from `src/utils/security-kit.ts`. Direct calls to `encodeURIComponent`, `decodeURIComponent`, `encodeURI`, or `decodeURI` are forbidden in application code.
- Rationale: Native functions fail to encode all reserved characters per RFC 3986 and are easy to misuse, causing security and interoperability bugs. The helpers enforce Secure by Default, Least Privilege, and Predictable Error Handling.
- Implementation:
  - Path segments: `encodePathSegment()`
  - Query values (space -> %20): `encodeQueryValue()`
  - Form values (`application/x-www-form-urlencoded`, space -> `+`): `encodeFormValue()`
  - Host labels (IDNA): `encodeHostLabel()`
  - Decoding (predictable result types): `strictDecodeURIComponent()` or `strictDecodeURIComponentOrThrow()`
- Best Practice: Construct complex URLs with the `URL` and `URLSearchParams` APIs, using the helpers for value injection.
- CI Check: ESLint bans native URI encode/decode usage via `no-restricted-globals` at ERROR level. Reviewed exceptions MUST be documented in code with justification and limited to the central wrapper (`src/utils/security-kit.ts`).

#### RULE: Global RegExp Safety (MUST)

- **Statement:** Do not use `RegExp.prototype.test()` with the `g` (global) or `y` (sticky) flags on a single, reusable RegExp instance.
- **Rationale:** The `.test()` method is stateful when used with `g` or `y` flags. The `lastIndex` property is updated after each match, leading to inconsistent and unpredictable results (`true`, `false`, `true`, `false`...) on repeated calls with the same input.
- **Good (No `g` flag):**
  ```javascript
  const URL_REGEX = /url\(/i; // No 'g' flag
  if (URL_REGEX.test(someString)) {
    /* ... */
  }
  if (URL_REGEX.test(anotherString)) {
    /* ... */
  }
  ```
- **Good (Reset `lastIndex`):**
  ```javascript
  const URL_REGEX_G = /url\(/gi; // 'g' flag is required for other reasons
  URL_REGEX_G.lastIndex = 0; // Reset state before testing
  if (URL_REGEX_G.test(someString)) {
    /* ... */
  }
  ```
- **Bad:**
  ```javascript
  const URL_REGEX_G = /url\(/gi;
  // First call might be true, second might be false on the same input.
  if (URL_REGEX_G.test(someString)) {
    /* ... */
  }
  if (URL_REGEX_G.test(someString)) {
    /* This might fail! */
  }
  ```
- **Tests:** Unit test that calls the validation function repeatedly in a loop with the same input and asserts that the output is always deterministic.
- **CI Check:** Custom ESLint rule to detect the use of `.test()` on a RegExp literal or variable that has the `/g` or `/y` flag.

#### **RULE: Client-Side API Response Validation (MUST)**

- **Statement:** All data received from external APIs, even trusted first-party APIs, **MUST** be validated against an expected schema before being used by the application.
- **Rationale:** An API could be compromised, return malformed data, or change its contract unexpectedly. Blindly trusting API responses can lead to unhandled exceptions, state corruption, and security vulnerabilities if the data is later passed to a DOM sink or other sensitive function. This extends our Zero Trust philosophy to our own infrastructure. (Inspired by Chapter 5.4).
- **Good (Using a schema validator like Zod or Yup):**

  ```javascript
  import { z } from "zod";

  const userSchema = z.object({
    id: z.string().uuid(),
    name: z.string(),
    isAdmin: z.boolean().default(false),
  });

  async function fetchUser(userId) {
    const response = await fetch(`/api/users/${userId}`);
    const rawData = await response.json();
    // Throws an error if data doesn't match the schema
    const validatedUser = userSchema.parse(rawData);
    return validatedUser;
  }
  ```

- **Bad:**
  ```javascript
  // VULNERABLE: Blindly trusts the API response structure.
  async function fetchUser(userId) {
    const response = await fetch(`/api/users/${userId}`);
    const user = await response.json(); // No validation
    // user.name could be undefined, user.isAdmin could be a malicious string.
    return user;
  }
  ```
- **CI Check:** A linter rule can encourage wrapping `fetch` responses in validation functions.

#### RULE: Cryptographic Integrity (MUST)

- **Statement:** All randomness **MUST** be generated via the Web Crypto API (`crypto.getRandomValues`). `Math.random()` is forbidden for any security-sensitive context.
- **Rationale:** `Math.random()` is a pseudo-random number generator (PRNG) that is not cryptographically secure and can be predicted, making it unsuitable for generating nonces, keys, or unique IDs.
- **Good:**
  ```javascript
  // From a centralized, tested security utility
  function getSecureRandomBytes(len) {
    const array = new Uint8Array(len);
    window.crypto.getRandomValues(array);
    return array;
  }
  ```
- **Tests:** Statistical verification (e.g., Chi-Squared test) on the output of random number generators to ensure uniform distribution.
- **CI Check:** ESLint rule (`no-restricted-properties`) to ban `Math.random`.

#### RULE: Centralized Cryptography & Mutation Controls (MUST)

- **Statement:** All cryptographic operations and randomness APIs in application code **MUST** be consumed exclusively via `src/utils/security-kit.ts`. Direct access to `globalThis.crypto`, `node:crypto.webcrypto`, or ad-hoc random generation from application modules is forbidden. Runtime mutation of the crypto provider is prohibited in production unless explicitly allowed for a narrowly scoped, auditable scenario. The security kit **MUST** be sealed at startup to prevent configuration tampering.
- **Rationale:** Centralizing crypto avoids footguns, enforces uniform hardening (DoS guards, unbiased sampling, precision fallbacks), and enables verifiable testing. Sealing configuration and guarding test-time injection prevent late-binding supply-chain attacks and environment drift.
- **Implementation (Approved APIs):**

  ```javascript
  import {
    getSecureRandom, // Secure float [0,1)
    getSecureRandomAsync,
    getSecureRandomInt, // Uniform integer in [min, max]
    generateSecureId, // Hex ID, bounded length
    generateSecureUUID, // RFC 4122 v4
    setCrypto, // Test-only injection
    sealSecurityKit, // Call once during startup
  } from "@utils/security-kit.ts";

  // Startup hardening
  sealSecurityKit();

  // Usage
  const id = await generateSecureId(32);
  const uuid = await generateSecureUUID();
  const n = await getSecureRandomInt(10, 99);
  const r = getSecureRandom();
  ```

- **Forbidden:**
  ```javascript
  // ❌ Direct crypto access (bypasses uniform hardening)
  crypto.getRandomValues(buf);
  (await import("node:crypto")).webcrypto.getRandomValues(buf);
  ```
- **Test-Time Injection Controls:**
- Use `setCrypto(stub)` only in tests and always clear with `setCrypto(null)` afterwards.
- In production, `setCrypto(stub)` **MUST** throw unless `allowInProduction: true` is passed for an exceptional, short-lived scenario with explicit owner approval and audit trail.
- `sealSecurityKit()` **MUST** be called at startup. After sealing, any attempt to mutate configuration (`setCrypto`, environment overrides) **MUST** throw.
- **Precision & DoS Guards:**
- `getSecureRandom()`/`getSecureRandomAsync()` SHOULD prefer the high-precision `BigUint64` path when supported, with a safe 32-bit fallback and dev-only warning.
- APIs MUST enforce strict input validation and circuit breakers (e.g., unbiased-rejection iteration limits, bounded buffer sizes) to mitigate DoS.
- **CI Check:**
- ESLint: Ban `Math.random` (error) and discourage direct `crypto` access outside `security-kit.ts`.
- Tests: Include sealing behavior, production-guard enforcement for `setCrypto`, BigUint64 fallback, and unbiased sampling assertions.

- **Minimum Security Strength (MUST):** All cryptographic primitives utilized by the application **MUST** provide a minimum of 128-bits of security, based on the algorithm, key size, and configuration (e.g., a 256-bit ECC key or a 3072-bit RSA key for 128 bits of security).
  - **ASVS Reference:** V11.2.3 (All cryptographic primitives utilize a minimum of 128-bits of security).
- **Nonces, IVs, and Single-Use Numbers (MUST):** Nonces, initialization vectors (IVs), and other single-use numbers **MUST NOT** be used for more than one encryption key and data-element pair. The method of generation **MUST** be appropriate for the algorithm being used.
  - **ASVS Reference:** V11.3.4 (Nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair).
- **Encrypt-then-MAC Mode (MUST):** Any combination of an encryption algorithm and a Message Authentication Code (MAC) algorithm **MUST** operate in encrypt-then-MAC mode.
  - **ASVS Reference:** V11.3.5 (Any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode).
- **Hash Collision Resistance (MUST):** Hash functions used in digital signatures, as part of data authentication or data integrity, **MUST** be collision-resistant and have appropriate bit-lengths. If collision resistance is required, the output length **MUST** be at least 256 bits. If only resistance to second pre-image attacks is required, the output length **MUST** be at least 128 bits.
  - **ASVS Reference:** V11.4.3 (Hash functions used in digital signatures are collision resistant and have appropriate bit-lengths).
- **Key Derivation Functions with Stretching (MUST):** The application **MUST** use approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use **MUST** balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key.
  - **ASVS Reference:** V11.4.4 (Application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords).
- **Random Number Generation under Demand (MUST):** The random number generation mechanism in use **MUST** be designed to work securely, even under heavy demand.
  - **ASVS Reference:** V11.5.2 (Random number generation mechanism in use is designed to work securely, even under heavy demand).
- **Secure Key Generation Algorithms (MUST):** Only approved cryptographic algorithms and modes of operation **MUST** be used for key generation and seeding, and digital signature generation and verification. Key generation algorithms **MUST NOT** generate insecure keys vulnerable to known attacks (e.g., RSA keys vulnerable to Fermat factorization).
  - **ASVS Reference:** V11.6.1 (Only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification).
- **Secure Key Exchange Mechanisms (MUST):** Approved cryptographic algorithms **MUST** be used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This prevents attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks.
  - **ASVS Reference:** V11.6.2 (Approved cryptographic algorithms are used for key exchange with secure parameters).

#### RULE: Open Redirect Prevention (MUST)

- **Statement:** Any client-side logic that redirects the user to a new URL **MUST NOT** use unvalidated user-supplied input to determine the destination. All redirect destinations **MUST** be validated against a strict allowlist.
- **Rationale:** As detailed in the OWASP Unvalidated Redirects and Forwards Cheat Sheet, an open redirect vulnerability allows an attacker to craft a legitimate-looking URL that redirects users to a malicious phishing site. Because the initial domain is trusted, users are more likely to fall for the scam.
- **Implementation:**
  1.  Never use data from sources like `URLSearchParams` or `window.location.hash` directly as a redirect target.
  2.  If dynamic redirects are required, the destination **MUST** be validated to ensure it is either a relative path within the same application or an absolute URL belonging to an explicitly approved, allowlisted domain.
- **Good (Allowlist Validation):**

  ```javascript
  const ALLOWED_REDIRECT_HOSTS = new Set(["example.com", "help.example.com"]);

  function safeRedirect(url) {
    try {
      const destination = new URL(url, window.location.origin);
      // Case 1: Is it a relative path on the same origin?
      if (destination.origin === window.location.origin) {
        window.location.href = destination.href;
        return;
      }
      // Case 2: Is it an absolute URL to an allowed host?
      if (ALLOWED_REDIRECT_HOSTS.has(destination.hostname)) {
        window.location.href = destination.href;
        return;
      }
    } catch (e) {
      // Invalid URL, fall through to error.
    }
    console.error(`[Security]: Blocked unsafe redirect to ${url}`);
    // Redirect to a safe, default page instead.
    window.location.href = "/";
  }

  const redirectTarget = new URLSearchParams(window.location.search).get(
    "next",
  );
  if (redirectTarget) {
    safeRedirect(redirectTarget);
  }
  ```

- **Bad:**
  ```javascript
  // VULNERABLE: Attacker can set ?next=//malicious-site.com
  const redirectTarget = new URLSearchParams(window.location.search).get(
    "next",
  );
  if (redirectTarget) {
    window.location.href = redirectTarget;
  }
  ```
- **CI Check:** A linter rule **SHOULD** be configured to flag direct assignments to `window.location.href` or `window.location.assign()` from variable sources and recommend using the `safeRedirect` helper.

#### RULE: Global Development Safeguards (MUST)

- **Statement:** The development environment MUST be actively hardened against common developer errors, such as the accidental logging of sensitive data.
- **Rationale:** Developers can make mistakes, such as using a raw `console.log()` on an object containing secrets. To adhere to the "Fail Loudly, Fail Safely" and "Defense in Depth" principles, we must add a safety net that catches these errors by default. This makes the secure path the easiest path.
- **Implementation:**
  1.  In development mode only, the global `console.error` and `console.warn` methods **MUST** be wrapped ("monkey-patched").
  2.  This wrapper **MUST** automatically pass all arguments through the centralized redaction utility (`_redact` from `security-kit.ts`) before passing them to the original console method.
  3.  The wrapper **MUST** include a `try/catch` block; if redaction fails for any reason, it should log the original arguments to ensure no information is lost during a critical failure.
- **Good (In an initialization script):**
  ```javascript
  // In security-kit.ts or a similar startup module
  function applyGlobalDevLoggingGuards() {
    if (isDevelopment()) {
      // MUST only run in development
      const originalError = console.error;
      console.error = (...args) => {
        try {
          const redactedArgs = args.map((arg) => _redact(arg));
          originalError.apply(console, redactedArgs);
        } catch {
          originalError.apply(console, args); // Fallback on failure
        }
      };
      // ... also wrap console.warn
    }
  }
  applyGlobalDevLoggingGuards();
  ```
- **Tests:** Integration tests must verify that when running in a development environment, a call to `console.error` with a sensitive object results in a redacted object being logged to the console.
- **CI Check:** A CI check is not practical for this rule. Enforcement relies on code review to ensure the guard-application function is called during application startup.

#### RULE: Side-Channel Resistance for Secrets (SHOULD)

- **Statement:** Operations involving secret data (e.g., encoding, comparison) SHOULD use constant-time algorithms to prevent timing-based side-channel attacks.
- **Rationale:** Standard algorithms can have execution times that vary based on the data being processed. An attacker could measure these minute timing differences to infer information about the secret itself. Constant-time operations take the same amount of time regardless of the input, mitigating this risk. This adds a deeper layer to our "Cryptographic Integrity" rule.
- **Good (Constant-Time Comparison):**

  ```javascript
  // Using the approved helper from security-kit.ts
  import { secureCompare } from "@utils/security-kit";

  // This function's execution time depends only on string length, not content.
  if (secureCompare(userInputToken, storedToken)) {
    // ... proceed
  }
  ```

- **Good (Constant-Time Encoding):**
  ```javascript
  // A helper designed to encode secret data without data-dependent branches.
  function bytesToHexConstantTime(buffer) {
    let hex = "";
    for (let i = 0; i < buffer.length; i++) {
      // No "if" statements based on the byte's value.
      hex += PRECOMPUTED_HEX_TABLE[buffer[i]];
    }
    return hex;
  }
  ```
- **Bad (Variable-Time Comparison):**
  ```javascript
  // VULNERABLE: The '===' operator short-circuits, exiting early on the
  // first non-matching character. This leaks timing information.
  if (userInputToken === storedToken) {
    // ...
  }
  ```
- **Tests:** Unit tests for constant-time helpers must verify they do not contain data-dependent branches. Performance benchmarks can help identify significant timing variations, but static analysis is the primary enforcement mechanism.
- **CI Check:** A static analysis tool or custom ESLint rule should flag the use of `===` for comparing variables with names like `token`, `secret`, or `key` and recommend `secureCompare`.

#### RULE: Software Bill of Materials (SBOM) Generation (MUST)

- **Statement:** A comprehensive SBOM **MUST** be generated and maintained for every build. This SBOM should list all packages (including sub-dependencies) used by the static site and its build process.
- **Rationale:** An SBOM enables quick impact analysis when new CVEs or policy issues arise in any dependency. It supplements vulnerability scanning by providing an auditable manifest of all components, improving transparency and enabling faster fixes.
- **Implementation:**
  - Use a tool like CycloneDX or SPDX to produce an SBOM (e.g., `sbom.json` or `sbom.xml`) as part of the build pipeline.
  - Include all production and development dependencies in the SBOM.
  - Store or publish the SBOM alongside the build artifacts (or commit it to the repo) so it can be reviewed and traced.
  - **CI Check:** Fail the build if no SBOM is generated or if it is outdated relative to the `package-lock.json`/`yarn.lock`.

#### RULE: Dev Logging Redaction & Telemetry Hygiene (SHOULD)

- **Statement:** Developer-facing logs and diagnostics **MUST NOT** include secrets or high-entropy values. In development, logging **SHOULD** use a centralized, redaction-enforcing utility (`secureDevLog`) that dispatches sanitized events and performs deep redaction.
- **Rationale:** Logs are frequently copied to external systems and can outlive their original context. Redaction by default reduces risk of secret leakage and fingerprinting.
- **Implementation:**

  ```javascript
  import { secureDevLog } from "@utils/security-kit.ts";

  secureDevLog("info", "component", "initialized", {
    harmless: 123,
    password: "will be redacted",
    nested: { apiKey: "will be redacted" },
  });
  // In dev, a sanitized CustomEvent('secure-dev-log') is dispatched.
  ```

- **Hardening Requirements:**
- Redaction engine MUST block `__proto__`, `constructor`, `prototype` keys and only allow safe key patterns to prevent prototype pollution.
- Use null‑prototype objects for constructed payloads and an allowlist for console methods (no dynamic property access like `console[level]`).
- In production, `secureDevLog` MUST be a no-op.
- **CI Check:** Security linters must flag unsafe sinks and dynamic property access; tests must include adversarial payloads (e.g., prototype pollution attempts) to verify redaction.

#### RULE: Ephemeral Secret Handling (MUST NOT)

- **Statement:** Secrets **MUST NOT** be persisted in client storage or long-lived memory. When a temporary symmetric key is required client-side, it **MUST** be generated via `createOneTimeCryptoKey` (non-extractable `CryptoKey`) and used with Web Crypto APIs.
- **Rationale:** Client code and memory are untrusted. Minimizing lifetime and exposure reduces exfiltration risk.
- **Implementation:**
  ```javascript
  import {
    createOneTimeCryptoKey,
    createAesGcmNonce,
    secureWipe,
    secureCompare,
  } from "@utils/security-kit.ts";
  ```

const key = await createOneTimeCryptoKey({ length: 256 }); // AES-GCM key
const iv = createAesGcmNonce(); // 12-byte IV for GCM
// ... use with SubtleCrypto ...

    // Timing-safe-ish comparisons for short secrets
    if (secureCompare(provided, expected)) {
      // proceed
    }
    ```

- **Forbidden:** Storing secrets in `localStorage`, `sessionStorage`, IndexedDB, URL params, or logging secrets (even in dev).
- **CI Check:** Linters ban direct storage APIs for secret-like keys; tests verify read-once semantics and wiping behavior.

#### RULE: Consistent Object Shapes (SHOULD)

- **Statement:** When creating multiple objects that share the same logical structure, you **SHOULD** initialize their properties in a consistent order, preferably using constructors or factory functions.
- **Rationale:** Adherence to this rule directly supports our core principle of **"Performance is a Security Feature" (1.6)**. The V8 JavaScript engine heavily optimizes property access for objects with a stable structure (a consistent "Hidden Class" or "Map"). Initializing properties in a non-deterministic order creates objects with different internal structures. This forces the JIT compiler into a slower, polymorphic or megamorphic state, degrading performance, especially in performance-sensitive code paths that process large numbers of objects. While often a micro-optimization, consistent object shapes contribute to a more predictable and performant system.
- **Good (Consistent order via constructor or literal):**

  ```javascript
  // GOOD: The property order is always the same.
  class User {
    constructor(name, age) {
      this.name = name;
      this.age = age;
    }
  }
  const user1 = new User("Alice", 30);
  const user2 = new User("Bob", 32);

  // Also good for simple objects:
  const makeVector = (x, y) => ({ x, y });
  ```

- **Bad (Inconsistent order):**
  ````javascript
  // BAD: The shape of the returned object depends on runtime conditions.
  function createObjectFromData(data) {
    const obj = {};
    if (data.hasNameFirst) {
      obj.name = data.name;
      obj.value = data.value;
    } else {
      obj.value = data.value;
      obj.name = data.name;
    }
    return obj; // This function produces objects with two different shapes.
  }
  ```*   **Tests:** Direct verification via unit tests is impractical. This rule should be validated through performance benchmarks on critical application paths and enforced during code review.
  ````
- **CI Check:** A static linter rule for this is often too noisy to be practical. Enforcement relies on developer training (per section 5.3) and vigilant code reviews (per section 5.1), especially for code within loops or high-frequency functions.

### RULE: Data Classification and Protection Documentation (MUST)

- **Statement:** All sensitive data created and processed by the application **MUST** be identified and classified into protection levels. This includes data that is only encoded (e.g., Base64) and therefore easily decoded. Protection levels **MUST** take into account any relevant data protection and privacy regulations and standards. For each protection level, a documented set of protection requirements **MUST** be defined, including general encryption, integrity verification, retention, logging, access controls, database-level encryption, and privacy-enhancing technologies.
- **Rationale:** A clear understanding and classification of sensitive data is a prerequisite for implementing effective protection controls. This ensures that data is handled according to its sensitivity and legal/regulatory requirements, aligning with the "Principle of Least Privilege" for data exposure.
- **ASVS Reference:** V14.1.1 (All sensitive data created and processed by the application has been identified and classified), V14.1.2 (All sensitive data protection levels have a documented set of protection requirements).
- **Implementation:** Create a `DATA_CLASSIFICATION.md` document detailing data types, their classification, and corresponding protection requirements.

### RULE: Sensitive Data in URLs (MUST NOT)

- **Statement:** Sensitive data **MUST NOT** be sent in the URL or query string of HTTP messages. It **MUST** only be sent in the HTTP message body or header fields.
- **Rationale:** URLs are often logged by web servers, proxies, and browsers, and can be exposed in browser history, bookmarks, and referrer headers. Sending sensitive data in the URL significantly increases the risk of information leakage.
- **ASVS Reference:** V14.2.1 (Sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information).

### RULE: Sensitive Data Caching Prevention (MUST)

- **Statement:** The application **MUST** prevent sensitive data from being cached in server components (e.g., load balancers, application caches) or **MUST** ensure that such data is securely purged after use. Caching mechanisms **MUST** be configured to only cache responses with expected content types and **MUST NOT** cache sensitive, dynamic content to prevent Web Cache Deception attacks.
- **Rationale:** Caching sensitive data can lead to its unintended exposure if the cache is compromised or misconfigured. Preventing caching at various layers is a critical defense-in-depth measure.
- **ASVS Reference:** V14.2.2 (Application prevents sensitive data from being cached in server components), V14.2.5 (Caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content).

### RULE: Sensitive Data Transmission to Untrusted Parties (MUST NOT)

- **Statement:** Defined sensitive data **MUST NOT** be sent to untrusted third parties (e.g., user trackers, analytics services not explicitly approved for sensitive data handling) to prevent unwanted collection of data outside of the application's control.
- **Rationale:** This reinforces the "Privacy-Preserving Telemetry" principle and ensures that sensitive user data is not inadvertently shared with entities that do not have a legitimate, documented need for it, or are not subject to the same security and privacy controls.
- **ASVS Reference:** V14.2.3 (Sensitive data is not sent to untrusted parties).

### RULE: Data Retention Policy (MUST)

- **Statement:** Sensitive information **MUST** be subject to a data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires.
- **Rationale:** Retaining sensitive data longer than necessary increases the risk of exposure in the event of a breach. Implementing a clear data retention policy minimizes this risk and supports compliance with privacy regulations.
- **ASVS Reference:** V14.2.7 (Sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically).

### RULE: Metadata Stripping from User-Submitted Files (MUST)

- **Statement:** Sensitive information **MUST** be removed from the metadata of user-submitted files unless storage of such metadata is explicitly consented to by the user.
- **Rationale:** File metadata (e.g., EXIF data in images, author information in documents) can contain PII or other sensitive details that users may not intend to share. Stripping this metadata by default protects user privacy.
- **ASVS Reference:** V14.2.8 (Sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user).

### D. Code Correctness & Hygiene

This subsection codifies rules that enforce general code quality and prevent common JavaScript errors. Adherence to these rules reduces the overall bug surface, which in turn enhances security by creating a more predictable and robust codebase.

#### RULE: Exclusive Use of TypeScript for Application Logic (MUST)

- **Statement:** All new and existing application logic (source code within `src/` directories, excluding configuration files, build scripts, and test files) **MUST** be written exclusively in TypeScript (`.ts` or `.tsx` extensions). Direct use of JavaScript (`.js` or `.jsx`) or Module JavaScript (`.mjs`, `.cjs`) for application logic is strictly forbidden.
- **Rationale:** This mandate reinforces the "Secure by Default" and "Code Correctness & Hygiene" principles. TypeScript's static type checking significantly reduces runtime errors, catches entire classes of bugs (including potential security vulnerabilities arising from type mismatches or unexpected data shapes), and improves code maintainability and readability. Adopting a single, strict language standard for application logic streamlines development, simplifies tooling, and enhances the overall robustness and security posture of the project.
- **Implementation:**
  - All new application files **MUST** use the `.ts` or `.tsx` extension.
  - Existing `.js` or `.jsx` application files **MUST** be progressively migrated to `.ts` or `.tsx`.
  - Configuration files (e.g., `astro.config.mjs`, `eslint.config.js`), build scripts (e.g., `scripts/*.mjs`), and test files (e.g., `*.test.js`, `*.spec.js`) are exempt from this rule, provided they are explicitly excluded from the main TypeScript compilation and linting scope.
- **Forbidden:**
  ```javascript
  // ❌ Forbidden for application logic within `src/`
  // src/components/MyComponent.js
  // src/utils/helper.jsx
  ```
- **CI Check:**
  - A custom ESLint rule (e.g., `@yourorg/no-js-files`) **MUST** be configured to fail the build if any `.js` or `.jsx` files (excluding those in explicitly allowed `exclude` paths like `scripts/` or `tests/`) are found within the `src/` directory.
  - The `tsconfig.json` `include` array **MUST** be updated to remove `src/**/*.js` and `src/**/*.jsx` to align with this policy.

#### RULE: Strict Equality (MUST)

- **Statement:** The strict equality (`===`) and inequality (`!==`) operators **MUST** be used for all comparisons. The loose equality (`==`) and inequality (`!=`) operators are forbidden.
- **Rationale:** The loose equality operator (`==`) performs automatic type coercion before comparison, leading to unpredictable results that can be exploited to bypass security checks (e.g., `0 == ""` evaluates to `true`). Strict equality compares both value and type, ensuring comparisons are explicit and safe.
- **Good:**
  ```javascript
  if (userInput === 0) {
    /* ... */
  }
  if (typeof value !== "undefined") {
    /* ... */
  }
  ```
- **Bad:**
  ```javascript
  // VULNERABLE: A user input of "" or "0" could bypass this check.
  if (userInput == 0) {
    /* ... */
  }
  ```
- **CI Check:** An ESLint rule (`eqeqeq`) **MUST** be configured to enforce this at the error level.

#### RULE: Arbitrary Code Execution Prohibition (MUST NOT)

- **Statement:** The use of `eval()` and the `Function` constructor (`new Function(...)`) is strictly forbidden.
- **Rationale:** These functions execute arbitrary strings as code, creating a massive security vulnerability. They are the primary vector for injection attacks, allowing an attacker to run malicious code within the context of the application. There are no legitimate use cases for these functions in this project.
- **Forbidden:**

  ```javascript
  // VULNERABLE: Executes whatever is in the 'data' variable.
  const result = eval(data);

  const sum = new Function("a", "b", "return a + b");
  ```

- **CI Check:** ESLint rules (`no-eval`, `no-new-func`) **MUST** be enabled to fail the build if these are used.

#### RULE: Scope & Variable Declaration Hygiene (MUST)

- **Statement:** Global variables are forbidden. All variables **MUST** be declared with `let` or `const` within the narrowest possible scope. Variables **SHOULD** be initialized at the time of declaration.
- **Rationale:** Implicitly creating global variables by omitting a declaration keyword (`let`/`const`/`var`) pollutes the global scope, risking collisions with other scripts and creating unpredictable behavior. Adhering to strict scoping aligns with the "Principle of Least Privilege" and makes the codebase easier to reason about and secure.
- **Good:**
  ```javascript
  function processItems(items) {
    // 'l' and 'i' are scoped to the function and loop, respectively.
    const l = items.length;
    for (let i = 0; i < l; i++) {
      // ...
    }
  }
  ```
- **Bad:**
  ```javascript
  function processItems(items) {
    // VULNERABLE: 'i' becomes a global variable if not in strict mode.
    for (i = 0; i < items.length; i++) {
      // ...
    }
  }
  ```
- **CI Check:** The entire codebase **MUST** run in strict mode (`'use strict';`). An ESLint rule (`no-undef`) **MUST** be enabled to catch the use of undeclared variables.

#### RULE: Robust Control Flow (SHOULD)

- **Statement:** Functions **SHOULD** use default parameters to handle missing arguments. `switch` statements **SHOULD** include a `default` case to handle unexpected values.
- **Rationale:** This follows the "Fail Loudly, Fail Safely" principle. Explicitly handling unexpected or missing inputs prevents `undefined` values from propagating through the system, which can cause runtime errors and unpredictable states.
- **Good:**

  ```javascript
  function configure(options = {}) {
    const timeout = options.timeout ?? 500;
    // ...
  }

  switch (value) {
    case "a":
      // ...
      break;
    default:
      console.error(`Unexpected switch value: ${value}`);
    // Handle the unknown case safely.
  }
  ```

- **Bad:**
  ```javascript
  function configure(options) {
    // Throws TypeError if options is undefined.
    const timeout = options.timeout;
  }
  ```
- **CI Check:** ESLint rules (`default-param-last`, `default-case`) **SHOULD** be enabled to encourage these patterns.

#### RULE: Secure Error Boundaries (MUST)

- **Statement:** All components **MUST** be wrapped in error boundaries that redact sensitive data before logging.
- **Implementation:** Use Astro's `<ErrorBoundary>` or equivalent; integrate with `secureDevLog`.

#### RULE: Obfuscation of Feature-Revealing CSS Selectors (SHOULD)

- **Statement:** CSS class names that directly reveal sensitive application features (e.g., `.isAdminPanel`, `.deleteUserButton`) **SHOULD** be avoided in production builds.
- **Rationale:** As noted in the OWASP Securing Cascading Style Sheets Cheat Sheet, descriptive class names in a global CSS file can provide an unauthenticated attacker with a roadmap of the application's functionality and privilege levels. This constitutes an information disclosure vulnerability that aids in reconnaissance.
- **Implementation:**
  - Utilize modern frontend tooling that automatically generates non-descriptive, unique class names.
  - **Good (CSS Modules):** In frameworks that support CSS Modules, class names are automatically scoped and hashed (e.g., `app_component__addUser___1a2b3c`).
  - **Good (Utility-First CSS):** Using a framework like TailwindCSS naturally avoids semantic class names in favor of utility classes (e.g., `bg-red-500 font-bold`), which reveal nothing about functionality.
  - **Bad (Global Semantic CSS):**
    ```css
    /* VULNERABLE: Reveals application features to anyone who can download the CSS file. */
    .admin-dashboard {
      /* ... */
    }
    .export-financial-report-button {
      /* ... */
    }
    ```
- **CI Check:** While difficult to enforce automatically, code reviews should favor utility-first approaches or tooling that provides automatic obfuscation.

---

## Part IV: Verification & Enforcement

### 4.1. Testing Requirements

A feature is not "done" until it is accompanied by tests that prove its security and resilience.

- **Unit Tests:** Modules touching security primitives must have >= 90% test coverage.
- **Adversarial & Fuzz Tests:** Functions parsing untrusted input (DOM data, API responses, user input) **MUST** be fuzzed with invalid, malicious, and unexpected data (e.g., `null`, `undefined`, prototype pollution payloads, non-string types).
- **Integration Tests:** Test the interaction between components, especially regarding lifecycle (init/destroy) and event handling, to catch memory leaks and state corruption.
- **Security Kit Coverage:** Tests MUST validate:
- Sealing behavior (`sealSecurityKit`) blocks runtime mutation after startup.
- Production guard in `setCrypto` throws unless `allowInProduction: true` is explicitly provided.
- High-precision randomness path with safe BigUint64 fallback and unbiased integer sampling with circuit breaker protection.
- Dev logging redaction resists prototype pollution and removes secret-like keys.

### 4.2. CI/CD Security Gates

The deployment pipeline **MUST** include these steps. A failure in any step **MUST** block deployment.

- **Policy-as-Code:** Key rules (allowed storage prefixes, selector patterns) should be stored in a machine-readable format (YAML/JSON) and used by CI jobs for validation.
- **Static Analysis (SAST):** Run ESLint with security-focused plugins and our custom rules derived from this constitution.
- **Dependency Scanning (SCA):** Run `npm audit --audit-level=high` and a third-party SCA tool. High/Critical vulnerabilities must be triaged within a defined SLA.
- **Test Execution:** Run the full suite of unit, integration, and adversarial tests.
- **Static Output Sanitization (post-build):** Run `npm run verify:sanitize` after the static build (or `npm run build:secure:verify:sanitize` to include all verifications). Any finding MUST fail the pipeline.
- **Ephemeral and Isolated Build Environments (MUST):** All production builds **MUST** be executed in a clean, ephemeral, and isolated environment (e.g., a fresh Docker container or VM). The build environment **MUST** be destroyed immediately after the build completes.
- **Rationale:** This prevents build cache poisoning and other attacks where a compromised build environment could inject malicious code into a legitimate artifact. It ensures a reproducible and trusted build process, a key principle from the OWASP Software Supply Chain Security Cheat Sheet.
- **E2E Security Scans:** Run automated penetration tests (e.g., OWASP ZAP baseline scan) on deployed previews to detect issues like missing headers, open redirects, or XSS in rendered pages.

### 4.3. Example CI Job

```yaml
jobs:
  security-and-test:
    name: Security Scan & Tests
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Install Dependencies
        run: npm ci

      - name: Linting & Static Analysis
        run: npm run lint:security # Runs ESLint with security rules

      - name: Dependency Vulnerability Scan
        run: npm audit --audit-level=high

      - name: Comprehensive Test Suite
        run: npm test # Includes unit, integration, and adversarial tests

      # This step should execute after the build stage in your pipeline.
      - name: Static Output Sanitization (post-build)
        run: npm run verify:sanitize

      - name: Policy-as-Code Validation
        run: ./scripts/validate-policy.sh # Checks against policy YAML files
```

#### 4.4. Sanitizer Configuration Policy (MUST)

- **Statement:** All `DOMPurify` configurations used within the application **MUST** be defined as named exports in a single, centralized, version-controlled file (e.g., `src/security/sanitizer-policies.ts`). Creating anonymous, ad-hoc configuration objects at the point of use is strictly forbidden.
- **Rationale:** The security of the entire application can be compromised by a single misconfigured `DOMPurify` call. As documented, overly permissive options in `ADD_TAGS`, `ADD_ATTR`, or `ALLOWED_URI_REGEXP` can completely negate the sanitizer's protections. Centralizing all policies into one file ensures that:
  1.  Every configuration is explicit, named, and has a documented purpose.
  2.  Security reviews can focus on a single file to audit the application's entire sanitization surface.
  3.  Automated tooling (linters) can be used to ban direct `DOMPurify.sanitize(dirty, { ... })` calls outside of the policy file.
- **Implementation:**
  - A file like `src/security/sanitizer-policies.ts` will contain all approved configurations.
  - Application code **MUST** import and use a named policy:
    ```javascript
    import { SVG_ENABLED_POLICY_CONFIG } from "@security/sanitizer-policies";
    const clean = DOMPurify.sanitize(dirty, SVG_ENABLED_POLICY_CONFIG);
    ```
  - Any change to this policy file **MUST** require a security team review and sign-off.
- **CI Check:** An ESLint rule **MUST** be implemented to fail any build where `DOMPurify.sanitize` is called with an inline object literal as its second argument.

#### 4.5. Adversarial CSP & SW Fuzz Tests (MUST)

- **Statement:** Add automated adversarial tests that:
  - attempt to inject inline scripts/styles into built HTML and assert `npm run verify:sanitize` fails.
  - simulate a tampered `sw.js` and assert client-side verification rejects it.

- **Rationale:** Automated negative tests ensure rules are not only present but effective.

---

## Part V: Governance & Process

### 5.1. Ownership & Code Review

Every rule in this constitution has an owner. Every Pull Request **MUST** be reviewed by at least one other developer and pass the "Code Review Checklist" (see Appendix). Security-critical changes require an additional review from a security team member.

### 5.2. Dependency Management

We practice **Trust is Not Transitive**. Every new dependency must be vetted for maintenance, popularity, security history, and sub-dependencies. The `package-lock.json` file **MUST** be committed to the repository.

- All third-party components and their transitive dependencies **MUST** be sourced exclusively from pre-defined, trusted, and continually maintained repositories (e.g., internal registries, official npm registry). The build process **MUST** implement checks to prevent dependency confusion attacks by verifying the origin of fetched packages.
- **ASVS Reference:** V15.2.4 (Third-party components and all of their transitive dependencies are included from the expected repository, and that there is no risk of a dependency confusion attack).

#### 5.2.1. Build Provenance & Lockfile Signing (MUST)

- **Statement:** The build artifact **MUST** include verifiable provenance metadata (build tool version, commit hash, `csp-hashes` manifest) and the repository **SHOULD** sign the `package-lock` or publish signatures for important lockfile checkpoints.
- **Rationale:** Committing `package-lock.json` is good; adding provenance and signatures closes a gap vs. modern supply-chain attacks (reproducibility and chain-of-trust).&#x20;
- **Implementation:** Use a reproducible build container, attach a `build-provenance.json`, and store artifacts in a nonce-signed artifact repository or enable SLSA/in-toto pipelines where practical.

### 5.3. Training & Onboarding

All new developers must complete a 30-minute training session covering the Top 10 rules of this constitution.

### 5.4. Audits & Reviews

The Security Team will conduct quarterly audits to verify CI coverage, unresolved lint failures, policy exceptions, and overall adherence to this constitution.

### 5.5. Threat Modeling & Abuse Case Analysis (MUST)

- **Statement:** Before the implementation of any new, non-trivial feature, a lightweight threat modeling exercise **MUST** be conducted. This includes identifying potential abuse cases and documenting the feature's impact on the application's attack surface.
- **Rationale:** This codifies the "think like an attacker" mindset and aligns with our "Verifiable Security" principle. By proactively identifying how a feature could be misused (abuse cases), we can design more resilient security controls from the start. This process directly informs the creation of the adversarial tests required in section 4.1.
- **Implementation:**
  1.  For each new feature, developers **MUST** answer the following questions in the design document or pull request description:
      - **What can go wrong?** (e.g., A user could try to upload a malicious file, bypass a payment step, enumerate other users, etc.).
      - **How does this change the attack surface?** (e.g., Does it add a new API endpoint? A new third-party integration? A new data parser?).
      - **What are we doing about it?** (e.g., This is mitigated by Rule X.X, and we have added adversarial test Y to verify it).
  2.  The output of this analysis **MUST** be reviewed as part of the standard code review process (5.1).
  3.  The Security Team **SHOULD** conduct a formal Attack Surface Review annually or after major architectural changes, as per section 5.4.

---

## Part VI: Incident Response & Observability

### 6.1. Incident Response Playbook

A short playbook must be readily available, outlining the process:

1.  **Detection:** How an incident is identified (monitoring, user report).
2.  **Containment:** How to immediately stop the bleeding (e.g., disable a feature flag, roll back).
3.  **Eradication:** How to remove the root cause.
4.  **Recovery:** How to restore service safely.
5.  **Post-Mortem:** A blameless retrospective must be completed within 5 business days, with action items assigned.

The playbook must include an up-to-date contact list for on-call security and development owners.

### 6.2. Observability & Metrics (KPIs)

We **MUST** track, dashboard, and review the following KPIs:

- Number of security-linter failures per PR.
- Time-to-remediate for high-severity SCA alerts.
- Percentage of modules with adversarial tests.
- Number of active policy exceptions, including reason and expiry date.

### 6.3. Secure Logging & Telemetry Policy (MUST)

- **Statement:** All logging and telemetry mechanisms must be designed to prevent the leakage of sensitive information, adhering to the "Principle of Least Privilege" for data collection.
- **Rationale:** Logs are a frequent source of data leakage. A single log line containing a password, API key, or PII can turn a minor bug into a critical security incident. We must treat log data with the same security rigor as production data.

#### 6.3.1. Data Exclusion from Logs (MUST NOT)

- **Statement:** The following data types **MUST NOT** be written to any log, whether client-side or server-side:
  - Session identifiers, access tokens, or API keys.
  - Authentication credentials (passwords, password reset tokens).
  - Personally Identifiable Information (PII) unless explicitly required for a documented, security-approved business purpose.
  - Encryption keys or other cryptographic secrets.
  - Full HTTP request/response bodies containing sensitive data.
- **Implementation:**
  - Utilize a centralized logging utility that automatically redacts or filters objects based on key names (e.g., `password`, `token`, `ssn`).
  - All new data structures containing potentially sensitive information **MUST** be reviewed to ensure they are compatible with the redaction filter.

#### 6.3.2. Structured Logging (MUST)

- **Statement:** All logs **MUST** be generated in a structured, machine-readable format (e.g., JSON).
- **Rationale:** Structured logs, as defined in the Logging Vocabulary cheat sheet, are essential for effective automated monitoring, alerting, and incident analysis. They allow for precise querying and correlation of events across the entire system.
- **Implementation:**
  ```json
  {
    "datetime": "2025-01-01T01:01:01-0700",
    "appid": "your-app-name",
    "event": "AUTHN_login_fail:joebob1",
    "level": "WARN",
    "description": "User joebob1 login failed",
    "source_ip": "REDACTED_FOR_PRIVACY",
    "request_uri": "/api/v2/auth/"
  }
  ```

#### 6.3.3. Client-Side Error Reporting (MUST)

- **Statement:** When reporting client-side exceptions to a remote collector, the payload **MUST** be sanitized to remove sensitive information.
- **Rationale:** Raw exception messages and stack traces can inadvertently contain PII, tokens, or other secrets that were in memory at the time of the error.
- **Implementation:**
  - Before sending an error report, scrub the message, stack trace, and any attached metadata for patterns matching secrets or PII.
  - The error reporting mechanism **MUST** be subject to the same data exclusion rules as server-side logging.

#### 6.3.4. Generic Error Messages (MUST)

- **Statement:** When an unexpected error or security-sensitive error occurs, the application **MUST** return a generic message to the end-user. Detailed error information (stack traces, internal queries, secret keys, tokens, specific validation failures) **MUST NOT** be exposed in client-facing responses.
- **Rationale:** Exposing detailed error messages provides attackers with valuable reconnaissance, helping them understand the application's internal structure, technologies, and potential vulnerabilities. This aligns with the "Principle of Least Privilege" for information disclosure.
- **Implementation (Good):**
  ```javascript
  // In a serverless function or API handler
  try {
    // ... application logic ...
  } catch (error) {
    console.error("Internal server error:", error); // Log full error internally
    return new Response(
      JSON.stringify({
        message: "An unexpected error occurred. Please try again later.",
      }),
      { status: 500 },
    );
  }
  ```
- **Forbidden:** Directly returning `error.message`, `error.stack`, or database error messages to the client.
- **CI Check:** Automated E2E tests or security scans should trigger various error conditions (e.g., invalid input, internal server errors) and verify that client-facing responses contain only generic messages.

#### 6.3.5. Comprehensive Logging Inventory (MUST)

- **Statement:** A comprehensive inventory **MUST** be maintained, documenting the logging performed at each layer of the application's technology stack (client, BFF, database, CDN logs). This inventory **MUST** detail what events are being logged, their formats, where logs are stored, how they are used, how access to them is controlled, and for how long logs are retained.
- **Rationale:** A clear understanding of all logging across the system is essential for effective security monitoring, incident response, and compliance. Without it, critical events might be missed, or sensitive data might be inadvertently logged and exposed.
- **ASVS Reference:** V16.1.1 (Security Logging Documentation).

#### 6.3.6. Security Event Logging (MUST)

- **Statement:** All security-relevant events **MUST** be logged, including successful and unsuccessful authentication attempts, failed authorization attempts, attempts to bypass security controls (e.g., input validation, business logic, anti-automation), and unexpected security control failures (e.g., backend TLS failures). For ASVS L3, all authorization decisions, including sensitive data access (without logging the data itself), **MUST** be logged.
- **Rationale:** Capturing these events is critical for detecting suspicious behavior, supporting investigations, and fulfilling compliance obligations. This provides the necessary data for SIEMs and other monitoring tools.
- **ASVS Reference:** V16.3.1 (All authentication operations are logged), V16.3.2 (Failed authorization attempts are logged; L3: all authorization decisions), V16.3.3 (Application logs attempts to bypass security controls), V16.3.4 (Application logs unexpected errors and security control failures).

#### 6.3.7. Log Protection (MUST)

- **Statement:** All logs **MUST** be protected from unauthorized access, modification, and disclosure. Logging components **MUST** appropriately encode data to prevent log injection. Logs **MUST** be securely transmitted to a logically separate system for analysis, detection, alerting, and escalation to ensure they are not compromised if the application itself is breached.
- **Rationale:** Logs are valuable forensic artifacts. Their integrity and confidentiality are paramount for incident investigations and legal proceedings. Protecting logs from the application itself ensures that a breach of the application does not automatically compromise the audit trail.
- **ASVS Reference:** V16.4.1 (Logging components appropriately encode data to prevent log injection), V16.4.2 (Logs are protected from unauthorized access and cannot be modified), V16.4.3 (Logs are securely transmitted to a logically separate system).

#### 6.3.8. Graceful & Secure Failure (MUST)

- **Statement:** The application **MUST** fail gracefully and securely, preventing "fail-open" conditions where a transaction proceeds despite errors (e.g., processing a payment after validation logic fails). It **MUST** also continue to operate securely when external resource access fails (e.g., using circuit breakers or graceful degradation). A "last resort" error handler **MUST** be defined to catch all unhandled exceptions, ensuring error details are logged and preventing application process crashes.
- **Rationale:** Secure failure ensures that security controls are not bypassed due to unexpected errors and that the application remains available or degrades predictably. A last-resort handler is crucial for capturing critical error information and maintaining system stability.
- **ASVS Reference:** V16.5.2 (Application continues to operate securely when external resource access fails), V16.5.3 (Application fails gracefully and securely, preventing fail-open conditions), V16.5.4 (A “last resort” error handler is defined which will catch all unhandled exceptions).

---

## Appendix A: Operator's Quick Checklist

This checklist **MUST** be reviewed by the developer before submitting a Pull Request.

- [ ] **Security:** Does my code handle untrusted input? Have I used the approved helpers for DOM manipulation, storage, and selectors?
- [ ] **Lifecycle:** If my component creates listeners or subscriptions, is there a `destroy()` method that cleans them all up using `AbortController` or an `unsubscribe` function?
- [ ] **Performance:** Am I using performant APIs (`IntersectionObserver`, WAAPI)? Have I avoided blocking the main thread?
- [ ] **Accessibility:** Have I considered `prefers-reduced-motion`? Are all interactive elements keyboard-navigable and screen-reader friendly?
- [ ] **Testing:** Have I added tests for the happy path, error conditions, and adversarial inputs?
- [ ] **Policy:** Does my change comply with all `MUST` rules in the Security Constitution?

---

## Appendix B: Developer Tooling & Helpers

To make compliance easy, we provide a suite of tools.

- **`@yourorg/sec-utils`:** An internal npm package containing helpers like `safeQuerySelector`, `safeSetStorage`, `addEventListenerWithAbort`, and `validateKeyframe`.
- **`eslint-plugin-yourorg`:** A custom ESLint plugin that codifies the rules in this constitution.
- **Pre-commit Hooks:** A pre-commit hook is configured to run fast lint checks and unit smoke tests before code can be committed.

---

## Appendix C: Reference Sanitization Implementation (`DOMPurify`)

To effectively implement the **Trusted Types** and **Defense in Depth** mandates, a robust, well-configured sanitization library is required. Our recommended and reference implementation is **DOMPurify**.

### C.1. Rationale

`DOMPurify` is a security-focused HTML sanitizer that is highly effective against DOM-based XSS. It is the cornerstone of our client-side security, providing a critical defense layer that works in all browsers, including those that do not support Trusted Types (like Firefox).

### C.2. Creating the `app-policy` for Trusted Types

The `app-policy` required by our CSP **MUST** use `DOMPurify` to create `TrustedHTML` objects. This ensures that even in supporting browsers, all HTML is sanitized before being injected.

**Implementation Example:**

```javascript
import DOMPurify from "dompurify";

// This policy should be defined once in a central security module.
let appPolicy;

if (window.trustedTypes && trustedTypes.createPolicy) {
  appPolicy = trustedTypes.createPolicy("app-policy", {
    createHTML: (stringToSanitize) => {
      // Sanitize the string with a strict configuration.
      const sanitized = DOMPurify.sanitize(stringToSanitize, {
        USE_PROFILES: { html: true }, // Allow basic HTML tags
        RETURN_TRUSTED_TYPE: true, // Return a TrustedHTML object
      });
      return sanitized;
    },
    // Define createScriptURL and createScript as needed, or have them throw.
    createScriptURL: () => {
      throw new TypeError("Dynamic script URLs are not allowed");
    },
    createScript: () => {
      throw new TypeError("Dynamic scripts are not allowed");
    },
  });
}
```

### C.3. Secure Fallback for Non-Trusted-Types Browsers

In browsers like Firefox, where `window.trustedTypes` is undefined, you must still sanitize. The logic should fall back to using `DOMPurify` and assigning to a safe sink like `.textContent` or, if HTML is necessary, ensuring the sanitization is just as strict.

**Implementation Example:**

```javascript
function secureSetHTML(element, htmlContent) {
  if (appPolicy) {
    // Trusted Types path (Chrome, Edge)
    element.innerHTML = appPolicy.createHTML(htmlContent);
  } else {
    // Secure fallback path (Firefox, Safari)
    const sanitized = DOMPurify.sanitize(htmlContent, {
      USE_PROFILES: { html: true },
    });
    element.innerHTML = sanitized;
  }
}
```

#### C.4. Hardened Configuration for Complex Content (SVG/MathML) (MUST)

- **Statement:** If the application requires support for user-provided SVG or MathML, it **MUST NOT** use the default `DOMPurify` configuration. A specific, hardened configuration that minimizes the attack surface **MUST** be used. This configuration **MUST** be centrally managed and subject to security review (see Rule 4.4).
- **Rationale:** SVG and MathML are not just image or formula formats; they are XML-based document models with their own DOMs, scripting capabilities, and complex parsing rules. This dramatically increases the mutation XSS (mXSS) attack surface. The default `DOMPurify` configuration is too permissive for this context. To adhere to our "Secure by Default" and "Defense in Depth" principles, we must start with a minimal, allow-list-based policy. High-risk tags like `<foreignObject>`, `<script>`, and `<style>` are common vectors for bypasses as they can embed arbitrary HTML or scripts, and they are strictly forbidden.
- **Implementation Example (Secure Baseline for SVG):**

  ```javascript
  import DOMPurify from "dompurify";

  /**
   * This is the centrally-approved, hardened configuration for allowing SVGs.
   * It MUST be exported from a central security policy file.
   * DO NOT create ad-hoc configurations in component code.
   */
  export const SVG_ENABLED_POLICY_CONFIG = {
    // --- STRATEGY 1: DEFINE SCOPE & MINIMIZE NAMESPACES ---
    // Explicitly allow only the namespaces required. Forbid MathML if not needed.
    USE_PROFILES: { html: true, svg: true },

    // --- STRATEGY 2: FORBID HIGH-RISK TAGS ---
    // Block all tags that can execute scripts, embed foreign content, or create links.
    // CRITICAL: <foreignObject> is a primary vector for mXSS, allowing arbitrary HTML.
    FORBID_TAGS: [
      "script",
      "style",
      "iframe",
      "foreignObject",
      "form",
      "noscript",
      "a",
    ],

    // --- STRATEGY 3: FORBID SCRIPT-LIKE ATTRIBUTES (DEFENSE IN DEPTH) ---
    // Block all event handlers and attributes that can trigger script execution.
    // We also forbid 'href' as a defense-in-depth measure, preventing scriptable
    // links (e.g., xlink:href) even on tags that might otherwise be permitted.
    FORBID_ATTR: [
      "onclick",
      "onerror",
      "onload",
      "onmouseover",
      "onfocus",
      "onkeyup",
      "onkeydown",
      "href",
    ],

    // --- STRATEGY 4: INTEGRATE WITH BROWSER SECURITY PRIMITIVES ---
    // Ensure the output is a TrustedHTML object for supporting browsers.
    RETURN_TRUSTED_TYPE: true,
  };

  // Usage with a Trusted Types policy
  if (window.trustedTypes && trustedTypes.createPolicy) {
    const svgPolicy = trustedTypes.createPolicy("app-policy-svg", {
      createHTML: (stringToSanitize) => {
        return DOMPurify.sanitize(stringToSanitize, SVG_ENABLED_POLICY_CONFIG);
      },
      // Forbid other types unless explicitly needed and reviewed.
      createScriptURL: () => {
        throw new TypeError("Dynamic script URLs are not allowed");
      },
      createScript: () => {
        throw new TypeError("Dynamic scripts are not allowed");
      },
    });
  }
  ```

---

## Appendix D: Nanoid Integration Analysis & Implementation

This appendix documents the security-focused integration of `nanoid`'s techniques into our `security-kit.ts` module, demonstrating how we apply the "Defense in Depth" and "Verifiable Security" principles from the Constitution. This is not merely copying code; this is a careful analysis of a high-quality, security-focused library and integration of its best-in-class techniques in a way that is compliant with and enhances our existing security framework.

### D.1. Analysis of Nanoid's Core Techniques

`nanoid` has three key architectural features that make it fast and secure:

1.  **Randomness Pooling (Node.js version):** It requests a large buffer of random bytes from the OS at once (`fillPool`) and then serves smaller requests from this in-memory pool.
    - **Pro:** Massively reduces system call overhead in high-throughput server environments, leading to significant performance gains.
    - **Con:** Adds state management (`pool`, `poolOffset`). In a browser context, the overhead of `crypto.getRandomValues` is very low, making this a premature optimization that adds complexity for little to no gain.
    - **Constitution Alignment:** Violates the spirit of simplicity and encapsulated state. The performance gain on the client-side is negligible and not worth the added complexity.

2.  **Unbiased Sampling via Rejection Sampling (`customRandom`):** This is the most critical security feature for custom alphabets. To avoid "modulo bias" (where some characters appear more frequently if the alphabet size is not a power of two), it generates a random byte, masks it, and if the result is outside the range of the alphabet's length, it _rejects_ that byte and tries again.
    - **Pro:** Guarantees a uniform, cryptographically secure distribution of characters, which is essential for preventing prediction attacks.
    - **Con:** Can be slightly slower than biased methods, but this is a necessary trade-off for security.
    - **Constitution Alignment:** **Perfectly aligns.** This is a direct implementation of "Cryptographic Integrity (MUST)". Our existing `getSecureRandomInt` already uses this exact principle for number ranges.

3.  **Bitmasking Optimization (`nanoid` default):** For the default `urlAlphabet` (64 characters), `nanoid` uses a bitwise AND with a mask of `63` (`0b111111`). Since 64 is a power of two, every possible 6-bit value maps perfectly to one character. This is extremely fast and avoids the need for rejection sampling.
    - **Pro:** The fastest possible way to generate an unbiased ID when the alphabet size is a power of two.
    - **Con:** Only works for alphabet sizes that are powers of two (e.g., 2, 4, 8, 16, 32, 64, 128, 256).
    - **Constitution Alignment:** **Perfectly aligns.** This supports "Performance is a Security Feature (1.6)" without compromising security.

### D.2. Constitutional Compliance Assessment

| Technique                   | Recommendation                   | Justification (based on Security Constitution)                                                                                                                                                                                                                                            |
| :-------------------------- | :------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Randomness Pooling**      | **Do Not Implement**             | The complexity and global state management are not justified by the negligible performance gain in a browser environment. It's better to make direct, stateless calls to `crypto.getRandomValues`.                                                                                        |
| **Unbiased Sampling**       | **Implement as a New Feature**   | This is a critical security enhancement. We created a new, more flexible `generateSecureStringSync` function that can take any alphabet and size, and it uses rejection sampling to prevent modulo bias, adhering to "Cryptographic Integrity".                                           |
| **Bitmasking Optimization** | **Implement as an Optimization** | Inside our new `generateSecureStringSync` function, we detect if the alphabet's length is a power of two. If so, we use the highly performant bitmasking method. If not, we fall back to rejection sampling. This adheres to "Secure by Default" and "Performance is a Security Feature". |

### D.3. Implementation: Enhanced Security-Kit

The integration resulted in a new, powerful `generateSecureStringSync` function inspired by `nanoid` and refactored existing functions to use it:

#### D.3.1. Core Security Features

- **Cryptographic Integrity:** Uses rejection sampling to eliminate modulo bias for any alphabet size
- **Performance Optimization:** Automatically uses bitmasking for power-of-two alphabet sizes
- **Input Validation:** Strict parameter validation per "Fail Loudly, Fail Safely" principle
- **Secure Memory Management:** Proper cleanup of random bytes using `secureWipe`
- **Circuit Breaker:** Iteration limits prevent infinite loops from poor rejection sampling scenarios

#### D.3.2. API Improvements

1. **New `generateSecureStringSync(alphabet, size)`**: Generic, secure string generation from any alphabet
2. **Enhanced `generateSecureIdSync(length)`**: Now a simple wrapper using the hex alphabet
3. **Enhanced `generateSecureId(length)`**: Async version that ensures crypto availability
4. **New `URL_ALPHABET` constant**: Nanoid's proven URL-safe character set

#### D.3.3. Security Benefits

1. **More Capable:** Generic secure string generation function that can be used for more than just hex IDs (e.g., generating human-readable codes, using different alphabets).
2. **More Secure:** Guarantees uniform character distribution for _any_ alphabet, eliminating the risk of modulo bias that could have been introduced by a naive implementation. This fully aligns with the "Cryptographic Integrity" mandate.
3. **More Performant:** Automatically uses the fastest possible generation method (bitmasking) when conditions allow, directly supporting the "Performance is a Security Feature" principle.
4. **Better Code Quality:** Refactored existing functions to be simple wrappers, improving code reuse and making the library easier to maintain and reason about.

### D.4. Verification and Testing Requirements

Per Constitution principle 1.5 ("Verifiable Security"), the following tests **MUST** be implemented:

1. **Bias Testing:** Statistical tests to verify uniform distribution across different alphabet sizes
2. **Rejection Sampling Testing:** Verify that the function correctly rejects out-of-bounds values
3. **Performance Testing:** Benchmark the bitmasking optimization vs rejection sampling
4. **Security Property Testing:** Adversarial testing with malformed alphabets and edge cases
5. **Memory Safety Testing:** Verify proper cleanup of sensitive random data

This integration demonstrates how we take the best solutions from world-class libraries and implement them in a way that is 100% compliant with our strict Security Constitution while enhancing our security posture and performance characteristics.

### D.5. Future-Proofing: Post-Quantum Cryptography (SHOULD)

- **Statement:** For long-lived secrets (e.g., if extending to signing), prefer hybrid schemes combining classical (e.g., AES-256) with post-quantum algorithms (e.g., Kyber via Web Crypto extensions).
- **Rationale:** Quantum computers could break current asymmetric crypto; this aligns with "Verifiable Security" for forward defense.
- **Implementation:** Monitor Web Crypto API for PQ support; use libs like libsodium only if vendored and audited.
- **CI Check:** Flag deprecated algorithms (e.g., SHA-1) in code scans.
