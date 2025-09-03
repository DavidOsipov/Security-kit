### **Ultimate Adversarial Testing & Security Audit Plan for `security-kit`**

#### **I. Methodology & Core Principles**

This plan outlines a series of adversarial tests designed to ruthlessly probe the security boundaries of the `security-kit` library. The goal is not to verify correct functionality but to actively provoke insecure behavior, resource exhaustion, and logic flaws by violating the library's explicit and implicit security assumptions.

**Core Principles:**

1.  **Assume a Hostile Environment:** Tests will simulate scenarios where dependencies are compromised, cryptographic primitives are weak, and all inputs are malicious until proven otherwise.
2.  **Test the Boundaries:** Focus on edge cases, resource limits, and state transitions, as these are common sources of vulnerabilities.
3.  **Fail Safely and Loudly:** The library should never fail silently in a way that compromises security. Tests will verify that failures result in thrown exceptions or safe, inert states.
4.  **Defense-in-Depth Validation:** Tests will attempt to bypass primary defenses to ensure that secondary and tertiary controls (e.g., rate limiters, replay protection) correctly mitigate the failure.

**Required Tooling:**

- **Test Runner:** A framework supporting both Node.js and a browser-like DOM environment (e.g., Vitest with `happy-dom` or Playwright).
- **Mocking Library:** Extensive use of `vi.spyOn`, `vi.mock`, and `vi.stubGlobal` to control environmental factors like `crypto`, `fetch`, and timers.

---

#### **II. Test Suite 1: Input Validation & Canonicalization (CWE-20)**

**Adversarial Goal:** Bypass validation logic to inject malicious data, trigger unexpected code paths, or cause downstream parsing errors.

**1.1. Unicode & Encoding Obfuscation Attacks**

- **Vector:** Use non-standard Unicode characters, homoglyphs, and non-canonical encodings to trick validation logic that relies on simple string or regex checks.
- **Test Case (URL Homoglyph Bypass):**

  ```typescript
  // File: url.adversarial.test.ts
  import { normalizeOrigin, validateURL } from "../src/url";

  it("should not be fooled by Unicode homoglyphs in origins", () => {
    const legitimateOrigin = "https://apple.com";
    // U+0430 is the Cyrillic 'а', which looks identical to the Latin 'a'.
    const maliciousOrigin = "https://аpple.com";

    // 1. Test normalization: IDNA (Punycode) should canonicalize the malicious origin differently.
    const normalizedMalicious = normalizeOrigin(maliciousOrigin);
    expect(normalizedMalicious).not.toBe(legitimateOrigin);
    expect(normalizedMalicious).toBe("https://xn--pple-43d.com/");

    // 2. Test validation: The validation logic must use this canonical form.
    const validation = validateURL(maliciousOrigin, {
      allowedOrigins: [legitimateOrigin],
    });
    expect(validation.ok).toBe(false);
    expect(validation.error?.message).toContain("is not in allowlist");
  });
  ```

- **Test Case (Path Traversal with Double Encoding):**

  ```typescript
  // File: url.adversarial.test.ts
  import { createSecureURL } from "../src/url";

  it("should reject double-encoded path traversal characters", () => {
    // %252E is the double-encoded form of '.', which becomes '.' after one decode.
    const traversalPath = ["..%252E..%252Fetc%252Fpasswd"];
    expect(() =>
      createSecureURL("https://example.com/api/", traversalPath),
    ).toThrow(InvalidParameterError);
  });
  ```

**1.2. Type Juggling & Prototype Manipulation**

- **Vector:** Provide objects that are not true primitives or plain objects, designed to trick `typeof`, `instanceof`, or property access logic.
- **Test Case (Malicious `toJSON` Method):**

  ```typescript
  // File: canonical.adversarial.test.ts
  import { toCanonicalValue } from "../src/canonical";

  it("should not execute a malicious toJSON method during canonicalization", () => {
    const maliciousPayload = {
      a: 1,
      toJSON: () => {
        (globalThis as any).wasToJSONCalled = true;
        return { hacked: true };
      },
    };

    const canonical = toCanonicalValue(maliciousPayload);

    // The core assertion: the side effect should never happen.
    expect((globalThis as any).wasToJSONCalled).toBeUndefined();

    // The canonical form should be based on the object's actual properties, not the toJSON output.
    expect(canonical).toEqual({ a: 1 });
  });
  ```

---

#### **III. Test Suite 2: Deserialization & Prototype Pollution (CWE-502, CWE-787)**

**Adversarial Goal:** Pollute the global `Object.prototype` to achieve arbitrary code execution, privilege escalation, or XSS by adding malicious properties to all objects.

**2.1. Advanced Pollution Payloads**

- **Vector:** Use nested `constructor` and `prototype` keys to bypass shallow checks.
- **Test Case (Polluting `Object.prototype`):**

  ```typescript
  // File: postMessage.adversarial.test.ts
  import { toNullProto } from "../src/postMessage"; // Assuming __test_toNullProto is available
  import { toCanonicalValue } from "../src/canonical";
  import { _redact } from "../src/utils";

  describe("Prototype Pollution Defenses", () => {
    const payloads = [
      JSON.parse('{"__proto__": {"isPolluted": true}}'),
      JSON.parse('{"constructor": {"prototype": {"isPolluted": true}}}'),
    ];

    afterEach(() => {
      // Cleanup in case a test fails and pollutes the prototype
      delete (Object.prototype as any).isPolluted;
    });

    it.each([toNullProto, toCanonicalValue, _redact])(
      "should prevent prototype pollution via %p",
      (processor) => {
        for (const payload of payloads) {
          processor(payload);
          expect((Object.prototype as any).isPolluted).toBeUndefined();
        }
      },
    );
  });
  ```

---

#### **IV. Test Suite 3: Resource Consumption & DoS (CWE-400)**

**Adversarial Goal:** Crash the server or freeze the client by forcing the library into expensive computations, deep recursion, or high memory allocation.

**3.1. Asymmetric Computation DoS**

- **Vector:** Craft an input where verification is significantly more computationally expensive than creation, allowing an attacker to overload a server with cheap-to-create requests.
- **Test Case (Large Payload Verification):**

  ```typescript
  // File: verify-api-request-signature.adversarial.test.ts
  import { verifyApiRequestSignature } from "../src/verify-api-request-signature";

  it("should fail fast on oversized payloads before expensive canonicalization", async () => {
    // Create a payload just over the internal 10MB limit.
    const hugePayload = "a".repeat(10 * 1024 * 1024 + 1);
    const fakeRequest = {
      secret: "test-secret",
      payload: hugePayload,
      nonce: "nonce",
      timestamp: Date.now(),
      signatureBase64: "fake-signature",
    };

    // The test asserts that validation fails with a parameter error *before*
    // attempting to stringify the huge payload, which would consume significant CPU.
    await expect(
      verifyApiRequestSignature(fakeRequest, new InMemoryNonceStore()),
    ).rejects.toThrow("payload too large");
  });
  ```

**3.2. Worker Starvation & Rate Limiter Abuse**

- **Vector:** Occupy all available worker slots with requests that will time out, preventing legitimate requests from being processed.
- **Test Case (Worker Slot Exhaustion):**

  ```typescript
  // File: secure-api-signer.adversarial.test.ts
  import { SecureApiSigner } from "../src/secure-api-signer";

  it("should immediately reject requests when all worker slots are occupied by timed-out requests", async () => {
    // Mock the worker to never respond, forcing timeouts.
    const mockWorker = new Worker(/* path to a worker that does nothing */);
    vi.spyOn(mockWorker, "postMessage").mockImplementation(() => {});

    const signer = await SecureApiSigner.create({
      secret: new Uint8Array(32),
      workerUrl: "...", // provide valid URL
      maxPendingRequests: 5,
      requestTimeoutMs: 100,
    });
    // Inject the mock after creation
    (signer as any)["#worker"] = mockWorker;

    const promises = [];
    for (let i = 0; i < 5; i++) {
      promises.push(signer.sign({ data: i }));
    }

    // All 5 slots are now occupied. The next call must fail instantly.
    await expect(signer.sign({ data: "last" })).rejects.toThrow(RateLimitError);

    // Ensure the pending promises eventually time out as expected.
    for (const p of promises) {
      await expect(p).rejects.toThrow("Sign request timed out");
    }
  });
  ```

---

#### **V. Test Suite 4: Cryptographic & State Logic Flaws**

**Adversarial Goal:** Exploit weaknesses in the cryptographic implementation or state management to forge signatures, replay messages, or cause the system to enter an insecure state.

**5.1. Weak RNG and Nonce Reuse**

- **Vector:** Simulate a compromised client environment where `crypto.getRandomValues` is not random, leading to nonce reuse.
- **Test Case (Nonce Reuse Attack):**

  ```typescript
  // File: crypto.adversarial.test.ts
  import {
    _setCrypto,
    __test_resetCryptoStateForUnitTests,
  } from "../src/state";
  import { SecureApiSigner } from "../src/secure-api-signer";
  import {
    verifyApiRequestSignature,
    InMemoryNonceStore,
  } from "../src/verify-api-request-signature";

  it("should be resilient to nonce reuse from a weak client RNG", async () => {
    const mockCrypto = {
      ...globalThis.crypto,
      getRandomValues: (arr: Uint8Array) => arr.fill(0xaa), // Always returns the same bytes
    };
    _setCrypto(mockCrypto, { allowInProduction: true });

    const secret = new Uint8Array(32).fill(1);
    const signer = await SecureApiSigner.create({ secret, workerUrl: "..." });

    const payload1 = { data: "first message" };
    const signed1 = await signer.sign(payload1);

    const payload2 = { data: "second message" };
    const signed2 = await signer.sign(payload2);

    // Assert that the weak RNG produced the same nonce
    expect(signed1.nonce).toBe(signed2.nonce);

    // Now, test the server-side replay protection
    const nonceStore = new InMemoryNonceStore();
    const verificationInput1 = { ...signed1, secret, payload: payload1 };
    const verificationInput2 = { ...signed2, secret, payload: payload2 };

    // The first request should succeed.
    await expect(
      verifyApiRequestSignature(verificationInput1, nonceStore),
    ).resolves.toBe(true);

    // The second request, despite having a valid signature for its payload,
    // MUST be rejected because the nonce has already been seen.
    await expect(
      verifyApiRequestSignature(verificationInput2, nonceStore),
    ).rejects.toThrow(ReplayAttackError);

    __test_resetCryptoStateForUnitTests();
  });
  ```

**5.2. Circuit Breaker State Manipulation**

- **Vector:** Force the circuit breaker into an open or half-open state and verify its recovery logic is sound and does not get stuck.
- **Test Case (Circuit Breaker Lifecycle):**

  ```typescript
  // File: secure-api-signer.adversarial.test.ts
  it('should correctly transition through the circuit breaker states', async () => {
    const signer = await SecureApiSigner.create({ ... });
    const worker = (signer as any)['#worker'];
    const postMessageSpy = vi.spyOn(worker, 'postMessage');

    // 1. Trip the breaker to 'open'
    postMessageSpy.mockImplementation(() => { throw new Error('Worker Failure'); });
    for (let i = 0; i < 10; i++) { // CIRCUIT_BREAKER_FAILURE_THRESHOLD
      await expect(signer.sign({ i })).rejects.toThrow();
    }
    expect(signer.getCircuitBreakerStatus().state).toBe('open');
    await expect(signer.sign({ data: 'should be blocked' })).rejects.toThrow(CircuitBreakerError);

    // 2. Wait for timeout to enter 'half-open'
    vi.useFakeTimers();
    vi.advanceTimersByTime(60001); // CIRCUIT_BREAKER_TIMEOUT_MS + 1

    // The next call is allowed but will fail, re-opening the breaker immediately.
    await expect(signer.sign({ data: 'half-open test' })).rejects.toThrow();
    expect(signer.getCircuitBreakerStatus().state).toBe('open');

    // 3. Test recovery to 'closed'
    vi.advanceTimersByTime(60001); // Enter half-open again
    postMessageSpy.mockRestore(); // Let the worker succeed now

    for (let i = 0; i < 3; i++) { // CIRCUIT_BREAKER_SUCCESS_THRESHOLD
      await expect(signer.sign({ i })).resolves.toBeDefined();
    }
    expect(signer.getCircuitBreakerStatus().state).toBe('closed');
    vi.useRealTimers();
  });
  ```

---

#### **VI. Test Suite 5: Environmental & Supply-Chain Attacks**

**Adversarial Goal:** Exploit weaknesses in how the library interacts with its environment, including the network and its own dependencies.

**6.1. Server-Side Request Forgery (SSRF)**

- **Vector:** Provide a `workerUrl` that points to a sensitive internal network resource.
- **Test Case (SSRF via `workerUrl`):**

  ```typescript
  // File: secure-api-signer.adversarial.test.ts
  import { SecureApiSigner } from "../src/secure-api-signer";

  it("should throw an error when workerUrl points to a restricted internal IP address", async () => {
    // Mock fetch to simulate a successful response from an internal IP
    vi.stubGlobal("fetch", async (url: string) => {
      if (url.includes("127.0.0.1") || url.includes("169.254.169.254")) {
        return new Response("// worker code here");
      }
      return new Response("Not Found", { status: 404 });
    });

    const internalUrl = "http://127.0.0.1/worker.js";

    // The create function should contain logic to reject such URLs before fetching.
    await expect(
      SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: internalUrl,
      }),
    ).rejects.toThrow(InvalidParameterError); // Or a more specific SSRF error
  });
  ```

  **Note:** This test requires you to _implement_ SSRF protection in `normalizeAndValidateWorkerUrl`. A simple check could be to reject any URL whose hostname resolves to a private or loopback IP address.

This comprehensive plan provides a roadmap for a rigorous, adversarial security audit. By implementing these tests, you will build a powerful regression suite that actively defends against sophisticated attacks, ensuring `security-kit` remains a trusted and robust library.
