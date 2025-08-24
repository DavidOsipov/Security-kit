/**
 * Security Testing Utilities
 * A collection of utilities for testing JavaScript security vulnerabilities
 */

/**
 * Common XSS payloads for testing input sanitization
 */
export const XSS_PAYLOADS = [
  '<script>alert("XSS")</script>',
  '"><script>alert("XSS")</script>',
  "'><script>alert('XSS')</script>",
  '<img src="x" onerror="alert(1)">',
  '<svg onload="alert(1)">',
  'javascript:alert("XSS")',
  "data:text/html,<script>alert(1)</script>",
  '<iframe src="javascript:alert(1)">',
  '<object data="javascript:alert(1)">',
  '<embed src="javascript:alert(1)">',
  '<link rel="stylesheet" href="javascript:alert(1)">',
  '<style>@import "javascript:alert(1)"</style>',
  '<input autofocus onfocus="alert(1)">',
  '<select autofocus onfocus="alert(1)">',
  '<textarea autofocus onfocus="alert(1)">',
  '<keygen autofocus onfocus="alert(1)">',
  '<video><source onerror="alert(1)">',
  '<audio src="x" onerror="alert(1)">',
  '${alert("XSS")}',
  '#{alert("XSS")}',
  'eval("alert(1)")',
  'Function("alert(1)")()',
  'setTimeout("alert(1)",0)',
  'setInterval("alert(1)",0)',
];

/**
 * SQL injection payloads (for testing client-side input validation)
 */
export const SQL_INJECTION_PAYLOADS = [
  "' OR '1'='1",
  '" OR "1"="1',
  "'; DROP TABLE users; --",
  '" UNION SELECT * FROM users --',
  "' AND 1=1 --",
  "' AND 1=2 --",
  "1' OR '1'='1' --",
  "admin'--",
  "admin' /*",
  "' OR 1=1#",
  "' OR 1=1--",
  "') OR '1'='1--",
  ")) OR (('1'='1'--",
];

/**
 * Path traversal payloads
 */
export const PATH_TRAVERSAL_PAYLOADS = [
  "../../../etc/passwd",
  "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
  "/etc/passwd",
  "....//....//....//etc/passwd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "..%252f..%252f..%252fetc%252fpasswd",
  "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
];

/**
 * Tests if a sanitization function properly handles XSS payloads
 * @param {Function} sanitizeFunction - Function to test
 * @param {Array} payloads - Array of payloads to test (defaults to XSS_PAYLOADS)
 * @returns {Object} Test results
 */
export function testXSSResistance(sanitizeFunction, payloads = XSS_PAYLOADS) {
  const results = {
    totalTests: payloads.length,
    passed: 0,
    failed: 0,
    failures: [],
  };

  payloads.forEach((payload, index) => {
    try {
      const sanitized = sanitizeFunction(payload);

      // Check if dangerous patterns are removed
      const dangerousPatterns = [
        /<script/i,
        /javascript:/i,
        /on\w+=/i,
        /eval\(/i,
        /Function\(/i,
        /setTimeout\(/i,
        /setInterval\(/i,
      ];

      const isUnsafe = dangerousPatterns.some((pattern) =>
        pattern.test(sanitized),
      );

      if (isUnsafe) {
        results.failed++;
        results.failures.push({
          payload,
          sanitized,
          reason: "Dangerous pattern detected in output",
        });
      } else {
        results.passed++;
      }
    } catch (error) {
      results.failed++;
      results.failures.push({
        payload,
        error: error.message,
        reason: "Sanitization function threw an error",
      });
    }
  });

  return results;
}

/**
 * Tests URL validation against malicious URLs
 * @param {Function} validateFunction - URL validation function to test
 * @returns {Object} Test results
 */
export function testURLValidation(validateFunction) {
  if (!validateFunction || typeof validateFunction !== "function") {
    throw new Error("validateFunction must be a valid function");
  }

  const validURLs = [
    "https://example.com",
    "http://example.com",
    "mailto:test@example.com",
    "tel:+1234567890",
    "/relative/path",
    "./relative/path",
    "../relative/path",
  ];

  const maliciousURLs = [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:alert(1)",
    "file:///etc/passwd",
    "ftp://malicious.com",
    "javascript://comment%0Aalert(1)",
    "data:,alert(1)",
    "javascript&colon;alert(1)",
  ];

  const results = {
    validPassed: 0,
    validFailed: 0,
    maliciousBlocked: 0,
    maliciousAllowed: 0,
    failures: [],
  };

  // Test valid URLs (should pass)
  validURLs.forEach((url) => {
    try {
      if (validateFunction(url)) {
        results.validPassed++;
      } else {
        results.validFailed++;
        results.failures.push({
          url,
          expected: "valid",
          actual: "invalid",
          type: "false_negative",
        });
      }
    } catch (error) {
      results.validFailed++;
      results.failures.push({
        url,
        error: error.message,
        type: "validation_error",
      });
    }
  });

  // Test malicious URLs (should be blocked)
  maliciousURLs.forEach((url) => {
    try {
      if (validateFunction(url)) {
        results.maliciousAllowed++;
        results.failures.push({
          url,
          expected: "blocked",
          actual: "allowed",
          type: "false_positive",
        });
      } else {
        results.maliciousBlocked++;
      }
    } catch (error) {
      results.maliciousBlocked++; // Errors count as blocked
    }
  });

  return results;
}

/**
 * Tests if a function is vulnerable to prototype pollution
 * @param {Function} mergeFunction - Function that merges objects
 * @returns {boolean} True if vulnerable, false if safe
 */
export function testPrototypePollution(mergeFunction) {
  if (!mergeFunction || typeof mergeFunction !== "function") {
    throw new Error("mergeFunction must be a valid function");
  }

  // Clear any existing pollution first
  delete Object.prototype.polluted;
  delete Object.prototype.isVulnerable;

  const target = {};

  // Try multiple payload variations
  const payloads = [
    { __proto__: { polluted: true } },
    { __proto__: { isVulnerable: true } },
    JSON.parse('{"__proto__": {"polluted": true}}'),
  ];

  try {
    for (const payload of payloads) {
      mergeFunction(target, payload);

      // Check if prototype was polluted
      const testObj = {};
      if (
        testObj.polluted === true ||
        testObj.isVulnerable === true ||
        Object.prototype.polluted === true ||
        Object.prototype.isVulnerable === true
      ) {
        // Clean up before returning
        delete Object.prototype.polluted;
        delete Object.prototype.isVulnerable;
        return true;
      }
    }

    // Clean up
    delete Object.prototype.polluted;
    delete Object.prototype.isVulnerable;
    return false;
  } catch (error) {
    // If function throws an error, it's likely safe
    delete Object.prototype.polluted;
    delete Object.prototype.isVulnerable;
    return false;
  }
}

/**
 * Creates a mock CSP (Content Security Policy) for testing
 * @param {Object} policies - CSP policies to enforce
 * @returns {Object} Mock CSP object
 */
export function createMockCSP(policies = {}) {
  const defaultPolicies = {
    "script-src": ["'self'", "'unsafe-inline'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "default-src": ["'self'"],
  };

  const csp = { ...defaultPolicies, ...policies };

  return {
    policies: csp,

    /**
     * Check if a script source would be allowed
     * @param {string} src - Script source to check
     * @returns {boolean} True if allowed, false if blocked
     */
    allowsScript(src) {
      const scriptSrc = csp["script-src"] || [];

      // Block dangerous schemes like data: and blob: unless explicitly allowed
      if (src && (src.startsWith("data:") || src.startsWith("blob:"))) {
        return scriptSrc.includes("'unsafe-inline'") || scriptSrc.includes(src);
      }

      if (
        scriptSrc.includes("'self'") &&
        (!src || (!src.includes("://") && !src.includes(":")))
      ) {
        return true;
      }

      return scriptSrc.some((allowed) => {
        if (allowed === src) return true;
        if (allowed.endsWith("*") && src.startsWith(allowed.slice(0, -1)))
          return true;
        if (allowed.endsWith("/*") && src.startsWith(allowed.slice(0, -2)))
          return true;
        // Handle domain matching for HTTPS sources
        if (src.includes("://") && allowed.includes("://")) {
          const allowedDomain = allowed
            .replace(/^https?:\/\//, "")
            .replace(/\/.*$/, "");
          const srcDomain = src
            .replace(/^https?:\/\//, "")
            .replace(/\/.*$/, "");
          return allowedDomain === srcDomain;
        }
        return false;
      });
    },

    /**
     * Check if a resource would be allowed
     * @param {string} directive - CSP directive (e.g., 'img-src')
     * @param {string} src - Resource source to check
     * @returns {boolean} True if allowed, false if blocked
     */
    allows(directive, src) {
      const sources = csp[directive] || csp["default-src"] || [];

      // Block dangerous schemes like data: and blob: unless explicitly allowed
      if (src && (src.startsWith("data:") || src.startsWith("blob:"))) {
        return sources.includes("'unsafe-inline'") || sources.includes(src);
      }

      if (
        sources.includes("'self'") &&
        ((!src.includes("://") && !src.includes(":")) || src.startsWith("/"))
      ) {
        return true;
      }

      if (sources.includes("'none'")) {
        return false;
      }

      return sources.some((allowed) => {
        if (allowed === src) return true;
        if (allowed.endsWith("*") && src.startsWith(allowed.slice(0, -1)))
          return true;
        if (allowed.endsWith("/*") && src.startsWith(allowed.slice(0, -2)))
          return true;
        return false;
      });
    },
  };
}

/**
 * Security testing patterns for common vulnerabilities
 */
export const SECURITY_PATTERNS = {
  /**
   * Test DOM manipulation for XSS vulnerabilities
   */
  testDOMManipulation(manipulationFunction) {
    const testElement = document.createElement("div");
    const maliciousContent = "<script>window.xssTriggered=true</script>";

    manipulationFunction(testElement, maliciousContent);

    return {
      hasScript: testElement.innerHTML.includes("<script>"),
      scriptExecuted: !!window.xssTriggered,
      innerHTML: testElement.innerHTML,
      textContent: testElement.textContent,
    };
  },

  /**
   * Test event handler registration for security
   */
  testEventHandlers(element, eventType, handler) {
    const eventInfo = {
      type: eventType,
      handler: handler,
      isFunction: typeof handler === "function",
      isString: typeof handler === "string",
      containsScript: typeof handler === "string" && handler.includes("script"),
    };

    // Safe event registration
    if (eventInfo.isFunction) {
      element.addEventListener(eventType, handler);
      return { ...eventInfo, registered: true, safe: true };
    }

    return { ...eventInfo, registered: false, safe: false };
  },

  /**
   * Test form input validation
   */
  testFormValidation(validationFunction, testInputs) {
    return testInputs.map((input) => ({
      input,
      isValid: validationFunction(input),
      length: input ? input.length : 0,
      containsScript: input ? input.includes("<script>") : false,
    }));
  },
};

/**
 * Utility to run a comprehensive security test suite
 * @param {Object} testTarget - Object containing functions to test
 * @returns {Object} Complete security test results
 */
export function runSecurityTestSuite(testTarget) {
  const results = {
    timestamp: new Date().toISOString(),
    tests: {},
    summary: {
      totalTests: 0,
      passed: 0,
      failed: 0,
      critical: 0,
    },
  };

  // Test XSS resistance if sanitize function is provided
  if (testTarget.sanitize) {
    results.tests.xssResistance = testXSSResistance(testTarget.sanitize);
    results.summary.totalTests++;
    if (results.tests.xssResistance.failed === 0) {
      results.summary.passed++;
    } else {
      results.summary.failed++;
      results.summary.critical++;
    }
  }

  // Test URL validation if provided
  if (testTarget.validateURL) {
    results.tests.urlValidation = testURLValidation(testTarget.validateURL);
    results.summary.totalTests++;
    if (results.tests.urlValidation.maliciousAllowed === 0) {
      results.summary.passed++;
    } else {
      results.summary.failed++;
      results.summary.critical++;
    }
  }

  // Test prototype pollution if merge function is provided
  if (testTarget.merge) {
    results.tests.prototypePollution = testPrototypePollution(testTarget.merge);
    results.summary.totalTests++;
    if (!results.tests.prototypePollution) {
      results.summary.passed++;
    } else {
      results.summary.failed++;
      results.summary.critical++;
    }
  }

  return results;
}
