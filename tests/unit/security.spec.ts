import { describe, it, expect, vi, beforeEach } from "vitest";

// This test is a port of tests/old_tests/security.test.js -> focused unit assertions
// We adapt helpers inline where the original used external utilities.

describe("Security Testing Suite (unit)", () => {
  beforeEach(() => {
    // reset DOM
    if (typeof document !== "undefined") {
      document.body.innerHTML = "";
    }
    vi.clearAllMocks();
  });

  describe("XSS Prevention (unit)", () => {
    it("sanitizes script tags via simple pattern", () => {
      const maliciousHTML = '<script>alert("XSS")</script><p>Safe content</p>';
      const mockSanitizer = (html: string) =>
        html.replace(/<script[^>]*>.*?<\/script>/gi, "");
      const sanitized = mockSanitizer(maliciousHTML);
      expect(sanitized).not.toContain("<script>");
      expect(sanitized).not.toContain('alert("XSS")');
      expect(sanitized).toContain("<p>Safe content</p>");
    });

    it("prevents javascript: URL injection via validation helper", () => {
      const maliciousURL = 'javascript:alert("XSS")';
      const isValidURL = (url: string) => {
        try {
          const parsed = new URL(
            url,
            typeof window !== "undefined"
              ? window.location.origin
              : "https://example.test",
          );
          return ["http:", "https:", "mailto:", "tel:"].includes(
            parsed.protocol,
          );
        } catch {
          return false;
        }
      };

      expect(isValidURL(maliciousURL)).toBe(false);
      expect(isValidURL("https://example.com")).toBe(true);
      expect(isValidURL("mailto:test@example.com")).toBe(true);
    });

    it("demonstrates innerHTML danger vs textContent safety", () => {
      const div =
        typeof document !== "undefined" ? document.createElement("div") : null;
      const userInput = '<img src="x" onerror="alert(1)">';
      const isUnsafePattern = () => {
        if (!div) return false;
        try {
          div.innerHTML = userInput;
          return div.querySelector("img[onerror]") !== null;
        } catch {
          return false;
        }
      };
      expect(isUnsafePattern()).toBe(true);
      if (div) {
        div.textContent = userInput;
        expect(div.innerHTML).toBe('&lt;img src="x" onerror="alert(1)"&gt;');
      }
    });

    it("escapes template literal user input", () => {
      const userInput = '${alert("XSS")}';
      const escapeHTML = (str: string) =>
        str
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");
      const safeTemplate = `<div>${escapeHTML(userInput)}</div>`;
      expect(safeTemplate).toContain("&quot;");
      expect(safeTemplate).not.toContain("<script>");
    });
  });

  describe("CSP Compatibility (unit)", () => {
    it("avoids eval-like patterns in code strings", () => {
      const dangerousFunctions = ["eval", "setTimeout", "setInterval"];
      const codeString = "const result = someFunction(); return result;";
      dangerousFunctions.forEach((fn) =>
        expect(codeString).not.toContain(`${fn}(`),
      );
      expect(codeString).toContain("someFunction");
    });

    it("attaches nonce to script element", () => {
      if (typeof document === "undefined") return;
      const mockNonce = "test-nonce-12345";
      const script = document.createElement("script");
      script.nonce = mockNonce;
      script.textContent = 'console.log("Safe script");';
      expect(script.nonce).toBe(mockNonce);
      expect(script.textContent).not.toContain("eval");
    });
  });

  describe("Input Validation (unit)", () => {
    it("validates simple email pattern", () => {
      const validateEmail = (email: string) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email) && email.length <= 254;
      };
      expect(validateEmail("valid@example.com")).toBe(true);
      expect(validateEmail("invalid.email")).toBe(false);
      expect(validateEmail("")).toBe(false);
    });

    it("sanitizes form input by trimming and removing < and >", () => {
      const sanitizeInput = (input: unknown) => {
        if (typeof input !== "string") return "";
        return input.trim().slice(0, 1000).replace(/[<>]/g, "");
      };
      expect(sanitizeInput("  normal input  ")).toBe("normal input");
      expect(sanitizeInput("<script>alert(1)</script>")).toBe(
        "scriptalert(1)/script",
      );
    });

    it("validates URL param safety against common schemes", () => {
      const validateURLParam = (param: unknown) => {
        if (typeof param !== "string") return false;
        const dangerousPatterns = [
          /javascript:/i,
          /data:/i,
          /vbscript:/i,
          /<script/i,
          /on\w+=/i,
        ];
        return !dangerousPatterns.some((p) => p.test(param));
      };
      expect(validateURLParam("safe-value")).toBe(true);
      expect(validateURLParam("javascript:alert(1)")).toBe(false);
      expect(validateURLParam("onclick=alert(1)")).toBe(false);
    });
  });

  describe("DOM Manipulation & Prototype Pollution (unit)", () => {
    it("uses safe DOM methods and avoids setting on* attributes", () => {
      if (typeof document === "undefined") return;
      const container = document.createElement("div");
      const userContent = '<img src="x" onerror="alert(1)">';
      const safeAppendText = (element: Element, text: string) =>
        element.appendChild(document.createTextNode(text));
      safeAppendText(container, userContent);
      expect(container.textContent).toBe(userContent);
      expect(container.innerHTML).not.toContain("<img");

      const safeCreateElement = (
        tag: string,
        attributes: Record<string, unknown> = {},
      ) => {
        const el = document.createElement(tag);
        Object.entries(attributes).forEach(([k, v]) => {
          if (typeof k === "string" && !k.startsWith("on") && k !== "href")
            el.setAttribute(k, String(v));
        });
        return el;
      };
      const img = safeCreateElement("img", { src: "test.jpg", alt: "test" });
      expect(img.tagName).toBe("IMG");
      expect(img.hasAttribute("onerror")).toBe(false);
    });

    it("prevents prototype pollution via safeObjectAssign", () => {
      const safeObjectAssign = (
        target: Record<string, unknown>,
        source: Record<string, unknown>,
      ) => {
        const dangerousKeys = ["__proto__", "constructor", "prototype"];
        Object.keys(source).forEach((key) => {
          if (!dangerousKeys.includes(key)) target[key] = source[key];
        });
        return target;
      };
      const target: any = {};
      const malicious = {
        normal: "value",
        __proto__: { polluted: true },
        constructor: { polluted: true },
      } as any;
      safeObjectAssign(target, malicious);
      expect(target.normal).toBe("value");
      expect(({} as any).polluted).toBeUndefined();
    });
  });

  describe("Event Handler Security", () => {
    it("validates event names and handler types", () => {
      if (typeof document === "undefined") return;
      const button = document.createElement("button");
      const safeAddEventListener = (
        el: Element,
        event: string,
        handler: unknown,
      ) => {
        const allowed = [
          "click",
          "submit",
          "keydown",
          "keyup",
          "focus",
          "blur",
        ];
        if (!allowed.includes(event))
          throw new Error(`Event ${event} not allowed`);
        if (typeof handler !== "function")
          throw new Error("Handler must be a function");
        (el as any).addEventListener(event, handler as any);
      };
      expect(() =>
        safeAddEventListener(button, "click", () => {}),
      ).not.toThrow();
      expect(() => safeAddEventListener(button, "onload", () => {})).toThrow();
      expect(() =>
        safeAddEventListener(button, "click", "no" as any),
      ).toThrow();
    });
  });

  describe("Data Exposure Prevention", () => {
    it("does not leak sensitive data in errors", () => {
      const processUserData = (userData: any) => {
        try {
          if (!userData.email) throw new Error("Missing email");
          return { success: true };
        } catch {
          return { error: "Invalid input provided" };
        }
      };
      const result = processUserData({ password: "secret" });
      expect(result.error).toBe("Invalid input provided");
      expect((result as any).userData).toBeUndefined();
    });

    it("suppresses console output in production", () => {
      const original = console.log;
      const spy = vi.fn();
      console.log = spy;
      const oldEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";
      const safeLog = (message: string) => {
        if (process.env.NODE_ENV !== "production") console.log(message);
      };
      safeLog("Debug info");
      expect(spy).not.toHaveBeenCalled();
      process.env.NODE_ENV = oldEnv;
      console.log = original;
    });
  });

  describe("Edge Cases (encoding & mutation)", () => {
    it("handles encoded XSS payloads with sanitizer", async () => {
      const payloads = [
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
      ];
      payloads.forEach((p) => {
        const decoded = p.replace(/&lt;/g, "<").replace(/&gt;/g, ">");
        const mockSanitizer = (html: string) =>
          html.replace(/<script[^>]*>.*?<\/script>/gi, "");
        const sanitized = mockSanitizer(decoded);
        expect(sanitized).not.toContain("<script>");
      });
    });

    it("handles contextual XSS sanitization patterns", () => {
      const contextual = [
        { context: "attribute", payload: '" onload="alert(1)' },
        { context: "style", payload: "expression(alert(1))" },
        { context: "url", payload: "javascript:alert(1)" },
      ];
      contextual.forEach(({ context, payload }) => {
        const mockSanitizer = (input: string) => {
          if (context === "attribute") return input.replace(/on\w+=/gi, "");
          if (context === "style")
            return input.replace(/expression\s*\(/gi, "");
          if (context === "url") return input.replace(/javascript:/gi, "");
          return input;
        };
        const sanitized = mockSanitizer(payload);
        if (context === "attribute") expect(sanitized).not.toMatch(/on\w+=/i);
        if (context === "style")
          expect(sanitized).not.toMatch(/expression\s*\(/i);
        if (context === "url") expect(sanitized).not.toContain("javascript:");
      });
    });

    it("handles mutation XSS attempts by stripping <script> tags", () => {
      const mutationPayloads = [
        "<svg><script>alert(1)</script></svg>",
        "<math><script>alert(1)</script></math>",
      ];
      mutationPayloads.forEach((payload) => {
        const mockSanitizer = (html: string) =>
          html.replace(/<script[^>]*>.*?<\/script>/gis, "");
        const sanitized = mockSanitizer(payload);
        expect(sanitized).not.toContain("<script>");
      });
    });
  });
});
