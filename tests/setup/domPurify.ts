import { JSDOM } from "jsdom";
import createDOMPurify from "isomorphic-dompurify";

export function setupDOMPurify() {
  let dom: JSDOM | null = null;
  let createdWindow = false;
  let addedTrustedTypes = false;

  // Prefer the existing global window (Vitest's jsdom) when available.
  let window: any = (globalThis as any).window;
  if (!window || !window.document) {
    dom = new JSDOM("<!doctype html><html><body></body></html>");
    window = dom.window;
    (globalThis as any).window = window;
    createdWindow = true;
  }

  // Add a lightweight Trusted Types shim for tests if not present.
  if (typeof window.trustedTypes === "undefined") {
    window.trustedTypes = {
      createPolicy: (name: string, rules: any) => ({
        name,
        createHTML: rules.createHTML,
      }),
    } as any;
    addedTrustedTypes = true;
  }

  const DOMPurify = createDOMPurify(window as any);

  function cleanup() {
    try {
      if (addedTrustedTypes) {
        try {
          delete window.trustedTypes;
        } catch {}
      }
      if (createdWindow) {
        try {
          delete (globalThis as any).window;
        } catch {}
        if (dom && typeof dom.window.close === "function") dom.window.close();
      }
    } catch (e) {
      // ignore cleanup errors in tests
    }
  }

  return { window, DOMPurify, cleanup };
}
