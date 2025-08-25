import { setupDOMPurify } from "./domPurify";

// Initialize a shared JSDOM + DOMPurify instance for tests.
const { DOMPurify, cleanup } = setupDOMPurify();

// Expose DOMPurify globally for tests that want to access it directly.
(globalThis as any).__TEST_DOMPURIFY__ = DOMPurify;

// Register a cleanup hook when the process exits in the test runner.
if (typeof (globalThis as any).afterAll === "function") {
  // vitest global
  (globalThis as any).afterAll(() => cleanup());
} else {
  // fallback: attempt to cleanup on process exit
  process.on("exit", () => cleanup());
}
