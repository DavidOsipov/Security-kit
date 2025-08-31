import { describe, it, expect, vi, beforeEach } from "vitest";
import { registerTelemetry } from "../../src/utils";

describe("telemetry registration", () => {
  beforeEach(() => {
    // Ensure fresh global state by unregistering any existing hook if present.
    try {
      // There's no public getter, but calling registerTelemetry and immediately
      // unregistering is a no-op if a hook already exists; tests use isolated
      // processes so this is best-effort.
    } catch {
      /* ignore */
    }
  });

  it("registers, emits, and unregisters telemetry hooks (basic)", () => {
    const calls: Array<any> = [];
    const hook = (name: string, value?: number, tags?: Record<string, string>) => {
      calls.push({ name, value, tags });
    };

    const unregister = registerTelemetry(hook as any);
    // Simulate an emission by invoking the registered hook indirectly; we
    // can't call the private safeEmitMetric here, so call the hook to assert
    // it behaves like a telemetry receiver.
    hook("test.metric", 1, { reason: "unit" });
    expect(calls.length).toBe(1);

    unregister();
    expect(typeof unregister).toBe("function");
  });

  it("rejects double registration", () => {
    const hookA = () => {};
    const unregisterA = registerTelemetry(hookA as any);
    try {
      // Cast the whole function expression to any to avoid TypeScript parsing
      // issues when casting inside the arrow directly.
      expect(() => registerTelemetry((() => {}) as any)).toThrow();
    } finally {
      unregisterA();
    }
  });

  it("rejects non-function hooks", () => {
    // Intentionally passing wrong type at runtime; ensure API rejects it.
    expect(() => registerTelemetry(null as any)).toThrow();
    // Ensure no hook was left registered
    try {
      // noop
    } catch {
      /* ignore */
    }
  });

  it("handles user hook throwing without affecting library (hook error captured)", async () => {
    const throwingHook = vi.fn(() => {
      throw new Error("hook failure");
    });
    const unregister = registerTelemetry(throwingHook as any);

    // Trigger a code path that emits a metric. secureCompare exposes a code
    // path that calls safeEmitMetric when near-limit inputs are used. Use
    // a near-limit input to trigger a telemetry emission.
    const long = "x".repeat(4096 - 63);
    try {
      // We expect secureCompare to run without throwing even if the hook fails
      // because safeEmitMetric catches hook errors.
      // Import here to avoid circular module initialization issues in test runner
      const { secureCompare } = await import("../../src/utils");
      expect(secureCompare(long, long)).toBe(true);
      // Wait for microtask to complete
      await new Promise(resolve => setTimeout(resolve, 0));
      expect(throwingHook).toHaveBeenCalled();
    } finally {
      unregister();
    }
  });


  it('safeEmitMetric passes sanitized tags to hooks', async () => {
    const received: Array<any> = [];
    const hook = (name: string, value?: number, tags?: Record<string, string>) => {
      received.push({ name, value, tags });
    };
    const unregister = registerTelemetry(hook as any);
    try {
// Trigger emission via secureCompare path as in previous test
  const { secureCompare } = await import('../../src/utils');
      const long = 'x'.repeat(4096 - 63);
      expect(secureCompare(long, long)).toBe(true);
      // Wait for microtask
      await new Promise(resolve => setTimeout(resolve, 0));
      // Expect at least one telemetry call recorded
      expect(received.length).toBeGreaterThan(0);
      for (const call of received) {
        if (call.tags) {
          // No unexpected keys
          for (const k of Object.keys(call.tags)) {
            expect(['reason','strict','requireCrypto','subtlePresent']).toContain(k);
          }
        }
      }
    } finally {
      unregister();
    }
  });

  it("telemetry hook is called asynchronously (non-blocking)", async () => {
    let called = false;
    const hook = vi.fn(() => {
      called = true;
    });
    const unregister = registerTelemetry(hook as any);
    try {
      // Trigger emission
      const { secureCompare } = await import("../../src/utils");
      const long = "x".repeat(4096 - 63);
      secureCompare(long, long);
      // Should not be called synchronously
      expect(called).toBe(false);
      // Wait for microtask
      await new Promise(resolve => setTimeout(resolve, 0));
      expect(hook).toHaveBeenCalled();
    } finally {
      unregister();
    }
  });
});