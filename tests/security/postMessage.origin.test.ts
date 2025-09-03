import { test, expect, vi } from "vitest";
import { createSecurePostMessageListener } from "../../src/postMessage";

// RULE-ID: postmessage-origin
// This test ensures postMessage handlers reject messages from unknown origins.

test("postMessage handler must reject messages from unknown origins", async () => {
  // Create a listener with a strict allowlist and a spy for the consumer
  const allowed = ["https://example.com"];
  const onMessage = vi.fn();
  const listener = createSecurePostMessageListener({
    allowedOrigins: allowed,
    onMessage,
    validate: { processed: "boolean" },
  });

  // Simulate an event from an unknown origin (JSON string payload)
  const event = new MessageEvent("message", {
    data: JSON.stringify({ processed: true }),
    origin: "https://evil.com",
    source: null,
  } as any);

  // Dispatch through the global window event target to exercise the real listener
  window.dispatchEvent(event);

  // The API is designed to drop the message; ensure the consumer was not invoked.
  expect(onMessage).not.toHaveBeenCalled();

  listener.destroy();
});
