import { describe, it, expect } from "vitest";
import { sendSecurePostMessage } from "../../src/postMessage";
import { setPostMessageConfig, getPostMessageConfig } from "../../src/config";
import { InvalidParameterError } from "../../src/errors";

describe("postMessage global traversal node budget", () => {
  const original = getPostMessageConfig();

  afterEach(() => {
    setPostMessageConfig(original as any);
  });

  it("enforces a single global node budget across branches in sanitize path", () => {
    // Drastically lower node budget to force budget breach on a moderately wide object
    setPostMessageConfig({ maxTraversalNodes: 5, maxObjectKeys: 100 });

    const target = { postMessage: (_: unknown, __: string) => {} } as unknown as Window;

    // Create an object with several sibling objects so that the total node count
    // across the traversal exceeds the budget even though depth is small.
    const payload: Record<string, unknown> = {};
    for (let i = 0; i < 10; i++) payload["k" + i] = { v: i };

    expect(() =>
      sendSecurePostMessage({
        targetWindow: target,
        payload,
        targetOrigin: "https://example.com",
        wireFormat: "structured",
        sanitize: true,
      }),
    ).toThrow(InvalidParameterError);
  });
});
