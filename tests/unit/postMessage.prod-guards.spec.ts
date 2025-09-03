import { test, expect, vi } from "vitest";

test("runtime test API guard throws when production and no flag set", async () => {
  vi.resetModules();
  const prevEnv = process.env.SECURITY_KIT_ALLOW_TEST_APIS;
  const env = await import("../../src/environment");
  // Ensure production flag and no global allow — temporarily stub getter
  const origDesc = Object.getOwnPropertyDescriptor(
    env.environment,
    "isProduction",
  );
  try {
    Object.defineProperty(env.environment, "isProduction", { get: () => true });
    // Ensure process env does not allow test APIs for this test
    process.env.SECURITY_KIT_ALLOW_TEST_APIS = undefined as unknown as string;
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    const postMessage = await import("../../src/postMessage");
    expect(() => (postMessage as any).__test_toNullProto({})).toThrow();
  } finally {
    if (origDesc)
      Object.defineProperty(env.environment, "isProduction", origDesc);
    if (typeof prevEnv === "undefined")
      delete process.env.SECURITY_KIT_ALLOW_TEST_APIS;
    else process.env.SECURITY_KIT_ALLOW_TEST_APIS = prevEnv;
  }
});

test("createSecurePostMessageListener fails fast in production without crypto", async () => {
  vi.resetModules();
  const env = await import("../../src/environment");
  const origDesc = Object.getOwnPropertyDescriptor(
    env.environment,
    "isProduction",
  );
  const origCrypto = (globalThis as any).crypto;
  try {
    Object.defineProperty(env.environment, "isProduction", { get: () => true });
    // Remove crypto to simulate missing secure RNG
    delete (globalThis as any).crypto;
    const postMessage = await import("../../src/postMessage");
    const { CryptoUnavailableError } = await import("../../src/errors");
    expect(() =>
      (postMessage as any).createSecurePostMessageListener({
        allowedOrigins: ["https://example.com"],
        onMessage: () => {},
        validate: (d: unknown) => true,
      }),
    ).toThrow(CryptoUnavailableError);
  } finally {
    if (origDesc)
      Object.defineProperty(env.environment, "isProduction", origDesc);
    (globalThis as any).crypto = origCrypto;
  }
});
