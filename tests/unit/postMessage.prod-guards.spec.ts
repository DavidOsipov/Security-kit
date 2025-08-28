import * as postMessage from '../../src/postMessage';
import { environment } from '../../src/environment';
import { CryptoUnavailableError } from '../../src/errors';

test('runtime test API guard throws when production and no flag set', () => {
  // Ensure production flag and no global allow — temporarily stub getter
  const origDesc = Object.getOwnPropertyDescriptor(environment, 'isProduction');
  try {
    Object.defineProperty(environment, 'isProduction', { get: () => true });
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    expect(() => postMessage.__test_toNullProto({})).toThrow();
  } finally {
    if (origDesc) Object.defineProperty(environment, 'isProduction', origDesc);
  }
});

test('createSecurePostMessageListener fails fast in production without crypto', () => {
  const origDesc = Object.getOwnPropertyDescriptor(environment, 'isProduction');
  const origCrypto = (globalThis as any).crypto;
  try {
    Object.defineProperty(environment, 'isProduction', { get: () => true });
    // Remove crypto to simulate missing secure RNG
    // @ts-expect-error allow wipe
    delete (globalThis as any).crypto;
    expect(() =>
      postMessage.createSecurePostMessageListener(
        {
          allowedOrigins: ['https://example.com'],
          onMessage: () => {},
          validate: (d: unknown) => true,
        },
      ),
    ).toThrow(CryptoUnavailableError);
  } finally {
    if (origDesc) Object.defineProperty(environment, 'isProduction', origDesc);
    (globalThis as any).crypto = origCrypto;
  }
});
