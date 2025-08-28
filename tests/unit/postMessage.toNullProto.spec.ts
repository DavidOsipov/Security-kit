import * as postMessage from '../../src/postMessage';

describe('postMessage toNullProto and fingerprint canonicalization fallback', () => {
  beforeEach(() => {
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
    postMessage.__test_resetForUnitTests();
  });
  afterEach(() => {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    postMessage.__test_resetForUnitTests();
  });

  test('toNullProto produces null-prototype objects and preserves values', () => {
    const src = { a: 1, b: { c: 2 } };
    const converted = postMessage.__test_toNullProto(src) as Record<string, unknown>;
    expect(converted).not.toBe(src);
    expect(Object.getPrototypeOf(converted)).toBeNull();
    expect((converted.b as Record<string, unknown>).c).toBe(2);
  });

  test('getPayloadFingerprint falls back when canonicalization fails (deep)', async () => {
    // Build a deep non-circular object that exceeds POSTMESSAGE_MAX_PAYLOAD_DEPTH
    let deep: any = { v: 0 };
    const root = deep;
    for (let i = 0; i < 20; i++) deep = (deep.next = { v: i + 1 });
    const fp = await postMessage.__test_getPayloadFingerprint(root);
    expect(typeof fp).toBe('string');
    expect(fp.length).toBeGreaterThan(0);
  });
});
