import { test, expect } from 'vitest';
import { createSecurePostMessageListener } from '../../src/postMessage';

test('expectedSource comparator returning false drops message', () => {
  const received: unknown[] = [];
  const listener = createSecurePostMessageListener(
    {
      allowedOrigins: [location.origin],
      onMessage: (d) => received.push(d),
      validate: () => true,
      expectedSource: (s: unknown) => false,
    },
  );

  const ev = new MessageEvent('message', { data: JSON.stringify({ a: 1 }), origin: location.origin, source: window as any });
  window.dispatchEvent(ev);
  listener.destroy();
  expect(received.length).toBe(0);
});

test('expectedSource comparator throwing drops message', () => {
  const received: unknown[] = [];
  const listener = createSecurePostMessageListener(
    {
      allowedOrigins: [location.origin],
      onMessage: (d) => received.push(d),
      validate: () => true,
      expectedSource: () => { throw new Error('boom'); },
    },
  );

  const ev = new MessageEvent('message', { data: JSON.stringify({ b: 2 }), origin: location.origin, source: window as any });
  window.dispatchEvent(ev);
  listener.destroy();
  expect(received.length).toBe(0);
});

test('expectedSource reference mismatch drops message', () => {
  const received: unknown[] = [];
  const other = {};
  const listener = createSecurePostMessageListener(
    {
      allowedOrigins: [location.origin],
      onMessage: (d) => received.push(d),
      validate: () => true,
      expectedSource: other as any,
    },
  );

  const ev = new MessageEvent('message', { data: JSON.stringify({ c: 3 }), origin: location.origin, source: window as any });
  window.dispatchEvent(ev);
  listener.destroy();
  expect(received.length).toBe(0);
});

test('deepFreeze budget exceeded does not prevent delivery', () => {
  const received: unknown[] = [];
  // create a wide object (many sibling properties) so deepFreeze visits many nodes
  const nested: Record<string, unknown> = {};
  for (let i = 0; i < 200; i++) {
    nested[`k${i}`] = { i };
  }

  const listener = createSecurePostMessageListener(
    {
      allowedOrigins: [location.origin],
      onMessage: (d) => received.push(d),
      validate: () => true,
      freezePayload: true,
      deepFreezeNodeBudget: 1, // intentionally tiny to trigger budget exceed
    },
  );

  const ev = new MessageEvent('message', { data: JSON.stringify(nested), origin: location.origin, source: window as any });
  window.dispatchEvent(ev);
  listener.destroy();

  // message should still be delivered even if deepFreeze budget was exceeded
  expect(received.length).toBeGreaterThanOrEqual(1);
  if (received.length > 0) {
    expect(typeof received[0]).toBe('object');
  }
});
