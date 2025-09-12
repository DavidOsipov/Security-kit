// SPDX-License-Identifier: LGPL-3.0-or-later
// Tests for postMessage parsing hardening: JSON textual byte cap and payload depth cap.
// These tests assert that oversized or overly deep payloads are dropped (handler not invoked)
// while a normal small payload is accepted.

import { describe, it, expect, vi } from 'vitest';
import { createSecurePostMessageListener } from '../../src/postMessage.ts';
import {
  getPostMessageConfig,
  setPostMessageConfig,
} from '../../src/config.ts';

// Helper to obtain current origin in jsdom / browser-like environment.
function currentOrigin(): string {
  try {
    const loc = (globalThis as Record<string, unknown>).location as { origin?: string } | undefined;
    return loc?.origin ?? 'http://localhost';
  } catch {
    return 'http://localhost';
  }
}

// Helper to safely obtain a stable source object for MessageEvent dispatch without using `any`.
// In jsdom there is a `window` object; in other runtimes we fall back to `globalThis`.
function currentSource(): MessageEventSource | null {
  const g = globalThis as Record<string, unknown>;
  const maybeWindow = g.window;
  if (maybeWindow && typeof maybeWindow === 'object') return maybeWindow as MessageEventSource;
  return null;
}

// Craft a nested object exceeding the configured depth.
function makeNestedObject(depth: number): unknown {
  // eslint-disable-next-line functional/no-let -- local construction for test helper
  let obj: Record<string, unknown> = { leaf: true };
  for (let i = 0; i < depth; i += 1) {
    obj = { wrap: obj };
  }
  return obj;
}

describe('postMessage hardening limits', () => {
  it('honors reduced maxJsonTextBytes override', () => {
    const original = getPostMessageConfig();
    const smallCap = 512; // below default 64KiB
    setPostMessageConfig({ maxJsonTextBytes: smallCap });
    try {
      const raw = 'z'.repeat(smallCap + 10);
      const json = JSON.stringify(raw);
      const handler = vi.fn();
      const listener = createSecurePostMessageListener({
        allowedOrigins: [currentOrigin()],
        onMessage: handler,
        validate: () => true,
        wireFormat: 'json',
      });
      (globalThis as unknown as { dispatchEvent: (e: Event) => boolean }).dispatchEvent(new MessageEvent('message', {
        origin: currentOrigin(),
        data: json,
        source: currentSource(),
      }));
      expect(handler).not.toHaveBeenCalled();
      listener.destroy();
    } finally {
      // Restore original config
      setPostMessageConfig({
        maxJsonTextBytes: original.maxJsonTextBytes,
      });
    }
  });

  it('honors reduced maxPayloadDepth override (structured path)', () => {
    const original = getPostMessageConfig();
    const newDepth = 2; // very small
    setPostMessageConfig({ maxPayloadDepth: newDepth });
    try {
      // Build nested object depth 4 (exceeds new depth)
      const tooDeep = makeNestedObject(4);
      const handler = vi.fn();
      const listener = createSecurePostMessageListener({
        allowedOrigins: [currentOrigin()],
        onMessage: handler,
        validate: () => true,
        wireFormat: 'structured',
      });
      (globalThis as unknown as { dispatchEvent: (e: Event) => boolean }).dispatchEvent(new MessageEvent('message', {
        origin: currentOrigin(),
        data: tooDeep,
        source: currentSource(),
      }));
      expect(handler).not.toHaveBeenCalled();
      listener.destroy();
    } finally {
      setPostMessageConfig({
        maxPayloadDepth: original.maxPayloadDepth,
      });
    }
  });
  it('drops JSON payloads that exceed maxPayloadBytes but are below textual cap', () => {
    const cfg = getPostMessageConfig();
    // Build a JSON string just beyond maxPayloadBytes but below textual cap.
    const targetOver = Math.min(cfg.maxPayloadBytes + 512, cfg.maxJsonTextBytes - 1);
    const raw = 'x'.repeat(targetOver); // ASCII => byteLength == length
    const json = JSON.stringify(raw);

    const handler = vi.fn();
    const listener = createSecurePostMessageListener({
      allowedOrigins: [currentOrigin()],
      onMessage: handler,
      validate: () => true,
      wireFormat: 'json',
    });

    (globalThis as unknown as { dispatchEvent: (e: Event) => boolean }).dispatchEvent(new MessageEvent('message', {
      origin: currentOrigin(),
      data: json,
      source: currentSource(),
    }));

    // Oversized payload should be rejected silently (no handler invocation)
    expect(handler).not.toHaveBeenCalled();
    listener.destroy();
  });

  it('drops JSON payloads that exceed textual JSON byte limit', () => {
    const cfg = getPostMessageConfig();
    // Ensure we exceed maxJsonTextBytes explicitly.
    const over = cfg.maxJsonTextBytes + 512;
    const raw = 'y'.repeat(over);
    const json = JSON.stringify(raw);

    const handler = vi.fn();
    const listener = createSecurePostMessageListener({
      allowedOrigins: [currentOrigin()],
      onMessage: handler,
      validate: () => true,
      wireFormat: 'json',
    });

    (globalThis as unknown as { dispatchEvent: (e: Event) => boolean }).dispatchEvent(new MessageEvent('message', {
      origin: currentOrigin(),
      data: json,
      source: currentSource(),
    }));

    expect(handler).not.toHaveBeenCalled();
    listener.destroy();
  });

  it('drops JSON payloads whose structure exceeds depth cap', () => {
    const cfg = getPostMessageConfig();
    const tooDeep = cfg.maxPayloadDepth + 1;
    const nested = makeNestedObject(tooDeep);
    const json = JSON.stringify(nested);

    const handler = vi.fn();
    const listener = createSecurePostMessageListener({
      allowedOrigins: [currentOrigin()],
      onMessage: handler,
      validate: () => true,
      wireFormat: 'json',
    });

    (globalThis as unknown as { dispatchEvent: (e: Event) => boolean }).dispatchEvent(new MessageEvent('message', {
      origin: currentOrigin(),
      data: json,
      source: currentSource(),
    }));

    expect(handler).not.toHaveBeenCalled();
    listener.destroy();
  });

  it('accepts a small valid JSON payload within limits and depth', () => {
    const payload = { ok: true, value: 'test' };
    const json = JSON.stringify(payload);

    const handler = vi.fn();
    const listener = createSecurePostMessageListener({
      allowedOrigins: [currentOrigin()],
      onMessage: handler,
  validate: (d: unknown): d is { ok: true; value?: unknown } => typeof d === 'object' && d !== null && (d as Record<string, unknown>).ok === true,
      wireFormat: 'json',
    });

    (globalThis as unknown as { dispatchEvent: (e: Event) => boolean }).dispatchEvent(new MessageEvent('message', {
      origin: currentOrigin(),
      data: json,
      source: currentSource(),
    }));

    expect(handler).toHaveBeenCalledTimes(1);
    listener.destroy();
  });
});
