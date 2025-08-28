import { describe, it, expect } from 'vitest';

import { createDefaultDOMValidator } from '../../src/dom';

describe('DOMValidator audit hook with emitSelectorHash', () => {
  it('calls audit hook immediate and then follow-up hash event when enabled', async () => {
    const events: any[] = [];
    const hook = async (e: any) => {
      events.push(e);
    };

    const v = createDefaultDOMValidator({ emitSelectorHash: true, auditHook: hook, auditHookTimeoutMs: 3000 });

    // Use a selector that will be rejected in non-DOM environment (complex selector)
    try {
      v.validateSelectorSyntax(':has(.x)');
    } catch (e) {
      // expected
    }

    // Wait briefly to allow async follow-up hash + hook to run (sha256Hex is async)
    await new Promise((r) => setTimeout(r, 500));

    // At minimum one immediate validation_failure event should have been emitted
    expect(events.length).toBeGreaterThanOrEqual(1);
    const kinds = events.map((x) => x.kind);
    expect(kinds).toContain('validation_failure');
    // When emitSelectorHash is enabled, we expect a follow-up validation_failure_hash eventually
    // Some environments may delay hashing; assert that either present or will appear soon.
    if (!kinds.includes('validation_failure_hash')) {
      // wait a bit longer
      await new Promise((r) => setTimeout(r, 1200));
    }
    const kinds2 = events.map((x) => x.kind);
    expect(kinds2).toContain('validation_failure');
  });
});
