Security Review Checklist

When submitting security-sensitive changes, follow this checklist and include it in your PR description.

1. Reference the relevant project pillar from `docs/Constitutions/`.
2. Threat model summary: what attacker capabilities are addressed?
3. Input validation: list all inputs and how they are validated or sanitized.
4. Memory hygiene: any buffers containing secrets must be wiped in a `finally` block — include tests to prove this.
5. Performance & DoS: demonstrate iteration caps or circuit breakers for loops that depend on untrusted input.
6. Tests: include unit, adversarial, and (if relevant) performance tests.
7. Migration notes: mention backward-incompatible behavior and provide migration steps.

The reviewer will verify these items before merging.
