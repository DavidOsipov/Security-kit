# Unicode Data Integrity & Upgrade Workflow (OWASP ASVS L3)

This document defines the **controlled, auditable procedure** for updating the Unicode security data used by `Security Kit` (currently Unicode 16.0.0) while preserving supply‑chain trust and reproducibility.

> Pillars: Zero Trust & Verifiable Security • Hardened Simplicity • Provable Correctness

---
## 1. Scope
Covers the authoritative source files:
- `IdentifierStatus.txt`
- `confusablesSummary.txt`
located in: `docs/Additional security guidelines/Specifications and RFC/Unicode <VERSION>/`

These are parsed by `scripts/parse-unicode-data-optimized.ts` to generate:
- Optimized binary range & confusables profiles (`src/generated/*.bin`)
- Embedded minimal profile + integrity constants (`src/generated/unicode-embedded-data.ts`)

---
## 2. Integrity Chain Overview
| Stage | Mechanism | Fails Closed? | Purpose |
|-------|-----------|--------------|---------|
| Pre-parse | Hardcoded SHA-384 digests | YES | Prevent tainted upstream data from entering build artifacts |
| Generation | SHA-384 hashing of embedded & external binaries | YES (on regen mismatch during review) | Trace artifact provenance |
| Runtime (minimal embedded) | SHA-384 WebCrypto verification | SOFT FAIL (warn) | Detect post-publish tampering in hostile environments |
| Runtime (external profiles) | SHA-384 WebCrypto verification | SOFT FAIL (warn) | Detect CDN / transit modification |
| CI Guard | Script + unit test (`verify-unicode-digests.ts`, `unicode-digests.test.ts`) | YES | Dual implementation confirmation |

---
## 3. Upgrade Procedure (e.g., Unicode 16.0.0 → 17.0.0)
1. Preparation
   - Create new directory: `docs/.../Unicode 17.0.0/`.
   - Download upstream files ONLY from official Unicode source (HTTPS):
     - https://unicode.org/Public/17.0.0/ucd/IdentifierStatus.txt
     - https://unicode.org/Public/17.0.0/ucd/confusablesSummary.txt
   - Record retrieval metadata (UTC timestamp, URL, SHA-384) in a temporary note.

2. Verify Source Authenticity
   - Compute SHA-384 locally:
     ```bash
     sha384sum IdentifierStatus.txt confusablesSummary.txt
     ```
   - (Optional) Independently verify using a different machine / network path.
   - If hashes differ between environments → investigate before proceeding.

3. Update Hardcoded Digests
   - Open `scripts/parse-unicode-data-optimized.ts` and replace:
     ```ts
     const EXPECTED_IDENTIFIER_STATUS_SHA384 = '...';
     const EXPECTED_CONFUSABLES_SUMMARY_SHA384 = '...';
     ```
   - Update test file: `tests/unit/unicode-digests.test.ts`.
   - Update verification script: `scripts/verify-unicode-digests.ts`.

4. Regenerate Artifacts
   ```bash
   node scripts/parse-unicode-data-optimized.ts
   ```
   - Confirm new SHA-384 constants in `src/generated/unicode-embedded-data.ts`.

5. Run Integrity & Tests
   ```bash
   node scripts/verify-unicode-digests.ts
   npm run test -- --run tests/unit/unicode-digests.test.ts
   ```
   - All checks must pass.

6. Audit Diff
   - Review changes to binary `.bin` files (size deltas expected, but extreme growth requires scrutiny).
   - Inspect range count & mapping counts printed by generator for anomalies.

7. Commit & Sign
   - Use **signed commit** (`git commit -S`).
   - Commit message template:
     ```
     chore(unicode): upgrade to Unicode 17.0.0
     
     - Updated source SHA-384 digests
     - Regenerated optimized binaries & embedded data
     - Verified via dual hash implementation & unit test
     - Range count: <N> (Δ <delta>) | Confusables: <M> (Δ <delta>)
     ```

8. PR Review Checklist
   - [ ] Hardcoded digests updated in all 3 locations
   - [ ] Generator output uses SHA-384 consistently
   - [ ] Unit digest test passes
   - [ ] `verify-unicode-digests.ts` passes
   - [ ] Range count variance reasonable
   - [ ] No unrelated code bundled
   - [ ] Commit(s) signed

9. Post-Merge
   - Tag release branch with version referencing Unicode major (optional): `unicode-17.0.0-adoption`.
   - Include upgrade note in CHANGELOG / release notes.

---
## 4. Security Rationale
- SHA-384 chosen: stronger collision margin than SHA-256 with negligible performance impact at these file sizes.
- Dual implementation (Node + WebCrypto) reduces single-implementation compromise risk (logic substitution attacks).
- Fail-closed pre-parse ensures no downstream artifact pollution.
- Soft-fail runtime protects UX while still signaling tampering risk.

---
## 5. Tamper Response Playbook
| Scenario | Action |
|----------|--------|
| Digest mismatch during build | Abort; verify upstream source, network MITM, local malware. Do not override blindly. |
| Runtime mismatch reports from users | Request environment details, fetch package copy, reproduce locally; consider yanking compromised version. |
| Unexpected explosion in mapping count | Suspend release; confirm upstream spec changes; run targeted fuzz & performance tests. |

---
## 6. Future Hardening Opportunities
- Add transparency log (Sigstore / Rekor) for Unicode digest updates.
- Introduce detached signature validation (e.g., minisign) if Unicode project publishes signatures.
- Integrate mutation test ensuring integrity guard paths exercised.

---
## 7. Quick Reference Commands
```bash
# Recompute & regenerate
node scripts/parse-unicode-data-optimized.ts

# Verify dual-hash integrity
node scripts/verify-unicode-digests.ts

# Run only digest unit test
npx vitest run tests/unit/unicode-digests.test.ts
```

---
Maintainers MUST treat digest changes as a high-trust operation requiring review. Do not accept automated PRs that alter these values without provenance evidence.
