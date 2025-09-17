# URL Normalization & Telemetry Migration Guide

## Overview
This guide documents the breaking removal of legacy URL normalization helpers and the introduction of strict, purpose‑built APIs and Unicode telemetry metrics in `security-kit`.

## Removed (Breaking)
The following legacy functions have been **removed** from the public API:
- `normalizeUrlComponent`
- `normalizeUrlSafeString`

These were historically exported from `canonical.ts` and coupled high‑risk Unicode normalization with URL component semantics. This coupling increased surface area for misuse and created ambiguity about trust boundaries.

## New Strict Replacements
Use the new dedicated URL helpers from `url.ts`:

```ts
import { normalizeUrlComponentStrict, normalizeUrlSafeStringStrict } from '@david-osipov/security-kit';

const host = normalizeUrlComponentStrict('ExAmPlE.COM', 'host'); // "example.com"
const safe = normalizeUrlSafeStringStrict('https://example.com/a?q=1', 'url');
```

### `normalizeUrlComponentStrict(value, kind)`
Validates and normalizes a specific component where `kind` ∈ `scheme | host | path | query | fragment`.
- Performs NFKC normalization using the hardened canonical pipeline.
- Enforces component‑specific character policies.
- Rejects dangerous patterns (e.g., encoded traversal in `path`, invalid scheme tokens, unsafe host chars).

### `normalizeUrlSafeStringStrict(value, context, options?)`
Validates a full URL‑safe string (e.g., query value, serialized URL segment) with optional:
- `maxLength` (default 2048)
- `allowSpaces` (false by default)

Rejects characters outside a conservative RFC 3986 + controlled extension set.

## Why the Change?
| Old Approach | Risk | New Approach Benefit |
|--------------|------|----------------------|
| Generic normalization functions applied to both Unicode hardening and URL semantics | Increased risk of accidental misuse and over‑blocking | Separation of concerns, clearer intent |
| Ambiguous API allowed untrusted inputs to flow through without context‑specific constraints | Potential for Trojan Source edge cases or inconsistent validation | Explicit component typing + strict validation |
| Lack of telemetry for structural & cumulative Unicode risks | Limited observability | Metrics enable runtime monitoring and anomaly detection |

## Unicode Telemetry Metrics
Telemetry is emitted (if a telemetry hook is registered) via `emitMetric` in `utils.ts`. You can register a hook:

```ts
import { registerTelemetry } from '@david-osipov/security-kit';

registerTelemetry((name, value, tags) => {
  // Forward to your metrics backend
  console.log('[metric]', name, value, tags);
});
```

### Metric Names
| Metric | Description | Tags |
|--------|-------------|------|
| `unicode.structural.introduced` | One or more structural delimiters (e.g., `. : / ? # & | ; , + @`) were introduced during normalization that did not appear literally in the raw input. | `context` |
| `unicode.risk.total` | Aggregate Unicode risk score for an input when risk scoring enabled. | `context`, `primary` (primary threat id) |
| `unicode.risk.metric.<id>` | Individual triggered risk metric (`bidi`, `invisibles`, `combiningRun`, etc.). | `context` |

### Structural Introduction Hardening
The normalization pipeline now explicitly detects when normalization *introduces* structural delimiter characters absent from the raw string (e.g., a full‑width or confusable variant normalizing to `.`). This is logged at `warn` level in development and emits `unicode.structural.introduced` with the count of introduced characters.

## Migration Steps
1. Replace imports:
   ```diff
- import { normalizeUrlComponent, normalizeUrlSafeString } from '@david-osipov/security-kit';
+ import { normalizeUrlComponentStrict, normalizeUrlSafeStringStrict } from '@david-osipov/security-kit';
   ```
2. Update any wrapper utilities that forwarded to removed names.
3. Register a telemetry hook (optional but recommended) to observe real‑world Unicode risk patterns.
4. (If you relied on lenient behavior) Re‑test user‑supplied URLs; stricter validation may now reject borderline cases.

## Example: Secure URL Assembly
```ts
import { normalizeUrlComponentStrict } from '@david-osipov/security-kit';

function buildProfileUrl(username: unknown) {
  const safeUser = normalizeUrlComponentStrict(username, 'path');
  return `https://example.com/u/${safeUser}`;
}
```

## Observability Playbook
- Alert on spikes of `unicode.structural.introduced` — potential obfuscation attempts.
- Track distribution of `unicode.risk.total` to tune `riskWarnThreshold` / `riskBlockThreshold` if you enable scoring.
- Correlate high `mixedScriptHomoglyph` metrics with authentication or signing failures.

## Security Notes
- Always treat user input as hostile. Use `normalizeInputString` for non‑URL text fields and the strict URL helpers for URL context data.
- Do **not** re‑normalize already validated components to avoid double‑processing.
- Avoid manual regex sanitization in favor of provided helpers; they enforce Trojan Source defenses and structural risk detection.

## FAQ
**Q: Do I need to enable risk scoring to get structural metrics?**  
No. `unicode.structural.introduced` is emitted independently of the risk scoring setting.

**Q: Why didn’t I see risk metrics in development?**  
Risk scoring is disabled by default (`enableRiskScoring: false`). Enable via:
```ts
import { setUnicodeSecurityConfig } from '@david-osipov/security-kit';
setUnicodeSecurityConfig({ enableRiskScoring: true, riskWarnThreshold: 20, riskBlockThreshold: 60 });
```

**Q: Can I suppress specific metrics?**  
At present, no. Filter them in your telemetry sink if required.

## Versioning & Change Impact
This removal is a **breaking change**. Update your application code before upgrading. If distributing a library layered atop `security-kit`, bump your own major version accordingly.

## Future Enhancements (Planned)
- Optional per‑metric sampling controls.
- Extended structural mapping set for additional Unicode confusables.
- Inline diff payload for introduced structural delimiter sequences.

---
For questions or security review requests, open an issue or consult the Security Constitution.
