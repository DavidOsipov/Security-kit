# Secure postMessage utilities

This document explains the hardened `postMessage` helpers provided by Security-kit and shows recommended usage patterns.

These helpers aim to enforce the principles of the project's Security & Engineering Constitution: positive validation, least privilege, defense-in-depth, and privacy-preserving diagnostics.

## Exports

- `sendSecurePostMessage(options: { targetWindow: Window; payload: unknown; targetOrigin: string })`
- `createSecurePostMessageListener(allowedOriginsOrOptions, onMessage?)`

## Quick example (sender)

```ts
import { sendSecurePostMessage } from "../src/postMessage";

const iframe = document.querySelector("iframe#app") as HTMLIFrameElement;
if (!iframe?.contentWindow) throw new Error("iframe missing");

sendSecurePostMessage({
  targetWindow: iframe.contentWindow,
  targetOrigin: "https://app.example.com",
  payload: { type: "user.update", data: { id: "u123" } },
});
```

Notes:

- `targetOrigin` must be an absolute origin (e.g., `https://app.example.com`). Non-HTTPS origins are rejected except for `localhost`/`127.0.0.1`.
- `payload` must be JSON-serializable and is size-limited.

## Quick example (receiver)

```ts
import { createSecurePostMessageListener } from "../src/postMessage";

const listener = createSecurePostMessageListener({
  allowedOrigins: ["https://app.example.com"],
  onMessage: (msg) => {
    // msg is a null-prototype object and deep-frozen (immutable)
    handleIncoming(msg);
  },
  // Validator: positive allowlist for messages
  validate: { type: "string", data: "object" },
  // Reject any extra unexpected properties by default
  allowExtraProps: false,
  // Optional: bind to an expected Window reference for extra safety
  // expectedSource: iframe.contentWindow,
  // Diagnostics disabled by default — enable only for debugging
  // enableDiagnostics: true,
});

// Later when done
// listener.destroy();
```

## Listener options (detailed)

- `allowedOrigins: string[]` — absolute origins. Required. Must be `https:` for production.
- `onMessage: (data: unknown) => void` — required callback. Receives sanitized (null-prototype), deep-frozen payload.
- `validate?: ((d: unknown) => boolean) | Record<string, 'string'|'number'|'boolean'|'object'|'array'>` — strongly recommended. If a schema object is provided, each key must be present and match the specified type.
- `allowExtraProps?: boolean` — when using a schema, set to `true` to allow additional properties. Default: `false`.
- `expectedSource?: Window | MessagePort` — additional defensive binding to ensure `event.source === expectedSource`.
- `allowOpaqueOrigin?: boolean` — whether to accept `origin === 'null'`. Default: `false`.
- `enableDiagnostics?: boolean` — when `true`, failed validation events may include a salted fingerprint to aid debugging. Disabled by default.

## Security rationale & best practices

1. Positive validation (allowlist) is essential. Always provide `validate` for any listener that performs security-sensitive actions.
2. Bind the listener to a specific `expectedSource` when you have the window reference. This prevents other windows on the same origin from sending messages that the listener will accept.
3. Avoid `allowOpaqueOrigin: true` if possible. Messages with `origin === 'null'` are often from data-URIs, sandboxed frames, or file:// contexts and are harder to reason about.
4. Keep `enableDiagnostics` disabled in production. Fingerprints are salted per-process and rate-limited, but logging still creates telemetry risk if mismanaged.
5. Prefer a stable envelope schema: `{ type: string, data: object, v?: number }` and check `type` values explicitly.

## Migration notes

- The module now _requires_ a validator by default. If you currently rely on `createSecurePostMessageListener` without validation, update your callers to provide a lightweight schema or validator function.
- If you have consumers that rely on accepting `origin === 'null'`, migrate them to an explicitly documented `allowOpaqueOrigin: true` configuration, and add additional checks in your `validate` function to ensure the payload shape is safe.

## Example validator

```ts
const envelopeSchema = { type: "string", data: "object" } as const;
function envelopeValidator(d: unknown) {
  // very small validator: returns true only for the expected shape
  if (!d || typeof d !== "object") return false;
  const o = d as Record<string, unknown>;
  return typeof o.type === "string" && typeof o.data === "object";
}

createSecurePostMessageListener({
  allowedOrigins: ["https://app.example.com"],
  onMessage: (m) => {
    /* ... */
  },
  validate: envelopeSchema,
});
```

## Troubleshooting

- If messages are being dropped, enable `enableDiagnostics` temporarily and reproduce the drop; examine the logged (salted) fingerprint to correlate events.
- If you see many fingerprint logs, you are likely under test spam; consider increasing or tuning the diagnostic budget locally.

## Canonical origin format & `freezePayload`

- Canonical origin format: origins are normalized to the form `protocol//hostname[:port]` with default ports removed (e.g., `https://example.com:443` becomes `https://example.com`). Hosts are lowercased and trailing slashes are ignored for allowlist matching. Use the exact canonical origin string in `allowedOrigins` to avoid mismatches.

- `freezePayload` option: listeners deep-freeze sanitized payloads by default to make them immutable before handing them to `onMessage`. High-throughput consumers can opt out by setting `freezePayload: false` in the listener options; doing so shifts responsibility for not mutating the payload to the consumer.

Keep `freezePayload` enabled unless you have measured performance impacts and accept the trade-offs.

\*\*\* End of document
