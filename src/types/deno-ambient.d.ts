// Ambient declaration to satisfy Node type builds when Deno global is probed.
// This file provides a minimal structural typing surface; no runtime impact.
// Kept intentionally narrow to avoid masking real API differences.
// OWASP ASVS L3: reduces build-time errors without weakening runtime checks.

// deno-lint-ignore-file
declare global {
  // Minimal subset used: env.get

  var Deno:
    | undefined
    | {
        readonly env?: {
          get(key: string): string | undefined;
        };
      };
}
export {};
