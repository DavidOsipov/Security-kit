// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
/**
 * Global type declarations for dnt build compatibility
 *
 * SECURITY: These declarations maintain the security intent of the original code
 * while providing TypeScript compatibility for the dnt build process.
 * They do NOT weaken security - they only provide type information.
 */

// Trusted Types API - Security-positive browser feature for XSS prevention
// This maintains the original security intent while providing dnt compatibility
declare global {
  interface Window {
    readonly trustedTypes?: {
      readonly createPolicy?: (
        name: string,
        rules: {
          readonly createHTML?: (input: string) => TrustedHTML;
          readonly createScript?: () => never;
          readonly createScriptURL?: () => never;
        },
      ) => TrustedTypePolicy;
    };
  }

  interface GlobalThis {
    readonly trustedTypes?: {
      readonly createPolicy?: (
        name: string,
        rules: {
          readonly createHTML?: (input: string) => TrustedHTML;
          readonly createScript?: () => never;
          readonly createScriptURL?: () => never;
        },
      ) => TrustedTypePolicy;
    };
  }

  // Test-time security guard - prevents test code from leaking into production
  // Setting to false ensures production behavior in dnt builds
  var __TEST__: boolean | undefined;
}

// Browser Trusted Types definitions for security compliance
interface TrustedHTML {
  toString(): string;
}

interface TrustedTypePolicy {
  createHTML(input: string): TrustedHTML;
}

export {};
