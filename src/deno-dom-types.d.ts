// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Additional DOM types for Deno that aren't included in standard DOM lib
 * This provides TrustedTypes support and other missing browser APIs
 */

// TrustedTypes API (experimental but needed for security)
declare global {
  interface TrustedHTML {
    readonly toString: () => string;
  }

  interface TrustedTypePolicy {
    readonly name: string;
    readonly createHTML: (input: string) => TrustedHTML;
  }

  interface TrustedTypePolicyFactory {
    createPolicy(
      policyName: string,
      policyOptions?: {
        readonly createHTML?: (input: string) => string | TrustedHTML;
      },
    ): TrustedTypePolicy;
  }

  // Extend globalThis with TrustedTypes
  var trustedTypes: TrustedTypePolicyFactory | undefined;
}

// Export empty to make this a module
export {};
