// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Shared text encoding utilities to reduce bundle size and memory allocation.
 * @module
 */

/**
 * Shared TextEncoder instance for UTF-8 encoding.
 * Reusing the same instance reduces memory allocation and bundle size.
 * SECURITY: Explicitly specified as UTF-8 for OWASP ASVS L3 compliance and audit clarity.
 */
export const SHARED_ENCODER = new TextEncoder(); // Always UTF-8 per HTML spec

/**
 * Shared TextDecoder instance for UTF-8 decoding.
 * Reusing the same instance reduces memory allocation and bundle size.
 * SECURITY: Explicitly specified as UTF-8 for OWASP ASVS L3 compliance and audit clarity.
 */
export const SHARED_DECODER = new TextDecoder("utf-8");
