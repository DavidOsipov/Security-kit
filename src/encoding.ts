// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Shared text encoding utilities to reduce bundle size and memory allocation.
 * @module
 */

/**
 * Shared TextEncoder instance for UTF-8 encoding.
 * Reusing the same instance reduces memory allocation and bundle size.
 */
export const SHARED_ENCODER = new TextEncoder();

/**
 * Shared TextDecoder instance for UTF-8 decoding.
 * Reusing the same instance reduces memory allocation and bundle size.
 */
export const SHARED_DECODER = new TextDecoder();
