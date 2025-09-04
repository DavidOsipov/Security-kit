// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * A build-time flag for dead code elimination of test-only exports.
 * Consumers of this library should configure their bundler (e.g., Vite, webpack)
 * to define this global constant as `true` in test builds and `false` in production.
 * This ensures that test helpers are completely removed from production bundles.
 *
 * @example Vite config (`vite.config.ts`):
 * ```
 * export default defineConfig({
 *   define: {
 *     __TEST__: process.env.NODE_ENV === 'test',
 *   },
 * });
 * ```
 */
declare const __TEST__: boolean | undefined;
