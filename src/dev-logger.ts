// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Neutral logger facade to break circular dependencies between utils and state.
 * This provides a no-op logger by default, which can be replaced with secureDevLog.
 */

export type DevLogger = (
  level: "debug" | "info" | "warn" | "error",
  component: string,
  message: string,
  context?: unknown,
) => void;

// eslint-disable-next-line functional/no-let -- Logger facade must be assignable for replacement
export let devLog: DevLogger = () => {};

export function setDevLogger(function_: DevLogger): void {
  devLog = function_;
}
