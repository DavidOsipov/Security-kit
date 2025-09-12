// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Neutral logger facade to break circular dependencies between utils and state.
 * This provides a no-op logger by default, which can be replaced with secureDevLog.
 */

export type DevelopmentLogger = (
  level: "debug" | "info" | "warn" | "error",
  component: string,
  message: string,
  context?: unknown,
) => void;

// Default no-op logger to avoid side effects on import
// explicit no-op to satisfy lint rule and avoid swallowing behavior
export const developmentLog: DevelopmentLogger = () => {
  void 0;
};

export function setDevelopmentLogger(_function_: DevelopmentLogger): void {
  // This function is kept for API compatibility
  // Logger initialization is now handled lazily where it's used
}

// Provide backward compatibility aliases
export const developmentLog_ = developmentLog;
export const setDevelopmentLogger_ = setDevelopmentLogger;
