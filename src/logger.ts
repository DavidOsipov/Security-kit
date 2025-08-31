// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Optional ergonomic wrapper for secureDevLog, providing a factory-based API.
 * This is purely syntactic sugar and forwards all calls to secureDevLog.
 * @module
 */

import { secureDevLog as secureDevelopmentLog } from "./utils";
import { environment } from "./environment";

export type LogLevel = "debug" | "info" | "warn" | "error";

/**
 * Creates a logger instance for a specific component.
 * This is optional sugar over secureDevLog; all security logic remains in secureDevLog.
 * @param component The component name for logging.
 * @returns A logger object with methods for different log levels.
 */
export function createLogger(component: string) {
  const log = (level: LogLevel, message: string, context?: unknown) => {
    if (environment.isProduction) return;
    secureDevelopmentLog(level, component, message, context);
  };
  return {
    debug: (message: string, context?: unknown) =>
      log("debug", message, context),

    info: (message: string, context?: unknown) => log("info", message, context),

    warn: (message: string, context?: unknown) => log("warn", message, context),

    error: (message: string, context?: unknown) =>
      log("error", message, context),

    child: (sub: string) => createLogger(`${component}:${sub}`),
  };
}
