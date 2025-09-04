// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
// Backward-compatibility shim for legacy import path.
// Historically, tests and external code imported from "src/secure-lru-cache".
// The implementation now lives in "src/secure-cache.ts". Re-export to avoid breaking imports.
export * from "./secure-cache";
