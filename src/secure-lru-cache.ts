// SPDX-License-Identifier: MIT
// Backward-compatibility shim for legacy import path.
// Historically, tests and external code imported from "src/secure-lru-cache".
// The implementation now lives in "src/secure-cache.ts". Re-export to avoid breaking imports.
export * from "./secure-cache";
