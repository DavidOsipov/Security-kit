// SPDX-License-Identifier: MIT
// Re-export a small, guarded surface of test-only helpers for consumers who need
// to run tests against the package. This file is intended for dev/test usage
// and is guarded at runtime by the same dev-guards used elsewhere in the repo.

import { environment } from "./environment";
import { sanitizeErrorForLogs } from "./errors";
import * as postMessageModule from "./postMessage";

function assertTestAllowed(): void {
  const environmentAllow =
    typeof process !== "undefined" &&
    process?.env?.["SECURITY_KIT_ALLOW_TEST_APIS"] === "true";
  const globalAllow = !!(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  if (environment.isProduction && !environmentAllow && !globalAllow) {
    throw new Error(
      "Test internals not allowed in production. Set SECURITY_KIT_ALLOW_TEST_APIS or set global flag.",
    );
  }
}

export function toNullProtoTest(
  object: unknown,
  depth?: number,
  maxDepth?: number,
): unknown {
  assertTestAllowed();
  return (postMessageModule as any).toNullProto(
    object,
    depth ?? 0,
    maxDepth ?? 8,
  );
}

export function getPayloadFingerprintTest(data: unknown): Promise<string> {
  assertTestAllowed();
  return (postMessageModule as any).getPayloadFingerprint(data as any);
}

export function ensureFingerprintSaltTest(): Promise<Uint8Array> {
  assertTestAllowed();
  return (postMessageModule as any).ensureFingerprintSalt();
}

export function deepFreezeTest<T>(object: T): T {
  assertTestAllowed();
  return (postMessageModule as any).deepFreeze(object);
}
