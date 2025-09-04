// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
// Re-export a small, guarded surface of test-only helpers for consumers who need
// to run tests against the package. This file is intended for dev/test usage
// and is guarded at runtime by the same dev-guards used elsewhere in the repo.

/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return -- This file provides test-only re-exports of internal APIs that require flexible typing to access guarded internals. The use of 'any' is necessary for runtime compatibility checks and fallback access patterns in test environments, where strict typing would prevent the dynamic module introspection required for test helpers. These patterns are guarded by runtime checks (assertTestAllowed) and only active in non-production environments, minimizing security risk while enabling comprehensive testing of internal behaviors. */

import { environment } from "../../src/environment";
import { InvalidConfigurationError } from "../../src/errors";
import * as postMessageModule from "../../src/postMessage";

function assertTestAllowed(): void {
  const environmentAllow =
    typeof process !== "undefined" &&
    process?.env?.["SECURITY_KIT_ALLOW_TEST_APIS"] === "true";
  const globalAllow = !!(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  if (environment.isProduction && !environmentAllow && !globalAllow) {
    throw new InvalidConfigurationError(
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
  const pm = postMessageModule as any;
  const function_ =
    pm.__test_internals?.toNullProto ?? pm.__test_toNullProto ?? pm.toNullProto;
  if (typeof function_ !== "function")
    throw new InvalidConfigurationError(
      "toNullProto test export not available",
    );
  return function_(object, depth ?? 0, maxDepth ?? 8);
}

export function getPayloadFingerprintTest(data: unknown): Promise<string> {
  assertTestAllowed();
  const pm = postMessageModule as any;
  const function_ =
    pm.__test_internals?.getPayloadFingerprint ??
    pm.__test_getPayloadFingerprint ??
    pm.getPayloadFingerprint;
  if (typeof function_ !== "function")
    throw new InvalidConfigurationError(
      "getPayloadFingerprint test export not available",
    );
  return function_(data as any);
}

export function ensureFingerprintSaltTest(): Promise<Uint8Array> {
  assertTestAllowed();
  const pm = postMessageModule as any;
  const function_ =
    pm.__test_internals?.ensureFingerprintSalt ??
    pm.__test_ensureFingerprintSalt ??
    pm.ensureFingerprintSalt;
  if (typeof function_ !== "function")
    throw new InvalidConfigurationError(
      "ensureFingerprintSalt test export not available",
    );
  return function_();
}

export function deepFreezeTest<T>(object: T): T {
  assertTestAllowed();
  const pm = postMessageModule as any;
  const function_ =
    pm.__test_internals?.deepFreeze ?? pm.__test_deepFreeze ?? pm.deepFreeze;
  if (typeof function_ !== "function")
    throw new InvalidConfigurationError("deepFreeze test export not available");
  return function_(object);
}
