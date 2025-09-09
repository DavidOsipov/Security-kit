import { describe, it, expect, beforeEach } from "vitest";

import {
  secureWipeOrThrow,
  secureWipeAsyncOrThrow,
  __setSecureWipeImplForTests,
  __setSharedArrayBufferViewDetectorForTests,
} from "../../src/utils";
import { CryptoUnavailableError } from "../../src/errors";

describe("utils – throwing wipe variants", () => {
  beforeEach(() => {
    __setSecureWipeImplForTests();
    __setSharedArrayBufferViewDetectorForTests();
  });

  it("secureWipeOrThrow succeeds when wipe succeeds", () => {
    const u = new Uint8Array(8);
    __setSecureWipeImplForTests(() => true);
    expect(() => secureWipeOrThrow(u)).not.toThrow();
  });

  it("secureWipeOrThrow throws when wipe fails (simulated via SAB detection)", () => {
    const u = new Uint8Array(8);
    __setSharedArrayBufferViewDetectorForTests(() => true);
    expect(() => secureWipeOrThrow(u)).toThrow(CryptoUnavailableError);
  });

  it("secureWipeAsyncOrThrow resolves when async wipe succeeds", async () => {
    const u = new Uint8Array(8);
    __setSecureWipeImplForTests(() => true);
    await expect(secureWipeAsyncOrThrow(u)).resolves.toBeUndefined();
  });

  it("secureWipeAsyncOrThrow rejects when async wipe fails (simulated via SAB detection)", async () => {
    const u = new Uint8Array(8);
    __setSharedArrayBufferViewDetectorForTests(() => true);
    await expect(secureWipeAsyncOrThrow(u)).rejects.toBeInstanceOf(
      CryptoUnavailableError,
    );
  });
});
