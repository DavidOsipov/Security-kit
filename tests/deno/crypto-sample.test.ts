// Sample migrated test showing Vitest -> Deno.test conversion
import { describe, it, assertEquals } from "../helpers/deno-test-utils.ts";
import { generateSecureIdSync } from "../../src/crypto.ts";

describe("crypto migration sample", () => {
  it("should generate secure IDs", () => {
    const id1 = generateSecureIdSync(32);
    const id2 = generateSecureIdSync(32);
    
    assertEquals(id1.length, 32);
    assertEquals(id2.length, 32);
    assertEquals(id1 === id2, false); // Should be unique
  });
});