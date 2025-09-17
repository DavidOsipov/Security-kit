// Deno vs Node.js crypto performance benchmark
import { generateSecureIdSync } from "../../src/crypto.ts";

Deno.bench("generateSecureIdSync - 32 bytes", () => {
  generateSecureIdSync({ length: 32 });
});

Deno.bench("generateSecureIdSync - 64 bytes", () => {
  generateSecureIdSync({ length: 64 });
});

Deno.bench("Web Crypto getRandomValues", () => {
  crypto.getRandomValues(new Uint8Array(32));
});