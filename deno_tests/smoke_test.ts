import { assert, assertEquals, assertMatch } from "jsr:@std/assert@^1";

type PublicApi = {
  generateSecureId: (len: number) => Promise<string> | string;
  generateSecureUUID: () => Promise<string> | string;
};

// Prefer Deno-first dnt output (npm/esm/mod.js); fallback to dist/index.mjs if not present
let mod: PublicApi;
try {
  mod = await import(new URL("../npm/esm/mod.js", import.meta.url).href);
} catch {
  mod = await import(new URL("../dist/index.mjs", import.meta.url).href);
}

Deno.test("deno: generateSecureId works", async () => {
  assert(typeof mod.generateSecureId === "function");
  const id = await mod.generateSecureId(32);
  assertEquals(typeof id, "string");
  assertEquals(id.length, 32);
});

Deno.test("deno: generateSecureUUID shape", async () => {
  assert(typeof mod.generateSecureUUID === "function");
  const uuid = await mod.generateSecureUUID();
  assertMatch(uuid, /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i);
});
