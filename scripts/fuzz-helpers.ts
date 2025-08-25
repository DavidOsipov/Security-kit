import * as crypto from "crypto";

export function safeUrlForImport(u: string) {
  try {
    const parsed = new URL(u);
    // Allow only file: or http(s): imports in this script
    if (
      parsed.protocol === "file:" ||
      parsed.protocol === "http:" ||
      parsed.protocol === "https:"
    )
      return u;
  } catch {
    // invalid URL - treat as unsafe
  }
  return undefined;
}

export async function safeImport(url: string) {
  const safe = safeUrlForImport(url as string);
  if (!safe) throw new Error("Unsafe import URL");
  // eslint-disable-next-line no-unsanitized/method
  return import(safe);
}

export function randomString(len = 6) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const buf = Buffer.alloc(len);
  crypto.randomFillSync(buf);
  let s = "";
  for (let i = 0; i < len; i++) {
    // buf is a local Buffer filled by crypto.randomFillSync; this index usage is safe.
    // eslint-disable-next-line security/detect-object-injection
    const idx = buf[i] % chars.length;
    s += chars.charAt(idx);
  }
  return s;
}

export function makeHostilePayload(i: number) {
  const buf = Buffer.alloc(1);
  crypto.randomFillSync(buf);
  const r = buf[0] / 256;
  if (r < 0.2) {
    return { __proto__: { hacked: i } } as any;
  }
  if (r < 0.4) {
    const o: any = { a: 1 };
    const s = Symbol(randomString());
    // eslint-disable-next-line security/detect-object-injection
    o[s] = { evil: i };
    return o;
  }
  if (r < 0.6) {
    const o: any = { a: 1 };
    Object.defineProperty(o, "b", {
      get() {
        throw new Error("hostile getter");
      },
      enumerable: true,
    });
    return o;
  }
  if (r < 0.8) {
    const o: any = { nested: {} };
    o.nested.deep = { __proto__: { p: i } } as any;
    return o;
  }
  const a: any = { x: 1 };
  a.self = a;
  return a;
}

export default { safeUrlForImport, safeImport, randomString, makeHostilePayload };
