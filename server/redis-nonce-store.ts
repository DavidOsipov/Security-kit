// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
// Production-grade Redis-backed INonceStore implementation
// Requires a Redis client compatible with node-redis v4 (or ioredis with minimal changes)
// This module is optional and tree-shakable; import only if you use Redis in production.

import type { INonceStore } from "./verify-api-request-signature.ts";

/** Minimal Redis client subset used by this store. */
export type RedisLike = {
  set(
    key: string,
    value: string,
    opts: { NX?: boolean; PX?: number },
  ): Promise<"OK" | null>;
  pExpire(key: string, ttlMs: number): Promise<number>; // 1 if timeout set, 0 otherwise
  del(key: string): Promise<number>;
  exists?(key: string): Promise<number>; // optional: 1 if exists, 0 otherwise
};

/**
 * RedisNonceStore implements atomic reserve/finalize semantics.
 * Keys are namespaced as `${prefix}:${kid}:${nonce}` with PX TTLs.
 */
export class RedisNonceStore implements INonceStore {
  readonly #redis: RedisLike;
  readonly #prefix: string;

  constructor(redis: RedisLike, prefix = "nonce") {
    this.#redis = redis;
    this.#prefix = prefix;
  }

  #key(kid: string, nonce: string): string {
    return `${this.#prefix}:${kid}:${nonce}`;
  }

  has(_kid: string, _nonce: string): boolean {
    // We could use EXISTS, but we intentionally avoid additional commands to keep surface tiny.
    // Instead, reserve() or storeIfNotExists() should be used; has() is used only by legacy fallback paths.
    // Implement using PEXPIRE with PX=0 as a read check is not ideal; prefer EXISTS if available in your client.
    // For compatibility, we return false here to encourage use of atomic methods.
    // If you need has(), implement `exists(key)` on your RedisLike and wire it here.
    return false;
  }

  async store(kid: string, nonce: string, ttlMs: number): Promise<void> {
    const res = await this.#redis.set(this.#key(kid, nonce), "1", {
      PX: Math.max(1, Math.floor(ttlMs)),
    });
    if (res !== "OK")
      throw new Error("RedisNonceStore.store: failed to set key");
  }

  async storeIfNotExists(
    kid: string,
    nonce: string,
    ttlMs: number,
  ): Promise<boolean> {
    const res = await this.#redis.set(this.#key(kid, nonce), "1", {
      NX: true,
      PX: Math.max(1, Math.floor(ttlMs)),
    });
    return res === "OK";
  }

  async reserve(
    kid: string,
    nonce: string,
    reserveTtlMs: number,
  ): Promise<boolean> {
    const res = await this.#redis.set(this.#key(kid, nonce), "1", {
      NX: true,
      PX: Math.max(1, Math.floor(reserveTtlMs)),
    });
    return res === "OK";
  }

  async finalize(kid: string, nonce: string, ttlMs: number): Promise<void> {
    const updated = await this.#redis.pExpire(
      this.#key(kid, nonce),
      Math.max(1, Math.floor(ttlMs)),
    );
    if (updated !== 1)
      throw new Error("RedisNonceStore.finalize: key missing during finalize");
  }

  async delete(kid: string, nonce: string): Promise<void> {
    await this.#redis.del(this.#key(kid, nonce));
  }
}
