import { expect, test } from "vitest";
import {
  isLikelyBase64,
  isLikelyBase64Url,
  base64ToBytes,
  bytesToBase64,
} from "../../src/encoding-utils";

test("padded base64 is accepted and decodes to same bytes as unpadded base64url", () => {
  // Example bytes for "hello world"
  const raw = new TextEncoder().encode("hello world");
  const padded = bytesToBase64(raw); // standard base64, padded

  // create base64url variant (unpadded)
  const url = padded
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  // validators
  expect(isLikelyBase64(padded)).toBe(true);
  expect(isLikelyBase64Url(url)).toBe(true);

  // decoding both should yield identical bytes
  const fromPadded = base64ToBytes(padded);
  const fromUrl = base64ToBytes(url);
  expect(Array.from(fromPadded)).toEqual(Array.from(fromUrl));
});
import { test, expect } from "vitest";
import {
  isLikelyBase64,
  isLikelyBase64Url,
  base64ToBytes,
} from "../../src/encoding-utils";

test("base64 vs base64url padding behavior", () => {
  const padded = "YWJjZA=="; // 'abcd' padded base64
  const unpaddedUrl = "YWJjZA"; // same data, no padding
  const urlSafe = "YWJjZA"; // still matches base64url char set

  expect(isLikelyBase64(padded)).toBe(true);
  expect(isLikelyBase64Url(padded)).toBe(false); // padded base64 contains '='

  expect(isLikelyBase64(unpaddedUrl)).toBe(true);
  expect(isLikelyBase64Url(unpaddedUrl)).toBe(true);

  // normalized should decode to same bytes
  const b1 = base64ToBytes(padded);
  const b2 = base64ToBytes(unpaddedUrl);
  expect(b1).toEqual(b2);
});
