export function makeDeterministicStub(bytes: number[] | number = [10]) {
  // Returns a Crypto-like object whose getRandomValues returns provided bytes
  return {
    getRandomValues(arr: Uint8Array) {
      const src = Array.isArray(bytes) ? bytes : [bytes];
      for (let i = 0; i < arr.length; i++) arr[i] = src[i % src.length];
      return arr;
    },
    randomUUID: () => "00000000-0000-4000-8000-000000000000",
    subtle: {},
  } as unknown as Crypto;
}

export function makeAll255Stub() {
  return {
    getRandomValues(arr: Uint8Array) {
      for (let i = 0; i < arr.length; i++) arr[i] = 0xff;
      return arr;
    },
    randomUUID: () => "ffffffff-ffff-4fff-bfff-ffffffffffff",
    subtle: {},
  } as unknown as Crypto;
}
