import { describe, it, expect } from "vitest";
import { toCanonicalValue, safeStableStringify } from "../../src/canonical.js";
import { InvalidParameterError } from "../../src/errors.js";

describe("canonical", () => {
  describe("toCanonicalValue", () => {
    it("preserves null distinctly from undefined", () => {
      expect(toCanonicalValue(null)).toBe(null);
      expect(toCanonicalValue(undefined)).toBe(undefined);
    });

    it("handles primitive types correctly", () => {
      expect(toCanonicalValue("string")).toBe("string");
      expect(toCanonicalValue(true)).toBe(true);
      expect(toCanonicalValue(false)).toBe(false);
      expect(toCanonicalValue(42)).toBe(42);
      expect(toCanonicalValue(3.14)).toBe(3.14);
    });

    it("converts non-finite numbers to undefined", () => {
      expect(toCanonicalValue(NaN)).toBe(undefined);
      expect(toCanonicalValue(Infinity)).toBe(undefined);
      expect(toCanonicalValue(-Infinity)).toBe(undefined);
    });

    it("throws InvalidParameterError for BigInt values", () => {
      expect(() => toCanonicalValue(42n)).toThrow(InvalidParameterError);
      expect(() => toCanonicalValue(BigInt(123))).toThrow(
        InvalidParameterError,
      );
    });

    it("converts functions and symbols to undefined", () => {
      expect(toCanonicalValue(() => {})).toBe(undefined);
      expect(toCanonicalValue(Symbol("test"))).toBe(undefined);
    });

    it("converts Date objects to ISO strings", () => {
      const date = new Date("2023-01-01T00:00:00.000Z");
      expect(toCanonicalValue(date)).toBe("2023-01-01T00:00:00.000Z");
    });

    it("canonicalizes arrays recursively", () => {
      const arr = [1, "string", null, undefined, NaN];
      const result = toCanonicalValue(arr);
      expect(result).toEqual([1, "string", null, undefined, undefined]);
    });

    it("canonicalizes nested arrays", () => {
      const nested = [1, [2, 3], [4, [5, 6]]];
      const result = toCanonicalValue(nested);
      expect(result).toEqual([1, [2, 3], [4, [5, 6]]]);
    });

    it("canonicalizes objects with sorted keys", () => {
      const obj = { z: 1, a: 2, m: 3 };
      const result = toCanonicalValue(obj);
      expect(result).toEqual({ a: 2, m: 3, z: 1 });
    });

    it("filters forbidden keys from objects", () => {
      const obj = {
        normalKey: "value",
        __proto__: "forbidden",
        constructor: "forbidden",
        prototype: "forbidden",
        anotherKey: "anotherValue",
      };
      const result = toCanonicalValue(obj);
      expect(result).toEqual({
        anotherKey: "anotherValue",
        normalKey: "value",
      });
    });

    it("handles circular references", () => {
      const obj: any = { a: 1 };
      obj.self = obj;
      const result = toCanonicalValue(obj);
      expect(result).toEqual({ a: 1, self: { __circular: true } });
    });

    it("handles complex nested objects", () => {
      const complex = {
        users: [
          { id: 1, name: "Alice", active: true },
          { id: 2, name: "Bob", active: false },
        ],
        metadata: {
          version: "1.0",
          timestamp: new Date("2023-01-01T00:00:00.000Z"),
          config: {
            debug: true,
            features: ["auth", "crypto"],
          },
        },
        stats: {
          total: 100,
          processed: 75,
        },
      };

      const result = toCanonicalValue(complex);
      expect(result).toEqual({
        metadata: {
          config: {
            debug: true,
            features: ["auth", "crypto"],
          },
          timestamp: "2023-01-01T00:00:00.000Z",
          version: "1.0",
        },
        stats: {
          processed: 75,
          total: 100,
        },
        users: [
          { active: true, id: 1, name: "Alice" },
          { active: false, id: 2, name: "Bob" },
        ],
      });
    });

    it("handles empty objects and arrays", () => {
      expect(toCanonicalValue({})).toEqual({});
      expect(toCanonicalValue([])).toEqual([]);
    });

    it("handles mixed types in arrays", () => {
      const mixed = [1, "string", true, null, undefined, { a: 1 }, [2, 3]];
      const result = toCanonicalValue(mixed);
      expect(result).toEqual([
        1,
        "string",
        true,
        null,
        undefined,
        { a: 1 },
        [2, 3],
      ]);
    });

    it("handles RegExp and other objects", () => {
      const regex = /test/;
      const result = toCanonicalValue(regex);
      expect(result).toEqual({}); // RegExp objects become empty objects when canonicalized
    });

    it("handles other object types with fallback", () => {
      // Create a custom object that doesn't match typical patterns
      const customObj = Object.create(null);
      customObj.customProp = "value";
      const result = toCanonicalValue(customObj);
      expect(result).toEqual({ customProp: "value" });
    });

    it("handles negative zero correctly", () => {
      expect(toCanonicalValue(-0)).toBe(-0);
      expect(toCanonicalValue(0)).toBe(0);
      // Test that -0 and 0 are treated as distinct in canonical form
      expect(Object.is(toCanonicalValue(-0), -0)).toBe(true);
      expect(Object.is(toCanonicalValue(0), 0)).toBe(true);
    });

    it("handles very large numbers", () => {
      expect(toCanonicalValue(Number.MAX_VALUE)).toBe(Number.MAX_VALUE);
      expect(toCanonicalValue(Number.MIN_VALUE)).toBe(Number.MIN_VALUE);
      expect(toCanonicalValue(Number.MAX_SAFE_INTEGER)).toBe(
        Number.MAX_SAFE_INTEGER,
      );
      expect(toCanonicalValue(Number.MIN_SAFE_INTEGER)).toBe(
        Number.MIN_SAFE_INTEGER,
      );
    });

    it("handles exotic objects that should become empty", () => {
      // Test various built-in objects that should canonicalize to empty objects
      expect(toCanonicalValue(new RegExp("test"))).toEqual({});
      const now = new Date();
      expect(toCanonicalValue(now)).toBe(now.toISOString()); // Date is special-cased
      expect(toCanonicalValue(new Error("test"))).toEqual({});
      expect(toCanonicalValue(new Promise(() => {}))).toEqual({});
      expect(toCanonicalValue(new WeakMap())).toEqual({});
      expect(toCanonicalValue(new WeakSet())).toEqual({});
      expect(toCanonicalValue(new Map())).toEqual({});
      expect(toCanonicalValue(new Set())).toEqual({});
    });

    it("handles typed arrays", () => {
      const uint8Array = new Uint8Array([1, 2, 3]);
      const result = toCanonicalValue(uint8Array);
      expect(result).toEqual({}); // Should become empty object
    });

    it("handles URL and URLSearchParams objects", () => {
      const url = new URL("https://example.com/path?query=value");
      const result = toCanonicalValue(url);
      expect(result).toEqual({}); // Should become empty object
    });

    it("handles frozen and sealed objects", () => {
      const obj = { a: 1, b: 2 };
      Object.freeze(obj);
      const result = toCanonicalValue(obj);
      expect(result).toEqual({ a: 1, b: 2 });

      const sealedObj = { x: 10, y: 20 };
      Object.seal(sealedObj);
      const sealedResult = toCanonicalValue(sealedObj);
      expect(sealedResult).toEqual({ x: 10, y: 20 });
    });

    it("handles objects with getters and setters", () => {
      const obj = {
        normalProp: "value",
        get computed() {
          return "computed";
        },
        set computed(value) {
          /* setter */
        },
      };
      const result = toCanonicalValue(obj);
      expect(result).toEqual({ normalProp: "value" }); // getters/setters should be ignored
    });

    it("handles Proxy objects", () => {
      const target = { a: 1 };
      const proxy = new Proxy(target, {
        get(target, prop) {
          if (prop === "b") return 2;
          return Reflect.get(target, prop);
        },
      });
      const result = toCanonicalValue(proxy);
      expect(result).toEqual({ a: 1, b: 2 }); // Should work through proxy
    });

    it("handles objects with null prototype", () => {
      const obj = Object.create(null);
      obj.a = 1;
      obj.b = 2;
      const result = toCanonicalValue(obj);
      expect(result).toEqual({ a: 1, b: 2 });
    });

    it("handles complex circular references with multiple levels", () => {
      const obj1: any = { name: "obj1" };
      const obj2: any = { name: "obj2" };
      const obj3: any = { name: "obj3" };

      obj1.ref2 = obj2;
      obj1.ref3 = obj3;
      obj2.ref1 = obj1;
      obj2.ref3 = obj3;
      obj3.ref1 = obj1;
      obj3.ref2 = obj2;

      const result = toCanonicalValue(obj1);
      expect(result).toEqual({
        name: "obj1",
        ref2: {
          name: "obj2",
          ref3: {
            name: "obj3",
            ref1: { __circular: true },
            ref2: { __circular: true },
          },
          ref1: { __circular: true },
        },
        ref3: { __circular: true },
      });
    });

    it("handles arrays with circular references", () => {
      const arr: any[] = [1, 2];
      arr.push(arr); // circular reference to itself
      const result = toCanonicalValue(arr);
      expect(result).toEqual([1, 2, { __circular: true }]);
    });

    it("handles forbidden keys in nested objects", () => {
      const obj = {
        normal: "value",
        nested: {
          __proto__: "forbidden",
          constructor: "forbidden",
          normal: "nested_value",
        },
        another: {
          prototype: "also_forbidden",
          normal: "another_value",
        },
      };
      const result = toCanonicalValue(obj);
      expect(result).toEqual({
        another: { normal: "another_value" },
        nested: { normal: "nested_value" },
        normal: "value",
      });
    });

    it("handles undefined values in objects correctly", () => {
      const obj = {
        defined: "value",
        undefined: undefined,
        null: null,
        function: () => {},
        symbol: Symbol("test"),
      };
      const result = toCanonicalValue(obj);
      expect(result).toEqual({
        defined: "value",
        null: null,
        // undefined, function, and symbol should be filtered out
      });
    });

    it("handles BigInt in nested structures", () => {
      expect(() => toCanonicalValue({ value: 42n })).toThrow(
        InvalidParameterError,
      );
      expect(() => toCanonicalValue([1, 2n, 3])).toThrow(InvalidParameterError);
    });

    it("handles non-enumerable properties", () => {
      const obj = { enumerable: "value" };
      Object.defineProperty(obj, "nonEnumerable", {
        value: "hidden",
        enumerable: false,
      });
      const result = toCanonicalValue(obj);
      expect(result).toEqual({ enumerable: "value" }); // non-enumerable should be ignored
    });

    it("handles inherited properties", () => {
      const parent = { inherited: "from_parent" };
      const child = Object.create(parent);
      child.own = "own_property";
      const result = toCanonicalValue(child);
      expect(result).toEqual({ own: "own_property" }); // inherited properties should be ignored
    });
  });

  describe("safeStableStringify", () => {
    it("produces deterministic output for objects with different key orders", () => {
      const obj1 = { b: 2, a: 1, c: 3 };
      const obj2 = { a: 1, c: 3, b: 2 };

      const result1 = safeStableStringify(obj1);
      const result2 = safeStableStringify(obj2);

      expect(result1).toBe(result2);
      expect(result1).toBe('{"a":1,"b":2,"c":3}');
    });

    it("handles primitive values", () => {
      expect(safeStableStringify("string")).toBe('"string"');
      expect(safeStableStringify(42)).toBe("42");
      expect(safeStableStringify(true)).toBe("true");
      expect(safeStableStringify(null)).toBe("null");
    });

    it("returns 'null' for undefined values", () => {
      expect(safeStableStringify(undefined)).toBe("null");
    });

    it("handles arrays", () => {
      expect(safeStableStringify([1, 2, 3])).toBe("[1,2,3]");
      expect(safeStableStringify([3, 1, 2])).toBe("[3,1,2]"); // order preserved
    });

    it("handles complex nested structures", () => {
      const complex = {
        users: [
          { name: "Alice", id: 1 },
          { name: "Bob", id: 2 },
        ],
        metadata: {
          version: "1.0",
          features: ["auth", "crypto"],
        },
      };

      const result = safeStableStringify(complex);
      // Verify it's deterministic
      expect(safeStableStringify(complex)).toBe(result);

      // Parse and verify structure
      const parsed = JSON.parse(result);
      expect(parsed.users).toHaveLength(2);
      expect(parsed.metadata.version).toBe("1.0");
    });

    it("throws InvalidParameterError for BigInt values", () => {
      expect(() => safeStableStringify(42n)).toThrow(InvalidParameterError);
      expect(() => safeStableStringify({ value: 123n })).toThrow(
        InvalidParameterError,
      );
    });

    it("handles circular references", () => {
      const obj: any = { a: 1 };
      obj.self = obj;

      const result = safeStableStringify(obj);
      expect(result).toBe('{"a":1,"self":{"__circular":true}}');
    });

    it("filters forbidden keys", () => {
      const obj = {
        normalKey: "value",
        __proto__: "forbidden",
        constructor: "forbidden",
      };

      const result = safeStableStringify(obj);
      expect(result).toBe('{"normalKey":"value"}');
    });

    it("handles Date objects", () => {
      const date = new Date("2023-01-01T00:00:00.000Z");
      const result = safeStableStringify(date);
      expect(result).toBe('"2023-01-01T00:00:00.000Z"');
    });

    it("handles empty structures", () => {
      expect(safeStableStringify({})).toBe("{}");
      expect(safeStableStringify([])).toBe("[]");
    });

    it("handles undefined values in nested structures", () => {
      const obj = {
        defined: "value",
        undefined: undefined,
        nested: {
          also_undefined: undefined,
          defined: "nested",
        },
      };
      const result = safeStableStringify(obj);
      expect(result).toBe('{"defined":"value","nested":{"defined":"nested"}}');
    });

    it("handles mixed undefined and null values", () => {
      const obj = {
        null_value: null,
        undefined_value: undefined,
        array: [null, undefined, "string"],
      };
      const result = safeStableStringify(obj);
      expect(result).toBe('{"array":["string"],"null_value":null}');
    });

    it("handles objects with numeric keys", () => {
      const obj = {
        "1": "one",
        "2": "two",
        "10": "ten",
      };
      const result = safeStableStringify(obj);
      // Numeric keys should be sorted as strings
      expect(result).toBe('{"1":"one","10":"ten","2":"two"}');
    });

    it("handles empty strings and whitespace", () => {
      expect(safeStableStringify("")).toBe('""');
      expect(safeStableStringify("   ")).toBe('"   "');
      expect(safeStableStringify("\t\n")).toBe('"\\t\\n"');
    });

    it("handles special JSON characters", () => {
      const obj = {
        quotes: "\"double\" 'single'",
        backslash: "path\\to\\file",
        newline: "line1\nline2",
        tab: "col1\tcol2",
        unicode: "café",
      };
      const result = safeStableStringify(obj);
      const parsed = JSON.parse(result);
      expect(parsed.quotes).toBe("\"double\" 'single'");
      expect(parsed.backslash).toBe("path\\to\\file");
      expect(parsed.newline).toBe("line1\nline2");
      expect(parsed.tab).toBe("col1\tcol2");
      expect(parsed.unicode).toBe("café");
    });

    it("handles deeply nested structures", () => {
      const deep: any = { level: 1 };
      let current: any = deep;
      for (let i = 2; i <= 100; i++) {
        current = current.nested = { level: i };
      }
      const result = safeStableStringify(deep);
      expect(result).toContain('"level":100');
      // Verify it's still deterministic
      expect(safeStableStringify(deep)).toBe(result);
    });

    it("handles arrays with mixed object types", () => {
      const arr = [
        { type: "object", value: 1 },
        [1, 2, 3],
        "string",
        null,
        undefined,
        { z: 1, a: 2 },
      ];
      const result = safeStableStringify(arr);
      expect(result).toBe(
        '[{"type":"object","value":1},[1,2,3],"string",null,null,{"a":2,"z":1}]',
      );
    });

    it("handles Date objects in arrays", () => {
      const date = new Date("2023-01-01T00:00:00.000Z");
      const arr = [date, { timestamp: date }];
      const result = safeStableStringify(arr);
      expect(result).toBe(
        '["2023-01-01T00:00:00.000Z",{"timestamp":"2023-01-01T00:00:00.000Z"}]',
      );
    });

    it("handles circular references in stringify", () => {
      const obj: any = { a: 1 };
      obj.self = obj;
      const result = safeStableStringify(obj);
      expect(result).toBe('{"a":1,"self":{"__circular":true}}');
      // Verify it's deterministic
      expect(safeStableStringify(obj)).toBe(result);
    });

    it("handles forbidden keys in stringify", () => {
      const obj = {
        normal: "value",
        __proto__: "forbidden",
        constructor: "forbidden",
        nested: {
          __proto__: "nested_forbidden",
          normal: "nested_normal",
        },
      };
      const result = safeStableStringify(obj);
      expect(result).toBe(
        '{"nested":{"normal":"nested_normal"},"normal":"value"}',
      );
    });

    it("handles very large objects", () => {
      const largeObj: any = {};
      for (let i = 0; i < 1000; i++) {
        largeObj[`key${i}`] = `value${i}`;
      }
      const result = safeStableStringify(largeObj);
      expect(result).toContain('"key0":"value0"');
      expect(result).toContain('"key999":"value999"');
      // Verify determinism
      expect(safeStableStringify(largeObj)).toBe(result);
    });

    it("handles objects with duplicate values but different keys", () => {
      const obj = {
        z: "same",
        a: "same",
        m: "different",
      };
      const result = safeStableStringify(obj);
      expect(result).toBe('{"a":"same","m":"different","z":"same"}');
    });

    it("handles arrays with duplicate objects", () => {
      const shared = { value: "shared" };
      const arr = [shared, shared, { different: "value" }];
      const result = safeStableStringify(arr);
      expect(result).toBe(
        '[{"value":"shared"},{"value":"shared"},{"different":"value"}]',
      );
    });

    it("handles undefined at top level", () => {
      expect(safeStableStringify(undefined)).toBe("null");
    });

    it("handles null at top level", () => {
      expect(safeStableStringify(null)).toBe("null");
    });

    it("handles empty array", () => {
      expect(safeStableStringify([])).toBe("[]");
    });

    it("handles empty object", () => {
      expect(safeStableStringify({})).toBe("{}");
    });
  });
});
