// @ts-nocheck: Dynamic VM-based harness with intentional any and cross-realm values.
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/require-await */
import { test, expect } from "vitest";
import ts from "typescript";
import vm from "node:vm";
import path from "path";
import { readFileSync } from "fs";
import { createRequire } from "module";
import {
  sanitizeParamProperties,
  createTranspilingRequire,
} from "../helpers/vmPostMessageHelper.ts";

// (sanitizer already defined above)

test("module evaluated with __TEST__ but no require should not expose __test_internals", () => {
  const srcPath = path.resolve(__dirname, "../../src/postMessage.ts");
  const src = readFileSync(srcPath, "utf8");
  // Don't set __TEST__ = true so that __test_internals will be undefined
  const withMacro = sanitizeParamProperties(src);
  const transpiled = ts.transpileModule(withMacro, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
      esModuleInterop: true,
    },
    fileName: "postMessage.test.ts",
  }).outputText;

  const wrapper = `(function(exports, require, module, __filename, __dirname) { ${transpiled} \n return module.exports; })`;
  const script = new vm.Script(wrapper, { filename: srcPath });

  const mod: { exports: unknown } = { exports: {} };
  // Intentionally provide a VM context without a global `require` so the
  // internal factory path that expects require() will fail and the module
  // will gracefully return undefined for __test_internals.
  // First create the stub require function
  function makeStubRequire(parentDir: string) {
    const nodeReq = createRequire(parentDir + path.sep);
    const transpReq = createTranspilingRequire(parentDir);
    return function req(spec: string) {
      if (!spec.startsWith(".")) return nodeReq(spec);
      // Map common local imports to tiny stubs sufficient for module init.
  // const _base = spec.replace(/^\.\//, "").replace(/\.ts$/, "");
      if (spec.endsWith("/environment") || spec === "./environment") {
        return {
          environment: {
            isProduction: false,
            setExplicitEnv: (_: unknown) => {},
            clearCache: () => {},
          },
        };
      }
      if (spec.endsWith("/config") || spec === "./config") {
        // Minimal config stub to satisfy postMessage's runtime getters
        return {
          getPostMessageConfig: () => ({
            maxPayloadBytes: 32 * 1024,
            maxTraversalNodes: 5000,
            maxObjectKeys: 256,
            maxSymbolKeys: 32,
            maxArrayItems: 256,
            maxTransferables: 2,
            includeSymbolKeysInSanitizer: false,
          }),
        };
      }
      if (spec.endsWith("/errors") || spec === "./errors") {
        class E extends Error {}
        return {
          InvalidParameterError: class InvalidParameterError extends E {},
          InvalidConfigurationError: class InvalidConfigurationError extends E {},
          CryptoUnavailableError: class CryptoUnavailableError extends E {},
          TransferableNotAllowedError: class TransferableNotAllowedError extends E {},
          sanitizeErrorForLogs: (e: unknown) => ({
            message: String((e as Error)?.message ?? e),
          }),
        };
      }
      if (spec.endsWith("/state") || spec === "./state") {
        return {
          ensureCrypto: async () => {
            await 0;
            return {
              getRandomValues: (u: Uint8Array) => {
                for (let i = 0; i < u.length; i++) u[i] = i;
              },
              subtle: { digest: async () => { await 0; return new ArrayBuffer(32); } },
            };
          },
        };
      }
      if (spec.endsWith("/utils") || spec === "./utils") {
        return {
          secureDevLog: () => {},
          _arrayBufferToBase64: (_: ArrayBuffer) => "AAA",
        };
      }
      if (spec.endsWith("/encoding") || spec === "./encoding") {
        return {
          SHARED_ENCODER: {
            encode: (s: string) => new TextEncoder().encode(s),
          },
        };
      }
      if (spec.endsWith("/constants") || spec === "./constants") {
        return { isForbiddenKey: (_: string) => false };
      }
      if (spec.endsWith("/url") || spec === "./url") {
        return { normalizeOrigin: (s: string) => s };
      }
      // Fallback: attempt to let Node resolve (may fail for .ts modules)
      try {
        // Prefer our transpiling require for local TS modules to avoid strip-only issues
        return transpReq(spec);
      } catch {
        return {};
      }
    };
  }

  const requireFor = makeStubRequire(path.dirname(srcPath));
  const context = vm.createContext({ console } as unknown as vm.Context);
  // Mock require to throw for development-guards to ensure __test_internals is undefined
  context.require = (spec: string) => {
    if (
      spec === "./development-guards" ||
      spec.endsWith("/development-guards")
    ) {
      throw new Error("require not available for development-guards");
    }
    // For other imports, use the stub require
    return requireFor(spec);
  };
  // Provide typed-array builtins so the module initialization doesn't blow up
  // on realm checks when loaded inside the VM.
  const host = globalThis as unknown as Record<string, unknown>;
  for (const key of [
    "ArrayBuffer",
    "Uint8Array",
    "Int8Array",
    "Uint16Array",
    "Int16Array",
    "Uint32Array",
    "Int32Array",
    "Float32Array",
    "Float64Array",
    "DataView",
    "SharedArrayBuffer",
    "TextEncoder",
    "TextDecoder",
  ]) {
    if (typeof host[key] !== "undefined") context[key] = host[key];
  }
  const fn = script.runInNewContext(context);
  const exported = fn(
    mod.exports,
    requireFor,
    mod,
    srcPath,
    path.dirname(srcPath),
  );

  // The factory should not expose internals when require is not available.
  expect(exported.__test_internals).toBeUndefined();
});

test("runtime test API guard throws in production unless explicitly allowed", () => {
  const srcPath = path.resolve(__dirname, "../../src/postMessage.ts");
  // Import the runtime-guarded helpers directly from the source so we exercise
  // the inline _assertTestApiAllowedInline check.
  // Build a VM execution of the module with a mocked './environment' import
  // and no global __SECURITY_KIT_ALLOW_TEST_APIS so the runtime guard will
  // enforce production restrictions.
  const withMacro2 = readFileSync(srcPath, "utf8");
  const sanitized2 = sanitizeParamProperties(withMacro2);
  const transpiled = ts.transpileModule(sanitized2, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
      esModuleInterop: true,
    },
    fileName: "postMessage.vm.ts",
  }).outputText;

  const wrapper2 = `(function(exports, require, module, __filename, __dirname) { ${transpiled} \n return module.exports; })`;
  const script2 = new vm.Script(wrapper2, { filename: srcPath + ".vm" });

  const mod2: { exports: unknown } = { exports: {} };
  const context2: Record<string, unknown> = { console } as unknown as Record<
    string,
    unknown
  >;
  // Expose typed-array builtins in VM
  const host2 = globalThis as unknown as Record<string, unknown>;
  for (const key of [
    "ArrayBuffer",
    "Uint8Array",
    "Int8Array",
    "Uint16Array",
    "Int16Array",
    "Uint32Array",
    "Int32Array",
    "Float32Array",
    "Float64Array",
    "DataView",
    "SharedArrayBuffer",
    "TextEncoder",
    "TextDecoder",
  ]) {
    if (typeof host2[key] !== "undefined") context2[key] = host2[key];
  }
  // Provide an initial process.env without SECURITY_KIT_ALLOW_TEST_APIS
  context2.process = { env: {} };

  // Create a require shim that mocks './environment' import to be production
  const nodeReq = createRequire(path.dirname(srcPath) + path.sep);
  const transpReq2 = createTranspilingRequire(path.dirname(srcPath));
  function requireShim(spec: string) {
    if (spec === "./environment" || spec.endsWith("/environment")) {
      return {
        environment: {
          isProduction: true,
          setExplicitEnv: (_: unknown) => {},
          clearCache: () => {},
        },
      };
    }
    if (spec === "./config" || spec.endsWith("/config")) {
      return {
        getPostMessageConfig: () => ({
          maxPayloadBytes: 32 * 1024,
          maxTraversalNodes: 5000,
          maxObjectKeys: 256,
          maxSymbolKeys: 32,
          maxArrayItems: 256,
          maxTransferables: 2,
          includeSymbolKeysInSanitizer: false,
        }),
      };
    }
    if (spec === "./errors" || spec.endsWith("/errors")) {
      class E extends Error {}
      return {
        InvalidParameterError: class InvalidParameterError extends E {},
        InvalidConfigurationError: class InvalidConfigurationError extends E {},
        CryptoUnavailableError: class CryptoUnavailableError extends E {},
        TransferableNotAllowedError: class TransferableNotAllowedError extends E {},
        sanitizeErrorForLogs: (e: unknown) => ({
          message: String((e as Error)?.message ?? e),
        }),
      };
    }
    if (spec === "./utils" || spec.endsWith("/utils")) {
      return { secureDevLog: () => {} };
    }
    if (spec === "./encoding" || spec.endsWith("/encoding")) {
      return {
        SHARED_ENCODER: { encode: (s: string) => new TextEncoder().encode(s) },
      };
    }
    if (spec === "./encoding-utils" || spec.endsWith("/encoding-utils")) {
      return { arrayBufferToBase64: (_: ArrayBuffer) => "AAA" };
    }
    if (spec === "./constants" || spec.endsWith("/constants")) {
      return { isForbiddenKey: (_: string) => false };
    }
    if (spec === "./url" || spec.endsWith("/url")) {
      return { normalizeOrigin: (s: string) => s };
    }
    if (spec === "./state" || spec.endsWith("/state")) {
      return {
        ensureCrypto: async () => {
          await 0;
          return {
            getRandomValues: (u: Uint8Array) => {
              for (let i = 0; i < u.length; i++) u[i] = i;
            },
            subtle: { digest: async () => { await 0; return new ArrayBuffer(32); } },
          };
        },
      };
    }
    // Default to Node resolution for other modules
    if (spec.startsWith(".")) {
      // For local TS files, prefer transpiling require to avoid esbuild strip-only mode
      return transpReq2(spec);
    }
    return nodeReq(spec);
  }

  const fn2 = script2.runInNewContext(context2);
  const exported2 = fn2(
    mod2.exports,
    requireShim,
    mod2,
    srcPath,
    path.dirname(srcPath),
  );

  // Calling the test API without any allow flags should throw
  expect(() => exported2.__test_getSaltFailureTimestamp()).toThrow();

  // Now set the VM process env flag and it should no longer throw
  context2.process.env["SECURITY_KIT_ALLOW_TEST_APIS"] = "true";
  expect(() => exported2.__test_getSaltFailureTimestamp()).not.toThrow();
});
