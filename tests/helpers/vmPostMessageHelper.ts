import * as ts from "typescript";
import { readFileSync } from "fs";
import { createRequire } from "module";
import path from "path";
import fs from "fs";
import vm from "node:vm";

// Small VM-based loader that transpiles src TypeScript files with a
// `const __TEST__ = true` prelude and evaluates them in an isolated VM.
// It returns the exported module object for `src/postMessage.ts` so tests can
// exercise build-time guarded internals (`__test_internals`).

export function loadPostMessageInternals(opts?: {
  clearCache?: boolean;
  stubCrypto?: { getRandomValues?: (u: Uint8Array) => void } | null;
  production?: boolean | undefined;
  /**
   * Optional timeout in milliseconds for VM script execution. Defaults to a
   * conservative 4000ms to prevent hanging tests. Tests that need longer
   * execution may override this.
   */
  timeoutMs?: number;
}) {
  const srcPath = path.resolve(__dirname, "../../src/postMessage.ts");
  const src = readFileSync(srcPath, "utf8");

  const withMacro = `const __TEST__ = true;\n` + src;
  const transpiled = ts.transpileModule(withMacro, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
      esModuleInterop: true,
    },
    fileName: "postMessage.test.ts",
  }).outputText;

  const srcDir = path.resolve(__dirname, "../../src");
  // simple per-call cache; allow clearing via opts
  const cache = new Map<string, any>();

  function transpileFile(tsPath: string) {
    const code = readFileSync(tsPath, "utf8");
    const withMacroInner = `const __TEST__ = true;\n` + code;
    const out = ts.transpileModule(withMacroInner, {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2020,
        esModuleInterop: true,
      },
      fileName: path.basename(tsPath),
    });
    if (!out.outputText)
      throw new Error(
        "Transpile failed for " +
          tsPath +
          "\n" +
          JSON.stringify(out.diagnostics || []),
      );
    return out.outputText;
  }

  function makeRequireFor(parentDir: string) {
    const nodeRequire = createRequire(parentDir + path.sep);
    return function requireShim(spec: string) {
      if (!spec.startsWith(".")) return nodeRequire(spec);
      let resolvedTs = path.resolve(parentDir, spec);
      if (!path.extname(resolvedTs)) resolvedTs += ".ts";
      const normalized = resolvedTs;
      if (cache.has(normalized)) return cache.get(normalized).exports;

      const mod: any = { exports: {} };
      cache.set(normalized, mod);
      const out = transpileFile(resolvedTs);
      const wrapper = `(function(exports, require, module, __filename, __dirname) { ${out} \n globalThis.__vm_module_exports = module.exports; \n return module.exports; })`;
      const script = new vm.Script(wrapper, { filename: resolvedTs });
      const context: any = { console, __SECURITY_KIT_ALLOW_TEST_APIS: true };
      // Ensure globalThis points to the context object so scripts that set
      // globalThis.__vm_result will attach to this object.
      context.globalThis = context;
      // Provide standard builtins from host so ArrayBuffer.isView and typed arrays
      // detection works correctly inside the VM realm.
      const host = globalThis as any;
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
      if (
        typeof host.ArrayBuffer !== "undefined" &&
        typeof host.ArrayBuffer.isView === "function"
      ) {
        context.ArrayBuffer = host.ArrayBuffer;
        context.ArrayBuffer.isView = host.ArrayBuffer.isView.bind(
          host.ArrayBuffer,
        );
      }
      // allow injecting a stubbed crypto for testing fallback branches
      if (opts?.stubCrypto === null) {
        // explicitly null => no crypto available in VM
      } else if (opts?.stubCrypto) {
        context.crypto = opts.stubCrypto;
      } else if ((globalThis as any).crypto)
        context.crypto = (globalThis as any).crypto;
      // allow stubbing environment.isProduction via environment.setExplicitEnv in tests
      const req = makeRequireFor(path.dirname(resolvedTs));
      context.require = req;
      const fn = script.runInNewContext(context);
      const result = fn(
        mod.exports,
        req,
        mod,
        resolvedTs,
        path.dirname(resolvedTs),
      );
      mod.exports = result || mod.exports;
      return mod.exports;
    };
  }

  const wrapper = `(function(exports, require, module, __filename, __dirname) { ${transpiled} \n globalThis.__vm_module_exports = module.exports; \n return module.exports; })`;
  const script = new vm.Script(wrapper, { filename: srcPath });
  const fakeModule: any = { exports: {} };
  const requireRoot = makeRequireFor(path.dirname(srcPath));
  const contextRoot: any = { console, __SECURITY_KIT_ALLOW_TEST_APIS: true };
  // Ensure globalThis points to the context object so scripts that set
  // globalThis.__vm_result will attach to this object.
  contextRoot.globalThis = contextRoot;
  // Ensure VM root has host typed-array builtins for consistent behavior
  const hostRoot = globalThis as any;
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
    if (typeof hostRoot[key] !== "undefined") contextRoot[key] = hostRoot[key];
  }
  if (
    typeof hostRoot.ArrayBuffer !== "undefined" &&
    typeof hostRoot.ArrayBuffer.isView === "function"
  ) {
    contextRoot.ArrayBuffer = hostRoot.ArrayBuffer;
    contextRoot.ArrayBuffer.isView = hostRoot.ArrayBuffer.isView.bind(
      hostRoot.ArrayBuffer,
    );
  }
  if (opts?.stubCrypto === null) {
    // no crypto
  } else if (opts?.stubCrypto) {
    contextRoot.crypto = opts.stubCrypto;
  } else if ((globalThis as any).crypto)
    contextRoot.crypto = (globalThis as any).crypto;

  // Provide minimal host timer & location/window shims so modules that expect a
  // browser-like global environment (window, location, timers) can initialize
  // inside the VM without hanging or throwing ReferenceErrors. We intentionally
  // forward to the host timers so behavior is predictable in tests.
  try {
    contextRoot.setTimeout = (globalThis as any).setTimeout;
    contextRoot.clearTimeout = (globalThis as any).clearTimeout;
    contextRoot.setInterval = (globalThis as any).setInterval;
    contextRoot.clearInterval = (globalThis as any).clearInterval;
    // Node's setImmediate may not exist in some platforms; forward if present
    if (typeof (globalThis as any).setImmediate === "function")
      contextRoot.setImmediate = (globalThis as any).setImmediate;
    if (typeof (globalThis as any).clearImmediate === "function")
      contextRoot.clearImmediate = (globalThis as any).clearImmediate;
    // Promise and scheduling primitives
    contextRoot.Promise = (globalThis as any).Promise;
    // simple window/location shims so modules that reference window.* don't crash
    contextRoot.window = contextRoot;
    contextRoot.location = { origin: "http://localhost" };
    // minimal event listener API used by postMessage.js
    contextRoot.addEventListener = function () {
      /* noop */
    };
    contextRoot.removeEventListener = function () {
      /* noop */
    };
  } catch {
    // best-effort: if anything fails, proceed without shims
  }
  if (typeof opts?.production === "boolean") {
    // if production flag set, inject a process.env.NODE_ENV into VM to control environment detection
    contextRoot.process = {
      env: { NODE_ENV: opts.production ? "production" : "development" },
    };
  }
  contextRoot.require = requireRoot;
  // Create a persistent VM context so module evaluation and subsequent
  // runner invocations share the exact same realm (prototypes/constructors).
  const vmContext = vm.createContext(contextRoot);
  // Prevent unbounded execution inside the VM helper by specifying a timeout.
  // This ensures tests fail fast with a clear VM timeout rather than hanging
  // the test runner. Use a moderately generous default so normal sync code
  // completes; tests that intentionally exercise long async operations should
  // use other mechanisms.
  // Use a generous timeout for initial module evaluation so tests that
  // intentionally pass a tiny runner timeout (to exercise timeout behavior)
  // don't cause the module load itself to time out. Runner helpers below
  // will use the smaller, test-provided timeout.
  const VM_MODULE_EVAL_TIMEOUT_MS = 10_000;
  const VM_RUNNER_TIMEOUT_MS =
    typeof opts?.timeoutMs === "number" ? opts.timeoutMs : 4000;
  const fn = script.runInContext(vmContext, {
    timeout: VM_MODULE_EVAL_TIMEOUT_MS,
  });
  const exported = fn(
    fakeModule.exports,
    requireRoot,
    fakeModule,
    srcPath,
    path.dirname(srcPath),
  );
  // Keep a reference to the sandbox/context object used to evaluate the module
  // so runner calls execute in the same VM realm and share prototypes/constructors.
  const sandbox = contextRoot;
  const contextified = vmContext;

  if (opts?.clearCache) {
    cache.clear();
  }

  // Attach a helper to execute arbitrary code inside the same VM setup so
  // tests can create VM-realm objects (e.g. MessagePort prototypes) and
  // exercise realm-sensitive checks like safeCtorName and ArrayBuffer.isView.
  try {
    // Low-level runner: preserved under a new, explicitly-unsafe name.
    // Tests should NOT use this directly; prefer `__runInVmJson` or
    // `__execInVm` which marshal results safely across the realm boundary.
    Object.defineProperty(exported, "__runInVmUnsafe", {
      value: (code: string) => {
        // Assign the result to both the VM global and a top-level symbol so
        // runInNewContext variants where `globalThis` isn't the same object
        // as the provided context still expose the value to the host.
        const wrapped = `globalThis.__vm_result = (function(){ ${code} })(); __vm_result = globalThis.__vm_result;`;
        const scriptInner = new vm.Script(wrapped, {
          filename: srcPath + ".runner",
        });
        const hostCtx = globalThis as any;
        // Ensure sandbox has the same builtins we provided earlier when loading the module
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
          if (typeof hostCtx[key] !== "undefined") {
            sandbox[key] = hostCtx[key];
            try {
              sandbox.globalThis[key] = hostCtx[key];
            } catch {
              /* best-effort */
            }
          }
        }
        // Ensure ArrayBuffer.isView is the host-bound function so host ArrayBuffer.isView
        // recognizes VM-created views.
        if (
          typeof hostCtx.ArrayBuffer !== "undefined" &&
          typeof hostCtx.ArrayBuffer.isView === "function"
        ) {
          sandbox.ArrayBuffer = hostCtx.ArrayBuffer;
          try {
            sandbox.ArrayBuffer.isView = hostCtx.ArrayBuffer.isView.bind(
              hostCtx.ArrayBuffer,
            );
          } catch {}
          try {
            sandbox.globalThis.ArrayBuffer = sandbox.ArrayBuffer;
          } catch {}
        }
        // Forward timer/scheduling primitives to the sandbox so tests (and fake timers)
        // behave predictably inside the VM runner.
        sandbox.setTimeout = (globalThis as any).setTimeout;
        sandbox.clearTimeout = (globalThis as any).clearTimeout;
        sandbox.setInterval = (globalThis as any).setInterval;
        sandbox.clearInterval = (globalThis as any).clearInterval;
        if (typeof (globalThis as any).setImmediate === "function")
          sandbox.setImmediate = (globalThis as any).setImmediate;
        if (typeof (globalThis as any).clearImmediate === "function")
          sandbox.clearImmediate = (globalThis as any).clearImmediate;
        try {
          sandbox.globalThis.setTimeout = sandbox.setTimeout;
        } catch {}
        try {
          sandbox.globalThis.clearTimeout = sandbox.clearTimeout;
        } catch {}
        try {
          sandbox.globalThis.setInterval = sandbox.setInterval;
        } catch {}
        try {
          sandbox.globalThis.clearInterval = sandbox.clearInterval;
        } catch {}
        // Inject Vitest's fake timer queueMicrotask if available
        if (typeof (globalThis as any).queueMicrotask === "function") {
          sandbox.queueMicrotask = (globalThis as any).queueMicrotask;
          try {
            sandbox.globalThis.queueMicrotask = sandbox.queueMicrotask;
          } catch {}
        }
        // Inject performance API for timer-based operations
        if (typeof (globalThis as any).performance === "object") {
          sandbox.performance = (globalThis as any).performance;
          try {
            sandbox.globalThis.performance = sandbox.performance;
          } catch {}
        }
        sandbox.Promise = (globalThis as any).Promise;
        try {
          sandbox.globalThis.Promise = sandbox.Promise;
        } catch {}
        sandbox.require = requireRoot;
        // Execute runner code inside the module's persistent context so objects
        // share the same realm as the loaded module. Capture the script return
        // value which is typically the IIFE's result; fall back to the context
        // global marker if needed.
        const maybe = scriptInner.runInContext(contextified, {
          timeout: VM_RUNNER_TIMEOUT_MS,
        });
        const ret =
          typeof maybe !== "undefined"
            ? maybe
            : typeof contextified.__vm_result !== "undefined"
              ? contextified.__vm_result
              : contextified.globalThis && contextified.globalThis.__vm_result;
        try {
          // Attach a best-effort copy of the last returned value and some meta
          Object.defineProperty(exported, "__vm_last_return", {
            value: ret,
            enumerable: false,
            configurable: true,
            writable: false,
          });
          const meta = {
            typeof: typeof ret,
            isView:
              typeof ArrayBuffer !== "undefined" &&
              typeof ArrayBuffer.isView === "function"
                ? ArrayBuffer.isView(ret as any)
                : false,
            ctorName: (() => {
              try {
                if (ret && typeof ret === "object") {
                  const p = Object.getPrototypeOf(ret);
                  if (
                    p &&
                    p.constructor &&
                    typeof p.constructor.name === "string"
                  )
                    return p.constructor.name;
                }
              } catch {}
              return undefined;
            })(),
          };
          Object.defineProperty(exported, "__vm_last_return_meta", {
            value: meta,
            enumerable: false,
            configurable: true,
            writable: false,
          });
        } catch {
          /* best-effort */
        }
        return ret;
      },
      enumerable: false,
      configurable: true,
      writable: false,
    });
    // Intentionally do not expose a callable `__runInVm` helper. The low-level
    // runner is available only as `__runInVmUnsafe` for advanced use. This
    // reduces the risk of accidental cross-realm object passing.
  } catch {
    // best-effort; ignore if we cannot attach helper
  }

  // Attach a convenience helper that executes a function name from the VM
  // module with JSON-serializable args and returns the result. This avoids
  // trying to pass rich VM objects directly into the host and instead runs
  // realm-sensitive checks inside the VM and returns primitive results.
  try {
    Object.defineProperty(exported, "__execInVm", {
      value: (fnName: string, ...args: any[]) => {
        try {
          // Build code that calls a named export on the module and serializes
          // the result to JSON so the host can receive it safely.
          const safeArgs = JSON.stringify(args);
          const code = `(() => { try { const m = globalThis.__vm_module_exports || globalThis.module && globalThis.module.exports; if (!m) return undefined; const fn = m[${JSON.stringify(fnName)}]; if (typeof fn !== 'function') return undefined; const res = fn.apply(null, ${safeArgs}); return typeof res === 'object' ? JSON.stringify(res) : String(res); } catch(e) { return '__VM_EXCEPTION__' + String(e); } })()`;
          const scriptInner = new vm.Script(code, {
            filename: srcPath + ".exec",
          });
          const maybe = scriptInner.runInContext(contextified, {
            timeout: VM_RUNNER_TIMEOUT_MS,
          });
          if (typeof maybe === "string" && maybe.startsWith("__VM_EXCEPTION__"))
            throw new Error(maybe.slice("__VM_EXCEPTION__".length));
          // Attempt to parse JSON result if applicable
          try {
            return JSON.parse(maybe as string);
          } catch {
            return maybe;
          }
        } catch (err) {
          return undefined;
        }
      },
      enumerable: false,
      configurable: true,
      writable: false,
    });
  } catch {
    /* best-effort */
  }

  // Execute arbitrary code inside the VM and return a JSON-serializable result.
  // This avoids passing rich VM objects across the host boundary which is
  // brittle; instead run realm-sensitive checks inside the VM and return
  // primitives that the host test can assert on.
  try {
    Object.defineProperty(exported, "__runInVmJson", {
      value: (code: string) => {
        try {
          // Primary attempt: serialize the IIFE result to a JSON string inside VM
          const wrapped = `(() => { try { return JSON.stringify((function(){ ${code} })()); } catch(e) { return '__VM_EXCEPTION__' + String(e); } })()`;
          const scriptInner = new vm.Script(wrapped, {
            filename: srcPath + ".runjson",
          });
          let maybe = scriptInner.runInContext(contextified, {
            timeout: VM_RUNNER_TIMEOUT_MS,
          });
          // Fallback: if primary attempt returned undefined, try a two-step approach
          // where we execute the code in the VM, store the result on the VM global,
          // JSON.stringify it inside the VM, then read that string from the host.
          if (typeof maybe === "undefined") {
            const setResultScript = new vm.Script(
              `(function(){ try { globalThis.__vm_runjson_result = (function(){ ${code} })(); globalThis.__vm_runjson_string = JSON.stringify(globalThis.__vm_runjson_result); } catch(e) { globalThis.__vm_runjson_string = '__VM_EXCEPTION__' + String(e); } })()`,
              { filename: srcPath + ".runjson.set" },
            );
            setResultScript.runInContext(contextified);
            const vmStr = contextified.__vm_runjson_string;
            if (
              typeof vmStr === "string" &&
              vmStr.startsWith("__VM_EXCEPTION__")
            ) {
              throw new Error(vmStr.slice("__VM_EXCEPTION__".length));
            }
            if (typeof vmStr !== "undefined") {
              maybe = vmStr;
            } else if (
              typeof contextified.__vm_runjson_result !== "undefined"
            ) {
              try {
                // Try to marshal simple results (arrays/objects of primitives)
                maybe = JSON.stringify(contextified.__vm_runjson_result);
              } catch {
                maybe = undefined;
              }
            }
          }
          if (
            typeof maybe === "string" &&
            (maybe as string).startsWith("__VM_EXCEPTION__")
          ) {
            throw new Error((maybe as string).slice("__VM_EXCEPTION__".length));
          }
          try {
            return typeof maybe === "string"
              ? JSON.parse(maybe as string)
              : maybe;
          } catch {
            return maybe;
          }
        } catch (err) {
          // Best-effort: expose the error message to the caller rather than
          // silently returning undefined to aid debugging in tests.
          try {
            return `__RUN_ERROR__${String(err)}`;
          } catch {
            return undefined;
          }
        }
      },
      enumerable: false,
      configurable: true,
      writable: false,
    });
  } catch {
    /* best-effort */
  }

  // Expose a host-side safeCtorName implementation on the exported object so
  // tests can call it directly against VM-created objects. This mirrors the
  // logic in src/postMessage.ts's internal helper.
  try {
    if (typeof exported.safeCtorName === "undefined") {
      Object.defineProperty(exported, "safeCtorName", {
        value: (value: unknown) => {
          if (value === null || typeof value !== "object") return undefined;
          try {
            const proto = Object.getPrototypeOf(value);
            if (!proto) return undefined;
            const ctor = (proto as { readonly constructor?: unknown })
              .constructor;
            if (typeof ctor === "function") {
              const maybeName = (ctor as { readonly name?: unknown }).name;
              return typeof maybeName === "string" ? maybeName : undefined;
            }
            return undefined;
          } catch {
            return undefined;
          }
        },
        enumerable: false,
        configurable: true,
        writable: false,
      });
    }
  } catch {
    // best-effort
  }

  // Normalize CommonJS/ESModule interop: if the transpiled module used
  // `exports.default = ...` then the real exports may live under `exported.default`.
  try {
    if (
      exported &&
      typeof exported === "object" &&
      typeof (exported as any).default === "object"
    ) {
      const def = (exported as any).default;
      for (const k of Object.keys(def)) {
        if (typeof (exported as any)[k] === "undefined")
          (exported as any)[k] = def[k];
      }
    }
  } catch {
    /* best-effort */
  }

  // If the module exposes __test_internals, re-export its helpers at the top
  // level so tests can call them directly (some transpilation shapes nest them).
  try {
    const internals =
      (exported as any).__test_internals ||
      ((exported as any).default && (exported as any).default.__test_internals);
    if (internals && typeof internals === "object") {
      if (
        typeof (exported as any).__test_toNullProto === "undefined" &&
        typeof internals.toNullProto === "function"
      ) {
        (exported as any).__test_toNullProto =
          internals.toNullProto.bind(internals);
      }
      if (
        typeof (exported as any).__test_getPayloadFingerprint === "undefined" &&
        typeof internals.getPayloadFingerprint === "function"
      ) {
        (exported as any).__test_getPayloadFingerprint =
          internals.getPayloadFingerprint.bind(internals);
      }
      if (
        typeof (exported as any).__test_ensureFingerprintSalt === "undefined" &&
        typeof internals.ensureFingerprintSalt === "function"
      ) {
        (exported as any).__test_ensureFingerprintSalt =
          internals.ensureFingerprintSalt.bind(internals);
      }
      if (
        typeof (exported as any).__test_deepFreeze === "undefined" &&
        typeof internals.deepFreeze === "function"
      ) {
        (exported as any).__test_deepFreeze =
          internals.deepFreeze.bind(internals);
      }
    }
  } catch {
    /* best-effort */
  }

  // Attach debug info so tests can inspect what was returned from the VM.
  try {
    Object.defineProperty(exported, "__vm_export_keys", {
      value: Object.keys(exported),
      enumerable: false,
      configurable: true,
      writable: false,
    });
  } catch {
    /* ignore */
  }

  return exported;
}

export default loadPostMessageInternals;

/*
 Recommended usage note:

 The VM helper exposes two runner-style helpers on the returned module:

  - `__runInVm(code: string)` - lower-level runner that returns whatever the VM IIFE returns. Passing rich VM objects to the host via this function is brittle because prototypes/constructors are realm-specific.
  - `__runInVmJson(code: string)` - recommended for tests. This executes code in the VM and returns JSON-serializable results (arrays, objects, strings) or an error marker. Use this when you need realm-sensitive checks and want reliable assertions on the host side.

 Example:
   const pm = loadPostMessageInternals();
   const arr = pm.__runInVmJson(`return Array.from(new Uint8Array([1,2,3]))`);
   // arr === [1,2,3]

 Prefer `__runInVmJson` in test code unless you specifically need to pass VM objects to host code and understand the risks.
*/
