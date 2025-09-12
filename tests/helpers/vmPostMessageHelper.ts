// @ts-nocheck: This VM test harness performs dynamic cross-realm evaluation and
// manipulates sandboxed contexts. Precise static typing would add noise without
// improving safety in tests. We contain this to tests/helpers only.
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access */
import * as ts from "typescript";
import { readFileSync } from "fs";
import { createRequire } from "module";
import path from "path";
// Note: prefer named fs imports; avoid unused default import to satisfy lint rules.
import vm from "node:vm";

// Small VM-based loader that transpiles src TypeScript files with a
// `const __TEST__ = true` prelude and evaluates them in an isolated VM.
// It returns the exported module object for `src/postMessage.ts` so tests can
// exercise build-time guarded internals (`__test_internals`).

// Some TypeScript syntax (parameter properties) can cause "strip-only mode"
// errors when using transpile-only toolchains. Sanitize by removing access
// modifiers from constructor parameter lists before transpilation. This keeps
// the runtime semantics intact for testing and is safe because it does not
// alter property initialization logic.
export function sanitizeParamProperties(input: string): string {
  const src = String(input);
  let out = "";
  let i = 0;
  // Walk the source and only rewrite the parameter list that immediately
  // follows a `constructor` token. Do not perform global token replacement to
  // avoid corrupting TypeScript types (e.g., mapped types with `readonly`).
  while (i < src.length) {
    const idx = src.indexOf("constructor", i);
    if (idx === -1) {
      out += src.slice(i);
      break;
    }
    out += src.slice(i, idx);
    out += "constructor";
    let j = idx + "constructor".length;
    // Skip whitespace
    while (j < src.length && /\s/.test(src[j] as string)) j++;
    if (src[j] !== "(") {
      // Not a constructor declaration we can sanitize; continue scanning
      i = j;
      continue;
    }
    // Capture the full parenthesized parameter list, handling newlines and nested parens
    let k = j;
    let depth = 0;
    while (k < src.length) {
      const ch = src[k] as string;
      if (ch === "(") depth++;
      else if (ch === ")") {
        depth--;
        if (depth === 0) {
          k++; // include the closing ')'
          break;
        }
      }
      k++;
    }
    const params = src.slice(j + 1, k - 1);
    const cleaned = params.replace(/\b(public|private|protected|readonly)\s+/g, "");
    out += "(" + cleaned + ")";
    i = k;
  }
  return out;
}

// Shared helper: create a require() that transpiles local .ts imports on the fly
// and reuses a shared cache to avoid infinite recursion when modules import each other.
const TRANSPILE_CACHE: Map<string, { mtimeMs: number; code: string }> = new Map();
const SCRIPT_CACHE: Map<string, { code: string; cachedData?: Buffer }> = new Map();

export function clearVmHelperCaches(): void {
  try {
    TRANSPILE_CACHE.clear();
    SCRIPT_CACHE.clear();
  } catch {
    // best-effort
  }
}
export function createTranspilingRequire(
  parentDir: string,
  sharedCache?: Map<string, { exports: unknown }>,
  opts?: { allowTestApisFlag?: boolean },
) {
  const nodeRequire = createRequire(parentDir + path.sep);
  const cache: Map<string, { exports: unknown }> =
    sharedCache ?? new Map<string, { exports: unknown }>();

  function transpileFile(tsPath: string) {
    try {
      const stat = require("fs").statSync(tsPath);
      const cached = TRANSPILE_CACHE.get(tsPath);
      if (cached && cached.mtimeMs === stat.mtimeMs) return cached.code;
      const code = readFileSync(tsPath, "utf8");
      const withMacroInner = `const __TEST__ = true;\n` + code;
      const out = ts.transpileModule(withMacroInner, {
        compilerOptions: {
          module: ts.ModuleKind.CommonJS,
          target: ts.ScriptTarget.ES2020,
          esModuleInterop: true,
          isolatedModules: true,
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
      TRANSPILE_CACHE.set(tsPath, { mtimeMs: stat.mtimeMs, code: out.outputText });
      return out.outputText;
    } catch (e) {
      // On any error, fall back to direct transpile without cache
      const code = readFileSync(tsPath, "utf8");
      const withMacroInner = `const __TEST__ = true;\n` + code;
      const out = ts.transpileModule(withMacroInner, {
        compilerOptions: {
          module: ts.ModuleKind.CommonJS,
          target: ts.ScriptTarget.ES2020,
          esModuleInterop: true,
          isolatedModules: true,
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
  }

  function req(spec: string) {
    if (!spec.startsWith(".")) return nodeRequire(spec);
    let resolvedTs = path.resolve(parentDir, spec);
    if (!path.extname(resolvedTs)) resolvedTs += ".ts";
    const normalized = resolvedTs;
    if (cache.has(normalized)) {
      const c = cache.get(normalized);
      if (c) return c.exports;
    }
    const modLocal: { exports: unknown } = { exports: {} };
    cache.set(normalized, modLocal);
    const out = transpileFile(resolvedTs);
    const wrapperLocal = `(function(exports, require, module, __filename, __dirname) { ${out} \n return module.exports; })`;
    let scriptLocal: vm.Script;
    const cached = SCRIPT_CACHE.get(resolvedTs);
    if (cached && cached.code === wrapperLocal) {
      try {
        scriptLocal = new vm.Script(wrapperLocal, {
          filename: resolvedTs,
          cachedData: cached.cachedData,
        } as any);
      } catch {
        scriptLocal = new vm.Script(wrapperLocal, { filename: resolvedTs });
      }
    } else {
      scriptLocal = new vm.Script(wrapperLocal, {
        filename: resolvedTs,
        // Node will attach cached data to the script; we can grab it after first run
        produceCachedData: true as any,
      } as any);
      try {
        const data = (scriptLocal as any).createCachedData?.();
        SCRIPT_CACHE.set(resolvedTs, {
          code: wrapperLocal,
          cachedData: data instanceof Buffer ? data : undefined,
        });
      } catch {
        SCRIPT_CACHE.set(resolvedTs, { code: wrapperLocal });
      }
    }
    const ctx: Record<string, unknown> = {
      console,
      __SECURITY_KIT_ALLOW_TEST_APIS:
        typeof opts?.allowTestApisFlag === "boolean"
          ? opts.allowTestApisFlag
          : true,
    } as unknown as Record<string, unknown>;
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
      if (typeof host[key] !== "undefined") ctx[key] = host[key];
    }
    // Use the same cache for nested requires to avoid recursion and repeated evals
    ctx.require = createTranspilingRequire(path.dirname(resolvedTs), cache, {
      allowTestApisFlag:
        typeof opts?.allowTestApisFlag === "boolean"
          ? opts.allowTestApisFlag
          : true,
    });
    const fnLocal = scriptLocal.runInNewContext(ctx as unknown as vm.Context);
    const result = fnLocal(
      modLocal.exports,
      ctx.require as (s: string) => unknown,
      modLocal,
      resolvedTs,
      path.dirname(resolvedTs),
    );
    modLocal.exports = result || modLocal.exports;
    return modLocal.exports;
  }

  return req;
}

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
  /**
   * Explicitly control the test-only allow flag inside the VM realm. Defaults
   * to true for back-compat, but tests should set this explicitly instead of
   * relying on host-global propagation.
   */
  allowTestApisFlag?: boolean;
  /**
   * Control how the helper resolves "./development-guards" inside the VM. This
   * avoids racy filesystem mutations in tests. When set to "missing", any require
   * of the guard module will throw as if the module is absent. When set to
   * "present", it will return a stub with assertTestApiAllowed() that does not
   * throw. When undefined, the real file system module resolution is used.
   */
  mockGuardModule?: "missing" | "present";
}) {
  const srcPath = path.resolve(__dirname, "../../src/postMessage.ts");
  // Heavy transpilation of a large, security-audited file can dominate test time
  // when performed repeatedly across many specs. Provide a tiny, in-process cache
  // keyed by file mtime to avoid redundant work and reduce risk of hitting per-test
  // timeouts in slower CI environments.
  interface CacheEntry { readonly mtimeMs: number; readonly code: string }
  const TOP_LEVEL_TRANSPILE_CACHE: Map<string, CacheEntry> = (globalThis as unknown as {
    __SK_VM_TOP_LEVEL_CACHE?: Map<string, CacheEntry>;
  }).__SK_VM_TOP_LEVEL_CACHE ||= new Map<string, CacheEntry>();

  const stat = require("fs").statSync(srcPath);
  const cachedTop = TOP_LEVEL_TRANSPILE_CACHE.get(srcPath);
  let transpiled: string;
  if (cachedTop && cachedTop.mtimeMs === stat.mtimeMs) {
    transpiled = cachedTop.code;
  } else {
    const src = readFileSync(srcPath, "utf8");
    const withMacro = `const __TEST__ = true;\n` + src;
    // Fail-fast watchdog: if transpilation takes unexpectedly long ( > 6s ) we abort
    // to surface a clear test error instead of letting Vitest hit its test timeout.
    const start = Date.now();
    const result = ts.transpileModule(withMacro, {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2020,
        esModuleInterop: true,
      },
      fileName: "postMessage.test.ts",
    }).outputText;
    const elapsed = Date.now() - start;
    if (!result)
      throw new Error("Transpile failed for postMessage.ts: empty output");
    if (elapsed > 6000) {
      throw new Error(
        `Transpile watchdog exceeded (>${6000}ms). Failing fast to avoid opaque test timeout.`,
      );
    }
    transpiled = result;
    try {
      TOP_LEVEL_TRANSPILE_CACHE.set(srcPath, {
        mtimeMs: stat.mtimeMs,
        code: transpiled,
      });
    } catch {
      /* best-effort cache set */
    }
  }

  // const _srcDir = path.resolve(__dirname, "../../src");
  // simple per-call cache; allow clearing via opts
  const cache = new Map<string, { exports: unknown }>();

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

  const flags = {
    allowTestApis:
      typeof opts?.allowTestApisFlag === "boolean"
        ? opts.allowTestApisFlag
        : true,
  };

  function makeRequireFor(parentDir: string) {
    const nodeRequire = createRequire(parentDir + path.sep);
    return function requireShim(spec: string) {
      // Intercept guard module resolution to avoid racy file mutations in tests
      if (
        spec === "./development-guards" ||
        spec.endsWith("/development-guards")
      ) {
        if (opts?.mockGuardModule === "missing") {
          throw new Error("Cannot find module './development-guards' (mocked)");
        }
        if (opts?.mockGuardModule === "present") {
          return { assertTestApiAllowed: () => void 0 } as const;
        }
        // Fallthrough to real resolution when not mocked
      }
      if (!spec.startsWith(".")) return nodeRequire(spec);
      let resolvedTs = path.resolve(parentDir, spec);
      if (!path.extname(resolvedTs)) resolvedTs += ".ts";
      const normalized = resolvedTs;
      if (cache.has(normalized)) {
        const c = cache.get(normalized);
        if (c) return c.exports;
      }

      const mod: { exports: unknown } = { exports: {} };
      cache.set(normalized, mod);
      const out = transpileFile(resolvedTs);
      const wrapper = `(function(exports, require, module, __filename, __dirname) { ${out} \n globalThis.__vm_module_exports = module.exports; \n return module.exports; })`;
      let script: vm.Script;
      const cached = SCRIPT_CACHE.get(resolvedTs);
      if (cached && cached.code === wrapper) {
        try {
          script = new vm.Script(wrapper, {
            filename: resolvedTs,
            cachedData: cached.cachedData,
          } as any);
        } catch {
          script = new vm.Script(wrapper, { filename: resolvedTs });
        }
      } else {
        script = new vm.Script(wrapper, {
          filename: resolvedTs,
          produceCachedData: true as any,
        } as any);
        try {
          const data = (script as any).createCachedData?.();
          SCRIPT_CACHE.set(resolvedTs, {
            code: wrapper,
            cachedData: data instanceof Buffer ? data : undefined,
          });
        } catch {
          SCRIPT_CACHE.set(resolvedTs, { code: wrapper });
        }
      }
      const context: Record<string, unknown> = {
        console,
        __SECURITY_KIT_ALLOW_TEST_APIS: flags.allowTestApis,
      } as unknown as Record<string, unknown>;
      // Ensure globalThis points to the context object so scripts that set
      // globalThis.__vm_result will attach to this object.
      (context as Record<string, unknown>).globalThis = context as unknown as Record<string, unknown>;
      // Provide standard builtins from host so ArrayBuffer.isView and typed arrays
      // detection works correctly inside the VM realm.
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
      try {
        const ab = host.ArrayBuffer as unknown as {
          isView?: (v: unknown) => boolean;
        };
        if (typeof ab !== "undefined" && typeof ab.isView === "function") {
          (context as Record<string, unknown>).ArrayBuffer = host.ArrayBuffer;
          (context as Record<string, unknown>).ArrayBuffer = Object.assign(
            (context as Record<string, unknown>).ArrayBuffer as object,
            { isView: ab.isView?.bind(host.ArrayBuffer as object) },
          );
        }
      } catch {
        // best-effort: if binding fails, proceed without customizing ArrayBuffer.isView
      }
      // allow injecting a stubbed crypto for testing fallback branches
      if (opts?.stubCrypto === null) {
        // explicitly null => no crypto available in VM
      } else if (opts?.stubCrypto) {
        (context as Record<string, unknown>).crypto = opts.stubCrypto as unknown;
      } else {
        const hostAny = globalThis as unknown as Record<string, unknown>;
        if (typeof hostAny.crypto !== "undefined")
          (context as Record<string, unknown>).crypto = hostAny.crypto;
      }
      // allow stubbing environment.isProduction via environment.setExplicitEnv in tests
      const req = makeRequireFor(path.dirname(resolvedTs));
      (context as Record<string, unknown>).require = req;
      const fn = script.runInNewContext(context as unknown as vm.Context);
      const result = fn(
        mod.exports as unknown,
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
  let script: vm.Script;
  {
    const cached = SCRIPT_CACHE.get(srcPath);
    if (cached && cached.code === wrapper) {
      try {
        script = new vm.Script(wrapper, {
          filename: srcPath,
          cachedData: cached.cachedData,
        } as any);
      } catch {
        script = new vm.Script(wrapper, { filename: srcPath });
      }
    } else {
      script = new vm.Script(wrapper, {
        filename: srcPath,
        produceCachedData: true as any,
      } as any);
      try {
        const data = (script as any).createCachedData?.();
        SCRIPT_CACHE.set(srcPath, {
          code: wrapper,
          cachedData: data instanceof Buffer ? data : undefined,
        });
      } catch {
        SCRIPT_CACHE.set(srcPath, { code: wrapper });
      }
    }
  }
  const fakeModule: { exports: unknown } = { exports: {} };
  const requireRoot = makeRequireFor(path.dirname(srcPath));
  const contextRoot: Record<string, unknown> = {
    console,
    __SECURITY_KIT_ALLOW_TEST_APIS: flags.allowTestApis,
  } as unknown as Record<string, unknown>;
  // Ensure globalThis points to the context object so scripts that set
  // globalThis.__vm_result will attach to this object.
  (contextRoot as Record<string, unknown>).globalThis = contextRoot as unknown as Record<string, unknown>;
  // Ensure VM root has host typed-array builtins for consistent behavior
  const hostRoot = globalThis as unknown as Record<string, unknown>;
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
  try {
    const ab = hostRoot.ArrayBuffer as unknown as {
      isView?: (v: unknown) => boolean;
    };
    if (typeof ab !== "undefined" && typeof ab.isView === "function") {
      (contextRoot as Record<string, unknown>).ArrayBuffer =
        hostRoot.ArrayBuffer;
      // Bind isView to host ArrayBuffer for cross-realm checks
      const bound = ab.isView?.bind(hostRoot.ArrayBuffer as object);
      (contextRoot as Record<string, unknown>).ArrayBuffer = Object.assign(
        (contextRoot as Record<string, unknown>).ArrayBuffer as object,
        { isView: bound },
      );
    }
  } catch {
    // best-effort: ignore if ArrayBuffer bind fails
  }
  if (opts?.stubCrypto === null) {
    // no crypto
  } else if (opts?.stubCrypto) {
    (contextRoot as Record<string, unknown>).crypto = opts.stubCrypto as unknown;
  } else {
    const hostAny = globalThis as unknown as Record<string, unknown>;
    if (typeof hostAny.crypto !== "undefined")
      (contextRoot as Record<string, unknown>).crypto = hostAny.crypto;
  }

  // Provide minimal host timer & location/window shims so modules that expect a
  // browser-like global environment (window, location, timers) can initialize
  // inside the VM without hanging or throwing ReferenceErrors. We intentionally
  // forward to the host timers so behavior is predictable in tests.
  try {
    const globalObj = globalThis as unknown as Record<string, unknown>;
    (contextRoot as Record<string, unknown>).setTimeout = globalObj.setTimeout as unknown;
    (contextRoot as Record<string, unknown>).clearTimeout = globalObj.clearTimeout as unknown;
    (contextRoot as Record<string, unknown>).setInterval = globalObj.setInterval as unknown;
    (contextRoot as Record<string, unknown>).clearInterval = globalObj.clearInterval as unknown;
    // Node's setImmediate may not exist in some platforms; forward if present
    if (typeof (globalObj as { setImmediate?: unknown }).setImmediate === "function")
      (contextRoot as Record<string, unknown>).setImmediate = (globalObj as {
        setImmediate?: unknown;
      }).setImmediate as unknown;
    if (typeof (globalObj as { clearImmediate?: unknown }).clearImmediate === "function")
      (contextRoot as Record<string, unknown>).clearImmediate = (globalObj as {
        clearImmediate?: unknown;
      }).clearImmediate as unknown;
    // Promise and scheduling primitives
    (contextRoot as Record<string, unknown>).Promise = (globalObj as {
      Promise?: unknown;
    }).Promise as unknown;
    // simple window/location shims so modules that reference window.* don't crash
    (contextRoot as Record<string, unknown>).window = contextRoot as unknown;
    (contextRoot as Record<string, unknown>).location = {
      origin: "http://localhost",
    } as unknown;
    // minimal event listener API used by postMessage.js
    (contextRoot as Record<string, unknown>).addEventListener = function () {
      /* noop */
    } as unknown;
    (contextRoot as Record<string, unknown>).removeEventListener = function () {
      /* noop */
    } as unknown;
  } catch {
    // best-effort: if anything fails, proceed without shims
  }
  if (typeof opts?.production === "boolean") {
    // if production flag set, inject a process.env.NODE_ENV into VM to control environment detection
    (contextRoot as Record<string, unknown>).process = {
      env: { NODE_ENV: opts.production ? "production" : "development" },
    } as unknown;
  }
  (contextRoot as Record<string, unknown>).require = requireRoot;
  // Create a persistent VM context so module evaluation and subsequent
  // runner invocations share the exact same realm (prototypes/constructors).
  const vmContext = vm.createContext(
    contextRoot as unknown as vm.Context,
  );
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
  const fn = script.runInContext(vmContext as vm.Context, {
    timeout: VM_MODULE_EVAL_TIMEOUT_MS,
  });
  const exported = fn(
    fakeModule.exports as unknown,
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
    clearVmHelperCaches();
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
  const hostCtx = globalThis as unknown as Record<string, unknown>;
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
          } catch {
            // best-effort: ignore inability to mirror into sandbox.globalThis
          }
          try {
            sandbox.globalThis.ArrayBuffer = sandbox.ArrayBuffer;
          } catch {
            // best-effort: ignore inability to mirror into sandbox.globalThis
          }
        }
        // Forward timer/scheduling primitives to the sandbox so tests (and fake timers)
        // behave predictably inside the VM runner.
        const gobj = globalThis as unknown as Record<string, unknown>;
        (sandbox as unknown as Record<string, unknown>).setTimeout = gobj.setTimeout as unknown;
        (sandbox as unknown as Record<string, unknown>).clearTimeout = gobj.clearTimeout as unknown;
        (sandbox as unknown as Record<string, unknown>).setInterval = gobj.setInterval as unknown;
        (sandbox as unknown as Record<string, unknown>).clearInterval = gobj.clearInterval as unknown;
        if (typeof (gobj as { setImmediate?: unknown }).setImmediate === "function")
          (sandbox as unknown as Record<string, unknown>).setImmediate = (gobj as {
            setImmediate?: unknown;
          }).setImmediate as unknown;
        if (typeof (gobj as { clearImmediate?: unknown }).clearImmediate === "function")
          (sandbox as unknown as Record<string, unknown>).clearImmediate = (gobj as {
            clearImmediate?: unknown;
          }).clearImmediate as unknown;
        try {
          (sandbox as unknown as { globalThis: Record<string, unknown> }).globalThis.setTimeout =
            (sandbox as unknown as Record<string, unknown>).setTimeout as unknown as typeof setTimeout;
        } catch {
          // best-effort
        }
        try {
          (sandbox as unknown as { globalThis: Record<string, unknown> }).globalThis.clearTimeout =
            (sandbox as unknown as Record<string, unknown>).clearTimeout as unknown as typeof clearTimeout;
        } catch {
          // best-effort
        }
        try {
          (sandbox as unknown as { globalThis: Record<string, unknown> }).globalThis.setInterval =
            (sandbox as unknown as Record<string, unknown>).setInterval as unknown as typeof setInterval;
        } catch {
          // best-effort
        }
        try {
          (sandbox as unknown as { globalThis: Record<string, unknown> }).globalThis.clearInterval =
            (sandbox as unknown as Record<string, unknown>).clearInterval as unknown as typeof clearInterval;
        } catch {
          // best-effort
        }
        // Inject Vitest's fake timer queueMicrotask if available
        if (
          typeof (gobj as { queueMicrotask?: unknown }).queueMicrotask ===
          "function"
        ) {
          (sandbox as unknown as Record<string, unknown>).queueMicrotask = (
            gobj as { queueMicrotask?: unknown }
          ).queueMicrotask as unknown;
          try {
            (sandbox as unknown as { globalThis: Record<string, unknown> }).globalThis.queueMicrotask = (
              sandbox as unknown as Record<string, unknown>
            ).queueMicrotask as unknown as typeof queueMicrotask;
          } catch {
            // best-effort
          }
        }
        // Inject performance API for timer-based operations
        if (typeof (gobj as { performance?: unknown }).performance === "object") {
          (sandbox as unknown as Record<string, unknown>).performance = (
            gobj as { performance?: unknown }
          ).performance as unknown;
          try {
            (sandbox as unknown as { globalThis: Record<string, unknown> }).globalThis.performance =
              (sandbox as unknown as Record<string, unknown>).performance;
          } catch {
            // best-effort
          }
        }
        (sandbox as unknown as Record<string, unknown>).Promise = (
          gobj as { Promise?: unknown }
        ).Promise as unknown;
        try {
          (sandbox as unknown as { globalThis: Record<string, unknown> }).globalThis.Promise =
            (sandbox as unknown as Record<string, unknown>).Promise as unknown as typeof Promise;
        } catch {
          // best-effort
        }
        sandbox.require = requireRoot;
        // Execute runner code inside the module's persistent context so objects
        // share the same realm as the loaded module. Capture the script return
        // value which is typically the IIFE's result; fall back to the context
        // global marker if needed.
        const maybe = scriptInner.runInContext(contextified as vm.Context, {
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
                ? ArrayBuffer.isView(ret as unknown as ArrayBufferView)
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
              } catch {
                /* best-effort */
              }
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

  // Provide explicit getters/setters for the test-only allow flag so tests can
  // reliably control its visibility in the VM realm without relying on
  // host-global propagation.
  try {
    Object.defineProperty(exported, "__getAllowTestApisFlag", {
      value: () => {
        try {
          return !!flags.allowTestApis;
        } catch {
          return undefined;
        }
      },
      enumerable: false,
      configurable: true,
      writable: false,
    });
    Object.defineProperty(exported, "__setAllowTestApisFlag", {
      value: (v: unknown) => {
        const b = Boolean(v);
        flags.allowTestApis = b;
        try {
          (contextRoot as Record<string, unknown>).__SECURITY_KIT_ALLOW_TEST_APIS = b as unknown as boolean;
          (contextified as unknown as { globalThis?: Record<string, unknown> }).globalThis &&
            ((contextified as unknown as { globalThis?: Record<string, unknown> }).globalThis![
              "__SECURITY_KIT_ALLOW_TEST_APIS"
            ] = b as unknown as boolean);
        } catch {
          /* best-effort */
        }
        return flags.allowTestApis;
      },
      enumerable: false,
      configurable: true,
      writable: false,
    });
  } catch {
    // best-effort
  }

  // Attach a convenience helper that executes a function name from the VM
  // module with JSON-serializable args and returns the result. This avoids
  // trying to pass rich VM objects directly into the host and instead runs
  // realm-sensitive checks inside the VM and returns primitive results.
  try {
    Object.defineProperty(exported, "__execInVm", {
      value: (fnName: string, ...args: unknown[]) => {
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
        } catch (_err) {
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
    if (exported && typeof exported === "object") {
      const maybeDefault = (exported as unknown as { default?: unknown })
        .default;
      if (maybeDefault && typeof maybeDefault === "object") {
        const def = maybeDefault as Record<string, unknown>;
        for (const k of Object.keys(def)) {
          const cur = (exported as Record<string, unknown>)[k];
          if (typeof cur === "undefined")
            (exported as Record<string, unknown>)[k] = def[k];
        }
      }
    }
  } catch {
    /* best-effort */
  }

  // If the module exposes __test_internals, re-export its helpers at the top
  // level so tests can call them directly (some transpilation shapes nest them).
  try {
    const _maybeInternals = (exported as unknown as {
      __test_internals?: unknown;
      default?: { __test_internals?: unknown };
    }).__test_internals;
    const internals =
      (exported as unknown as {
        __test_internals?: unknown;
        default?: { __test_internals?: unknown };
      }).__test_internals ||
      ((exported as unknown as { default?: { __test_internals?: unknown } })
        .default &&
        (exported as unknown as { default?: { __test_internals?: unknown } })
          .default!.__test_internals);
    if (internals && typeof internals === "object") {
      if (
        typeof (exported as Record<string, unknown>).__test_toNullProto ===
          "undefined" &&
        typeof internals.toNullProto === "function"
      ) {
        (exported as Record<string, unknown>).__test_toNullProto = (
          internals as Record<string, unknown>
        ).toNullProto.bind(internals);
      }
      if (
        typeof (exported as Record<string, unknown>).__test_getPayloadFingerprint ===
          "undefined" &&
        typeof internals.getPayloadFingerprint === "function"
      ) {
        (exported as Record<string, unknown>).__test_getPayloadFingerprint = (
          internals as Record<string, unknown>
        ).getPayloadFingerprint.bind(internals);
      }
      if (
        typeof (exported as Record<string, unknown>).__test_ensureFingerprintSalt ===
          "undefined" &&
        typeof internals.ensureFingerprintSalt === "function"
      ) {
        (exported as Record<string, unknown>).__test_ensureFingerprintSalt = (
          internals as Record<string, unknown>
        ).ensureFingerprintSalt.bind(internals);
      }
      if (
        typeof (exported as Record<string, unknown>).__test_deepFreeze ===
          "undefined" &&
        typeof internals.deepFreeze === "function"
      ) {
        (exported as Record<string, unknown>).__test_deepFreeze = (
          internals as Record<string, unknown>
        ).deepFreeze.bind(internals);
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
