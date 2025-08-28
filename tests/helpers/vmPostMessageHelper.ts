import * as ts from 'typescript';
import { readFileSync } from 'fs';
import { createRequire } from 'module';
import path from 'path';
import fs from 'fs';
import vm from 'node:vm';

// Small VM-based loader that transpiles src TypeScript files with a
// `const __TEST__ = true` prelude and evaluates them in an isolated VM.
// It returns the exported module object for `src/postMessage.ts` so tests can
// exercise build-time guarded internals (`__test_internals`).

export function loadPostMessageInternals(opts?: {
  clearCache?: boolean;
  stubCrypto?: { getRandomValues?: (u: Uint8Array) => void } | null;
  production?: boolean | undefined;
}) {
  const srcPath = path.resolve(__dirname, '../../src/postMessage.ts');
  const src = readFileSync(srcPath, 'utf8');

  const withMacro = `const __TEST__ = true;\n` + src;
  const transpiled = ts.transpileModule(withMacro, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
      esModuleInterop: true,
    },
    fileName: 'postMessage.test.ts',
  }).outputText;

  const srcDir = path.resolve(__dirname, '../../src');
  // simple per-call cache; allow clearing via opts
  const cache = new Map<string, any>();

  function transpileFile(tsPath: string) {
    const code = readFileSync(tsPath, 'utf8');
    const withMacroInner = `const __TEST__ = true;\n` + code;
    const out = ts.transpileModule(withMacroInner, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
      fileName: path.basename(tsPath),
    });
    if (!out.outputText) throw new Error('Transpile failed for ' + tsPath + '\n' + JSON.stringify(out.diagnostics || []));
    return out.outputText;
  }

  function makeRequireFor(parentDir: string) {
    const nodeRequire = createRequire(parentDir + path.sep);
    return function requireShim(spec: string) {
      if (!spec.startsWith('.')) return nodeRequire(spec);
      let resolvedTs = path.resolve(parentDir, spec);
      if (!path.extname(resolvedTs)) resolvedTs += '.ts';
      const normalized = resolvedTs;
      if (cache.has(normalized)) return cache.get(normalized).exports;

      const mod: any = { exports: {} };
      cache.set(normalized, mod);
      const out = transpileFile(resolvedTs);
      const wrapper = `(function(exports, require, module, __filename, __dirname) { ${out} \n return module.exports; })`;
      const script = new vm.Script(wrapper, { filename: resolvedTs });
      const context: any = { console, __SECURITY_KIT_ALLOW_TEST_APIS: true };
      // Provide standard builtins from host so ArrayBuffer.isView and typed arrays
      // detection works correctly inside the VM realm.
      const host = globalThis as any;
      for (const key of [
        'ArrayBuffer',
        'Uint8Array',
        'Int8Array',
        'Uint16Array',
        'Int16Array',
        'Uint32Array',
        'Int32Array',
        'Float32Array',
        'Float64Array',
        'DataView',
        'SharedArrayBuffer',
        'TextEncoder',
        'TextDecoder',
      ]) {
        if (typeof host[key] !== 'undefined') context[key] = host[key];
      }
      if (typeof host.ArrayBuffer !== 'undefined' && typeof host.ArrayBuffer.isView === 'function') {
        context.ArrayBuffer = host.ArrayBuffer;
        context.ArrayBuffer.isView = host.ArrayBuffer.isView.bind(host.ArrayBuffer);
      }
      // allow injecting a stubbed crypto for testing fallback branches
      if (opts?.stubCrypto === null) {
        // explicitly null => no crypto available in VM
      } else if (opts?.stubCrypto) {
        context.crypto = opts.stubCrypto;
      } else if ((globalThis as any).crypto) context.crypto = (globalThis as any).crypto;
      // allow stubbing environment.isProduction via environment.setExplicitEnv in tests
      const req = makeRequireFor(path.dirname(resolvedTs));
      context.require = req;
      const fn = script.runInNewContext(context);
      const result = fn(mod.exports, req, mod, resolvedTs, path.dirname(resolvedTs));
      mod.exports = result || mod.exports;
      return mod.exports;
    };
  }

  const wrapper = `(function(exports, require, module, __filename, __dirname) { ${transpiled} \n return module.exports; })`;
  const script = new vm.Script(wrapper, { filename: srcPath });
  const fakeModule: any = { exports: {} };
  const requireRoot = makeRequireFor(path.dirname(srcPath));
  const contextRoot: any = { console, __SECURITY_KIT_ALLOW_TEST_APIS: true };
  // Ensure VM root has host typed-array builtins for consistent behavior
  const hostRoot = globalThis as any;
  for (const key of [
    'ArrayBuffer',
    'Uint8Array',
    'Int8Array',
    'Uint16Array',
    'Int16Array',
    'Uint32Array',
    'Int32Array',
    'Float32Array',
    'Float64Array',
    'DataView',
    'SharedArrayBuffer',
    'TextEncoder',
    'TextDecoder',
  ]) {
    if (typeof hostRoot[key] !== 'undefined') contextRoot[key] = hostRoot[key];
  }
  if (typeof hostRoot.ArrayBuffer !== 'undefined' && typeof hostRoot.ArrayBuffer.isView === 'function') {
    contextRoot.ArrayBuffer = hostRoot.ArrayBuffer;
    contextRoot.ArrayBuffer.isView = hostRoot.ArrayBuffer.isView.bind(hostRoot.ArrayBuffer);
  }
  if (opts?.stubCrypto === null) {
    // no crypto
  } else if (opts?.stubCrypto) {
    contextRoot.crypto = opts.stubCrypto;
  } else if ((globalThis as any).crypto) contextRoot.crypto = (globalThis as any).crypto;
  if (typeof opts?.production === 'boolean') {
    // if production flag set, inject a process.env.NODE_ENV into VM to control environment detection
    contextRoot.process = { env: { NODE_ENV: opts.production ? 'production' : 'development' } };
  }
  contextRoot.require = requireRoot;
  const fn = script.runInNewContext(contextRoot);
  const exported = fn(fakeModule.exports, requireRoot, fakeModule, srcPath, path.dirname(srcPath));

  if (opts?.clearCache) {
    cache.clear();
  }

  // Attach a helper to execute arbitrary code inside the same VM setup so
  // tests can create VM-realm objects (e.g. MessagePort prototypes) and
  // exercise realm-sensitive checks like safeCtorName and ArrayBuffer.isView.
  try {
    Object.defineProperty(exported, '__runInVm', {
      value: (code: string) => {
        const wrapped = `globalThis.__vm_result = (function(){ ${code} })();`;
        const scriptInner = new vm.Script(wrapped, { filename: srcPath + '.runner' });
        const ctx: any = { console, __SECURITY_KIT_ALLOW_TEST_APIS: true, globalThis: {} };
        const hostCtx = globalThis as any;
        for (const key of [
          'ArrayBuffer',
          'Uint8Array',
          'Int8Array',
          'Uint16Array',
          'Int16Array',
          'Uint32Array',
          'Int32Array',
          'Float32Array',
          'Float64Array',
          'DataView',
          'SharedArrayBuffer',
          'TextEncoder',
          'TextDecoder',
        ]) {
          if (typeof hostCtx[key] !== 'undefined') ctx.globalThis[key] = hostCtx[key];
        }
        if (typeof hostCtx.ArrayBuffer !== 'undefined' && typeof hostCtx.ArrayBuffer.isView === 'function') {
          ctx.globalThis.ArrayBuffer = hostCtx.ArrayBuffer;
          ctx.globalThis.ArrayBuffer.isView = hostCtx.ArrayBuffer.isView.bind(hostCtx.ArrayBuffer);
        }
        if (opts?.stubCrypto === null) {
          // no crypto
        } else if (opts?.stubCrypto) {
          ctx.globalThis.crypto = opts.stubCrypto;
        } else if ((globalThis as any).crypto) ctx.globalThis.crypto = (globalThis as any).crypto;
        if (typeof opts?.production === 'boolean') {
          ctx.globalThis.process = { env: { NODE_ENV: opts.production ? 'production' : 'development' } };
        }
        ctx.require = requireRoot;
        scriptInner.runInNewContext(ctx);
        return ctx.globalThis.__vm_result;
      },
      enumerable: false,
      configurable: true,
      writable: false,
    });
  } catch {
    // best-effort; ignore if we cannot attach helper
  }

  return exported;
}

export default loadPostMessageInternals;
