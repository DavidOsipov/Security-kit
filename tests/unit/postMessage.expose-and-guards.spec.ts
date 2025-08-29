import { test, expect } from 'vitest';
import ts from 'typescript';
import vm from 'node:vm';
import path from 'path';
import { readFileSync } from 'fs';
import { createRequire } from 'module';

// Shared helper: create a require() that transpiles local .ts imports on the fly
// and reuses a shared cache to avoid infinite recursion when modules import each other.
function createTranspilingRequire(parentDir: string, sharedCache?: Map<string, any>) {
  const nodeRequire = createRequire(parentDir + path.sep);
  const cache = sharedCache ?? new Map<string, any>();

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

  function req(spec: string) {
    if (!spec.startsWith('.')) return nodeRequire(spec);
    let resolvedTs = path.resolve(parentDir, spec);
    if (!path.extname(resolvedTs)) resolvedTs += '.ts';
    const normalized = resolvedTs;
    if (cache.has(normalized)) return cache.get(normalized).exports;
    const modLocal: any = { exports: {} };
    cache.set(normalized, modLocal);
    const out = transpileFile(resolvedTs);
    const wrapperLocal = `(function(exports, require, module, __filename, __dirname) { ${out} \n return module.exports; })`;
    const scriptLocal = new vm.Script(wrapperLocal, { filename: resolvedTs });
    const ctx: any = { console, __SECURITY_KIT_ALLOW_TEST_APIS: true };
    const host = globalThis as any;
    for (const key of [
      'ArrayBuffer','Uint8Array','Int8Array','Uint16Array','Int16Array','Uint32Array','Int32Array',
      'Float32Array','Float64Array','DataView','SharedArrayBuffer','TextEncoder','TextDecoder',
    ]) {
      if (typeof host[key] !== 'undefined') ctx[key] = host[key];
    }
    // Use the same cache for nested requires to avoid recursion and repeated evals
    ctx.require = createTranspilingRequire(path.dirname(resolvedTs), cache);
    const fnLocal = scriptLocal.runInNewContext(ctx);
    const result = fnLocal(modLocal.exports, ctx.require, modLocal, resolvedTs, path.dirname(resolvedTs));
    modLocal.exports = result || modLocal.exports;
    return modLocal.exports;
  }

  return req;
}

test('module evaluated with __TEST__ but no require should not expose __test_internals', () => {
  const srcPath = path.resolve(__dirname, '../../src/postMessage.ts');
  const src = readFileSync(srcPath, 'utf8');
  const withMacro = `const __TEST__ = true;\n` + src;
  const transpiled = ts.transpileModule(withMacro, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: 'postMessage.test.ts',
  }).outputText;

  const wrapper = `(function(exports, require, module, __filename, __dirname) { ${transpiled} \n return module.exports; })`;
  const script = new vm.Script(wrapper, { filename: srcPath });

  const mod: any = { exports: {} };
  // Intentionally provide a VM context without a global `require` so the
  // internal factory path that expects require() will fail and the module
  // will gracefully return undefined for __test_internals.
  const context: any = { console };
  // Provide typed-array builtins so the module initialization doesn't blow up
  // on realm checks when loaded inside the VM.
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

  const fn = script.runInNewContext(context);
  // Provide a lightweight stub require for local imports so module evaluation
  // completes without transpiling the entire dependency graph. This avoids
  // deep recursive evaluation and stack overflows during tests.
  function makeStubRequire(parentDir: string) {
    const nodeReq = createRequire(parentDir + path.sep);
    return function req(spec: string) {
      if (!spec.startsWith('.')) return nodeReq(spec);
      // Map common local imports to tiny stubs sufficient for module init.
      const base = spec.replace(/^\.\//, '').replace(/\.ts$/, '');
      if (spec.endsWith('/environment') || spec === './environment') {
        return { environment: { isProduction: false, setExplicitEnv: (_: any) => {}, clearCache: () => {} } };
      }
      if (spec.endsWith('/errors') || spec === './errors') {
        class E extends Error {}
        return {
          InvalidParameterError: class InvalidParameterError extends E {},
          InvalidConfigurationError: class InvalidConfigurationError extends E {},
          CryptoUnavailableError: class CryptoUnavailableError extends E {},
          TransferableNotAllowedError: class TransferableNotAllowedError extends E {},
          sanitizeErrorForLogs: (e: unknown) => ({ message: String((e as Error)?.message ?? e) }),
        };
      }
      if (spec.endsWith('/state') || spec === './state') {
        return {
          ensureCrypto: async () => ({ getRandomValues: (u: Uint8Array) => { for (let i=0;i<u.length;i++) u[i]=i; }, subtle: { digest: async () => new ArrayBuffer(32) } }),
        };
      }
      if (spec.endsWith('/utils') || spec === './utils') {
        return { secureDevLog: () => {}, _arrayBufferToBase64: (_: ArrayBuffer) => 'AAA' };
      }
      if (spec.endsWith('/encoding') || spec === './encoding') {
        return { SHARED_ENCODER: { encode: (s: string) => new TextEncoder().encode(s) } };
      }
      if (spec.endsWith('/constants') || spec === './constants') {
        return { isForbiddenKey: (_: string) => false };
      }
      if (spec.endsWith('/url') || spec === './url') {
        return { normalizeOrigin: (s: string) => s };
      }
      // Fallback: attempt to let Node resolve (may fail for .ts modules)
      try {
        return nodeReq(spec);
      } catch {
        return {};
      }
    };
  }

  const requireFor = makeStubRequire(path.dirname(srcPath));
  const exported = fn(mod.exports, requireFor, mod, srcPath, path.dirname(srcPath));

  // The factory should not expose internals when require is not available.
  expect(exported.__test_internals).toBeUndefined();
});

test('runtime test API guard throws in production unless explicitly allowed', () => {
  const srcPath = path.resolve(__dirname, '../../src/postMessage.ts');
  // Import the runtime-guarded helpers directly from the source so we exercise
  // the inline _assertTestApiAllowedInline check.
  // Build a VM execution of the module with a mocked './environment' import
  // and no global __SECURITY_KIT_ALLOW_TEST_APIS so the runtime guard will
  // enforce production restrictions.
  const withMacro2 = readFileSync(srcPath, 'utf8');
  const transpiled = ts.transpileModule(withMacro2, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: 'postMessage.vm.ts',
  }).outputText;

  const wrapper2 = `(function(exports, require, module, __filename, __dirname) { ${transpiled} \n return module.exports; })`;
  const script2 = new vm.Script(wrapper2, { filename: srcPath + '.vm' });

  const mod2: any = { exports: {} };
  const context2: any = { console };
  // Expose typed-array builtins in VM
  const host2 = globalThis as any;
  for (const key of [
    'ArrayBuffer', 'Uint8Array', 'Int8Array', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array',
    'Float32Array', 'Float64Array', 'DataView', 'SharedArrayBuffer', 'TextEncoder', 'TextDecoder',
  ]) {
    if (typeof host2[key] !== 'undefined') context2[key] = host2[key];
  }
  // Provide an initial process.env without SECURITY_KIT_ALLOW_TEST_APIS
  context2.process = { env: {} };

  // Create a require shim that mocks './environment' import to be production
  const nodeReq = createRequire(path.dirname(srcPath) + path.sep);
  function requireShim(spec: string) {
    if (spec === './environment' || spec.endsWith('/environment')) {
      return { environment: { isProduction: true, setExplicitEnv: (_: any) => {}, clearCache: () => {} } };
    }
    if (spec === './errors' || spec.endsWith('/errors')) {
      class E extends Error {}
      return {
        InvalidParameterError: class InvalidParameterError extends E {},
        InvalidConfigurationError: class InvalidConfigurationError extends E {},
        CryptoUnavailableError: class CryptoUnavailableError extends E {},
        TransferableNotAllowedError: class TransferableNotAllowedError extends E {},
        sanitizeErrorForLogs: (e: unknown) => ({ message: String((e as Error)?.message ?? e) }),
      };
    }
    if (spec === './utils' || spec.endsWith('/utils')) {
      return { secureDevLog: () => {} };
    }
    if (spec === './encoding' || spec.endsWith('/encoding')) {
      return { SHARED_ENCODER: { encode: (s: string) => new TextEncoder().encode(s) } };
    }
    if (spec === './encoding-utils' || spec.endsWith('/encoding-utils')) {
      return { arrayBufferToBase64: (_: ArrayBuffer) => 'AAA' };
    }
    if (spec === './constants' || spec.endsWith('/constants')) {
      return { isForbiddenKey: (_: string) => false };
    }
    if (spec === './url' || spec.endsWith('/url')) {
      return { normalizeOrigin: (s: string) => s };
    }
    if (spec === './state' || spec.endsWith('/state')) {
      return {
        ensureCrypto: async () => ({ getRandomValues: (u: Uint8Array) => { for (let i=0;i<u.length;i++) u[i]=i; }, subtle: { digest: async () => new ArrayBuffer(32) } }),
      };
    }
    // Default to Node resolution for other modules
    return nodeReq(spec);
  }

  const fn2 = script2.runInNewContext(context2);
  const exported2 = fn2(mod2.exports, requireShim, mod2, srcPath, path.dirname(srcPath));

  // Calling the test API without any allow flags should throw
  expect(() => exported2.__test_getSaltFailureTimestamp()).toThrow();

  // Now set the VM process env flag and it should no longer throw
  context2.process.env['SECURITY_KIT_ALLOW_TEST_APIS'] = 'true';
  expect(() => exported2.__test_getSaltFailureTimestamp()).not.toThrow();
});
