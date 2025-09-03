#!/usr/bin/env node
// Husky installer in TypeScript. Skips install in CI/production and when HUSKY=0.
// Uses dynamic import to avoid hard errors when husky isn't installed.
(async function main() {
  try {
    const isCI = (process.env.CI || "").toLowerCase() === "true";
    const isProd = (process.env.NODE_ENV || "").toLowerCase() === "production";
    const huskyDisabled = (process.env.HUSKY || "") === "0";
    if (isCI || isProd || huskyDisabled) {
      // Silent exit when installing in CI/production or when explicitly disabled
      process.exit(0);
    }

    // Try to import husky dynamically. If not present, silently exit.
    let huskyModule: any;
    try {
      huskyModule = await import("husky");
    } catch (err) {
      // Husky not installed; do not fail installs. Keep output minimal for security.
      process.exit(0);
    }

    // Prefer explicit install function if available, otherwise call default export
    const installer =
      huskyModule &&
      (huskyModule.install || huskyModule.default || huskyModule);
    if (typeof installer === "function") {
      // Some husky versions export a function, some export an object with install()
      if (installer.length === 0) {
        // function with no args
        await installer();
      } else {
        // call install if present
        if (typeof huskyModule.install === "function") {
          await huskyModule.install();
        } else if (typeof huskyModule.default === "function") {
          await huskyModule.default();
        }
      }
    }
  } catch (e) {
    // Fail-safe: don't block installs when unexpected errors occur.
    process.exit(0);
  }
})();
