async function main() {
  const mod = await import(new URL("../dist/index.mjs", import.meta.url).href);
  const { runWithStrictUrlHardening, createSecureURL } = mod;
  try {
    runWithStrictUrlHardening(() => {
      // Will be rejected in strict mode (shorthand IPv4)
      try {
        createSecureURL("http://192.168.1", [], {}, undefined, {
          allowedSchemes: ["http:"],
        });
        console.log("Unexpected: shorthand IPv4 accepted in strict mode");
      } catch (err) {
        console.log(
          "Expected rejection in strict mode:",
          err instanceof Error ? err.message : String(err),
        );
      }
    });
  } catch (e) {
    console.error(
      "Error running strict-mode demo:",
      e instanceof Error ? e.message : String(e),
    );
  }
}

await main();
