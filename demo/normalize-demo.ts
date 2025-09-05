async function main() {
  const mod = await import(new URL("../dist/index.mjs", import.meta.url).href);
  const { normalizeOrigin } = mod;
  const inputs = [
    "https://EXAMPLE.com",
    " https://example.com:443/ ",
    "http://localhost:3000",
  ];
  for (const i of inputs) {
    try {
      const n = normalizeOrigin(i);
      console.log(`Input: ${i} -> Normalized: ${n}`);
    } catch (e) {
      console.error(
        `Input: ${i} -> Error: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }
}

await main();
