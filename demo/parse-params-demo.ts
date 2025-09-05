async function main() {
  const mod = await import(new URL("../dist/index.mjs", import.meta.url).href);
  const { parseURLParams } = mod;
  const url = "https://example.com/search?q=hello&lang=en";
  try {
    const params = parseURLParams(url);
    console.log("Parsed params (frozen, null-proto):", params);
  } catch (e) {
    console.error(
      "Failed to parse params:",
      e instanceof Error ? e.message : String(e),
    );
  }
}

await main();
