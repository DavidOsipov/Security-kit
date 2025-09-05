async function main() {
  const mod = await import(new URL("../dist/index.mjs", import.meta.url).href);
  const { createSecureURL } = mod;
  try {
    const url = createSecureURL(
      "https://api.example.com",
      ["v1", "users", "123"],
      { q: "search", page: 2 },
      undefined,
      { requireHTTPS: true, allowedSchemes: ["https:"] },
    );
    console.log("Created URL:", url);
  } catch (e) {
    console.error(
      "Failed to create secure URL:",
      e instanceof Error ? e.message : String(e),
    );
  }
}

await main();
