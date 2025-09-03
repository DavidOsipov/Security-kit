/**
 * Integration demo showing enhanced crypto detection capabilities
 * This demonstrates OWASP ASVS L3 compliant crypto detection
 */

import {
  ensureCrypto,
  secureRandomBytes,
  isCryptoAvailable,
} from "../src/state";

async function demoEnhancedCrypto() {
  console.log("🔐 Enhanced Crypto Detection Demo");
  console.log("================================");

  // Check if crypto is available
  const available = await isCryptoAvailable();
  console.log(`✅ Crypto available: ${available}`);

  if (available) {
    // Get crypto provider (auto-detects Node or browser)
    const crypto = await ensureCrypto();
    console.log(
      `✅ Crypto provider detected: ${crypto.constructor.name || "Crypto"}`,
    );
    console.log(`✅ Has SubtleCrypto: ${!!(crypto as any).subtle}`);

    // Generate secure random bytes
    const randomBytes = await secureRandomBytes(32);
    console.log(`✅ Generated ${randomBytes.length} random bytes`);
    console.log(
      `   Sample: ${Array.from(randomBytes.slice(0, 8))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ")}`,
    );

    // Test getRandomValues directly
    const testArray = new Uint8Array(16);
    crypto.getRandomValues(testArray);
    console.log(`✅ Direct getRandomValues works`);
    console.log(
      `   Sample: ${Array.from(testArray.slice(0, 8))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ")}`,
    );
  }

  console.log("");
  console.log("🛡️  Security Features:");
  console.log("   • Cache poisoning protection via generation tracking");
  console.log("   • Node.js crypto auto-detection with fallback");
  console.log("   • ASVS L3 interface validation");
  console.log("   • Secure error handling without information leakage");
  console.log("   • Type-safe crypto provider abstraction");
}

// Run the demo
demoEnhancedCrypto().catch(console.error);
