#!/usr/bin/env deno run --allow-read --allow-write
/**
 * Automated test migration script
 * Converts Vitest tests to Deno.test format
 */

interface MigrationStats {
  converted: number;
  skipped: number;
  errors: string[];
}

async function migrateTest(sourcePath: string, targetPath: string): Promise<boolean> {
  try {
    let content = await Deno.readTextFile(sourcePath);
    
    // Basic transformations
    content = content
      // Replace imports
      .replace(/import.*from ['"]vitest['"];?/g, 
        'import { assertEquals, assertThrows, assert } from "https://deno.land/std@0.210.0/assert/mod.ts";')
      
      // Replace describe/it structure  
      .replace(/describe\(['"]([^'"]+)['"], \(\) => \{/g, '// Test group: $1')
      .replace(/it\(['"]([^'"]+)['"], (?:async )?\(\) => \{/g, 'Deno.test("$1", async () => {')
      
      // Replace expectations
      .replace(/expect\(([^)]+)\)\.toBe\(([^)]+)\)/g, 'assertEquals($1, $2)')
      .replace(/expect\(([^)]+)\)\.toHaveLength\(([^)]+)\)/g, 'assertEquals($1.length, $2)')
      .replace(/expect\(([^)]+)\)\.toThrow\(\)/g, 'assertThrows(() => $1)')
      
      // Clean up closing braces (simplified)
      .replace(/^\}\);$/gm, '});');
    
    // Ensure target directory exists
    const targetDir = targetPath.split('/').slice(0, -1).join('/');
    await Deno.mkdir(targetDir, { recursive: true });
    
    await Deno.writeTextFile(targetPath, content);
    return true;
  } catch (error) {
    console.error(`Migration error for ${sourcePath}: ${error.message}`);
    return false;
  }
}

async function main() {
  const stats: MigrationStats = { converted: 0, skipped: 0, errors: [] };
  
  console.log("🔄 Starting automated test migration...");
  
  // Migrate the sample tests we defined
  const migrations = [
    ["tests/unit/crypto.test.ts", "tests/deno/crypto-migrated.test.ts"],
    ["tests/unit/utils.test.ts", "tests/deno/utils-migrated.test.ts"],
  ];
  
  for (const [source, target] of migrations) {
    try {
      const success = await migrateTest(source, target);
      if (success) {
        stats.converted++;
        console.log(`✅ Migrated: ${source} → ${target}`);
      } else {
        stats.skipped++;
      }
    } catch (error) {
      stats.errors.push(`${source}: ${error.message}`);
    }
  }
  
  console.log(`
📊 Migration Results:
   Converted: ${stats.converted}
   Skipped: ${stats.skipped}
   Errors: ${stats.errors.length}

⚠️  Note: Automated migration is a starting point.
   Manual review and testing is required for:
   - Complex mocking scenarios
   - Custom matchers
   - Async test timing
   - Performance assertions
`);
}

if (import.meta.main) {
  await main();
}