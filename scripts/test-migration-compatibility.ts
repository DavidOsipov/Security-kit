#!/usr/bin/env deno run --allow-read
/**
 * Test Migration Compatibility Checker
 * Validates that tests can migrate from Vitest to Deno.test
 */

interface MigrationReport {
  compatible: boolean;
  totalTests: number;
  issues: string[];
  recommendations: string[];
}

async function checkTestMigration(): Promise<MigrationReport> {
  console.log("🔍 Analyzing test migration compatibility...");
  
  const report: MigrationReport = {
    compatible: true,
    totalTests: 0,
    issues: [],
    recommendations: []
  };
  
  try {
    // Scan test files for compatibility
    for await (const entry of Deno.readDir("tests")) {
      if (entry.isFile && entry.name.endsWith('.test.ts')) {
        const content = await Deno.readTextFile(`tests/${entry.name}`);
        report.totalTests++;
        
        // Check for Vitest-specific APIs that need migration
        const vitestApis = ['describe', 'it', 'test', 'expect', 'vi.mock', 'beforeEach', 'afterEach'];
        const usedApis = vitestApis.filter(api => content.includes(api));
        
        if (usedApis.length > 0) {
          report.issues.push(`${entry.name}: Uses Vitest APIs: ${usedApis.join(', ')}`);
          report.recommendations.push(`Convert ${entry.name} to use Deno.test() and @std/assert`);
        }
      }
    }
  } catch (error) {
    report.issues.push(`Error scanning tests: ${error.message}`);
    report.compatible = false;
  }
  
  report.compatible = report.issues.length === 0;
  
  console.log(`\n📊 Migration Report:`);
  console.log(`   Total Tests: ${report.totalTests}`);
  console.log(`   Compatible: ${report.compatible ? '✅' : '❌'}`);
  console.log(`   Issues: ${report.issues.length}`);
  
  return report;
}

if (import.meta.main) {
  const report = await checkTestMigration();
  console.log(JSON.stringify(report, null, 2));
}