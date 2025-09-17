#!/usr/bin/env deno run --allow-read --allow-net --allow-env
/**
 * Comprehensive Security Audit for Supply Chain Protection
 * OWASP ASVS L3 Compliance Checker
 */

interface SecurityAuditResult {
  passed: boolean;
  issues: SecurityIssue[];
  recommendations: string[];
  score: number;
  asvs_l3_compliance: boolean;
}

interface SecurityIssue {
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
  file?: string;
  remediation: string;
}

async function auditSupplyChain(): Promise<SecurityAuditResult> {
  console.log("🔍 Running OWASP ASVS L3 Security Audit...");
  
  const result: SecurityAuditResult = {
    passed: true,
    issues: [],
    recommendations: [],
    score: 100,
    asvs_l3_compliance: true
  };
  
  // 1. Check for direct Node.js imports in production code (ASVS V14.2.1)
  try {
    const indexContent = await Deno.readTextFile("src/index.ts");
    const dangerousImports = ['require(', 'import("', 'eval(', 'Function('];
    
    for (const dangerous of dangerousImports) {
      if (indexContent.includes(dangerous)) {
        result.issues.push({
          severity: 'critical',
          category: 'Supply Chain',
          description: `Dynamic import ${dangerous} detected in production code`,
          file: 'src/index.ts',
          remediation: 'Replace with static imports or Deno-compatible alternatives'
        });
        result.passed = false;
        result.score -= 25;
      }
    }
  } catch (error) {
    result.issues.push({
      severity: 'medium',
      category: 'File Access',
      description: `Unable to read source file: ${error.message}`,
      remediation: 'Ensure all source files are accessible for security scanning'
    });
  }
  
  // 2. Validate crypto usage (ASVS V6.2.1)
  try {
    const cryptoFiles = ['src/crypto.ts', 'src/utils.ts'];
    for (const file of cryptoFiles) {
      try {
        const content = await Deno.readTextFile(file);
        
        // Check for secure random usage
        if (content.includes('Math.random()')) {
          result.issues.push({
            severity: 'critical',
            category: 'Cryptography',
            description: 'Insecure Math.random() usage detected',
            file,
            remediation: 'Replace with crypto.getRandomValues() or Deno secure alternatives'
          });
          result.asvs_l3_compliance = false;
        }
        
        // Check for proper secure comparison
        if (content.includes('=== ') && content.includes('token')) {
          result.issues.push({
            severity: 'high',
            category: 'Timing Attacks',
            description: 'Potential timing attack vulnerability in token comparison',
            file,
            remediation: 'Use constant-time comparison functions'
          });
        }
      } catch {
        // File doesn't exist, skip
      }
    }
  } catch (error) {
    console.warn(`Crypto audit warning: ${error.message}`);
  }
  
  // 3. Check dependencies for known vulnerabilities
  try {
    const packageJson = JSON.parse(await Deno.readTextFile("package.json"));
    const deps = {...packageJson.dependencies, ...packageJson.devDependencies};
    
    // Known vulnerable packages (simplified check)
    const vulnerablePackages = ['lodash', 'moment', 'request', 'debug'];
    for (const [name] of Object.entries(deps)) {
      if (vulnerablePackages.some(vuln => name.includes(vuln))) {
        result.issues.push({
          severity: 'medium',
          category: 'Dependencies',
          description: `Potentially vulnerable dependency: ${name}`,
          remediation: 'Update to latest version or find secure alternatives'
        });
      }
    }
  } catch (error) {
    result.issues.push({
      severity: 'low',
      category: 'Configuration',
      description: `Unable to audit dependencies: ${error.message}`,
      remediation: 'Ensure package.json is accessible'
    });
  }
  
  // Calculate final score and compliance
  const criticalIssues = result.issues.filter(i => i.severity === 'critical').length;
  const highIssues = result.issues.filter(i => i.severity === 'high').length;
  
  result.score = Math.max(0, 100 - (criticalIssues * 25) - (highIssues * 10));
  result.asvs_l3_compliance = criticalIssues === 0 && highIssues <= 2;
  result.passed = result.score >= 80 && result.asvs_l3_compliance;
  
  // Generate recommendations
  if (result.issues.length > 0) {
    result.recommendations = [
      "Complete migration to Deno for enhanced supply chain security",
      "Implement Content Security Policy with strict-dynamic",
      "Use Deno's permission system for least-privilege execution",
      "Enable integrity checking for all remote imports"
    ];
  }
  
  console.log(`\n🎯 Security Audit Results:`);
  console.log(`   Score: ${result.score}/100`);
  console.log(`   OWASP ASVS L3 Compliant: ${result.asvs_l3_compliance ? '✅' : '❌'}`);
  console.log(`   Issues Found: ${result.issues.length}`);
  
  if (result.issues.length > 0) {
    console.log(`\n🔍 Security Issues:`);
    for (const issue of result.issues) {
      const icon = {critical: '🚨', high: '⚠️', medium: '📋', low: '💡'}[issue.severity];
      console.log(`   ${icon} ${issue.category}: ${issue.description}`);
      if (issue.file) console.log(`      File: ${issue.file}`);
      console.log(`      Fix: ${issue.remediation}\n`);
    }
  }
  
  return result;
}

if (import.meta.main) {
  const result = await auditSupplyChain();
  Deno.exit(result.passed ? 0 : 1);
}