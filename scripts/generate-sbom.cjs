#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * SBOM (Software Bill of Materials) generator as mandated by Security Constitution
 * Generates a comprehensive list of dependencies and components
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

console.log('📋 Generating Software Bill of Materials (SBOM)...');

try {
  const packagePath = path.join(__dirname, '../package.json');
  // This script runs in a controlled environment; reading from package.json using a
  // computed path is acceptable for a dev-only utility. Disable the rule for this line.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    serialNumber: `urn:uuid:${generateUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'security-kit',
          name: 'generate-sbom',
          version: '1.0.0'
        }
      ],
      component: {
        type: 'library',
        'bom-ref': `${packageData.name}@${packageData.version}`,
        name: packageData.name,
        version: packageData.version,
        description: packageData.description || '',
        licenses: packageData.license ? [{ license: { id: packageData.license } }] : [],
        purl: `pkg:npm/${packageData.name}@${packageData.version}`
      }
    },
    components: []
  };
  
  // Add dependencies
  if (packageData.dependencies) {
    for (const [name, version] of Object.entries(packageData.dependencies)) {
      sbom.components.push({
        type: 'library',
        'bom-ref': `${name}@${version}`,
        name: name,
        version: version,
        purl: `pkg:npm/${name}@${version}`,
        scope: 'required'
      });
    }
  }
  
  // Add devDependencies
  if (packageData.devDependencies) {
    for (const [name, version] of Object.entries(packageData.devDependencies)) {
      sbom.components.push({
        type: 'library',
        'bom-ref': `${name}@${version}`,
        name: name,
        version: version,
        purl: `pkg:npm/${name}@${version}`,
        scope: 'optional'
      });
    }
  }
  
  const outputPath = path.join(__dirname, '../sbom.json');
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  fs.writeFileSync(outputPath, JSON.stringify(sbom, null, 2));
  
  console.log(`✅ SBOM generated successfully at ${outputPath}`);
  console.log(`📊 Components: ${sbom.components.length}`);
  console.log(`🏷️  Package: ${packageData.name}@${packageData.version}`);
  
} catch (error) {
  console.error('❌ Failed to generate SBOM:', error.message);
  process.exit(1);
}

function generateUUID() {
  // Use crypto.randomFillSync when available for secure randomness. Fall back to
  // a time-based deterministic entropy if not available (acceptable for SBOM IDs).
  try {
    const rnd = Buffer.alloc(16);
    crypto.randomFillSync(rnd);
    // Set version bits for v4 UUID
    rnd[6] = (rnd[6] & 0x0f) | 0x40;
    rnd[8] = (rnd[8] & 0x3f) | 0x80;
    const hex = Array.from(rnd)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return (
      hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20)
    );
  } catch (e) {
    // Reference the error for diagnostics and fall back to a hash-based deterministic
    // UUID derived from current time and process id. This avoids Math.random usage
    // and still yields a reasonably unique identifier for SBOM purposes.
    // Log that crypto was unavailable; best-effort only.
    console.warn('crypto.randomFillSync unavailable, falling back to hash-based UUID', e && e.message);
    const t = Date.now().toString(16) + process.pid.toString(16);
    const hash = crypto.createHash('sha256').update(t).digest();
    // Use first 16 bytes of hash
    const rnd = Buffer.from(hash.slice(0, 16));
    rnd[6] = (rnd[6] & 0x0f) | 0x40;
    rnd[8] = (rnd[8] & 0x3f) | 0x80;
    const hex = Array.from(rnd)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return (
      hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20)
    );
  }
}