#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * SBOM (Software Bill of Materials) generator as mandated by Security Constitution
 * Generates a comprehensive list of dependencies and components
 */

const fs = require('fs');
const path = require('path');

console.log('📋 Generating Software Bill of Materials (SBOM)...');

try {
  const packagePath = path.join(__dirname, '../package.json');
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
  fs.writeFileSync(outputPath, JSON.stringify(sbom, null, 2));
  
  console.log(`✅ SBOM generated successfully at ${outputPath}`);
  console.log(`📊 Components: ${sbom.components.length}`);
  console.log(`🏷️  Package: ${packageData.name}@${packageData.version}`);
  
} catch (error) {
  console.error('❌ Failed to generate SBOM:', error.message);
  process.exit(1);
}

function generateUUID() {
  // Simple UUID v4 generator for SBOM purposes
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}