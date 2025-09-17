// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Binary-to-text converter for auditing Unicode 16.0.0 data serialization
 * 
 * This tool converts the binary format back to human-readable text for:
 * - Verifying round-trip integrity (text -> binary -> text)
 * - Security auditing of the compression/serialization process
 * - Debugging binary format issues
 * - Compliance verification against original Unicode specification
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
// Explicit process import for environments (e.g., Deno with node:compat) where global process may be discouraged
// eslint-disable-next-line n/no-process-env
import process from 'node:process';

export type UnicodeProfile = 'minimal' | 'standard' | 'complete';
export type IdentifierStatus = 'Allowed' | 'Disallowed' | 'Restricted' | 'Obsolete';

export interface UnicodeRangeEntry {
  readonly start: number;
  readonly end: number;
  readonly status: IdentifierStatus;
}

export interface UnicodeConfusableEntry {
  readonly source: string;
  readonly target: string;
}

export interface AuditReport {
  readonly profile: UnicodeProfile;
  readonly identifierRanges: {
    readonly count: number;
    readonly totalCodepoints: number;
    readonly statusBreakdown: Record<IdentifierStatus, number>;
    readonly sampleRanges: UnicodeRangeEntry[];
  };
  readonly confusables: {
    readonly count: number;
    readonly stringTableSize: number;
    readonly avgSourceLength: number;
    readonly avgTargetLength: number;
    readonly sampleMappings: UnicodeConfusableEntry[];
  };
  readonly binarySize: {
    readonly identifierBytes: number;
    readonly confusablesBytes: number;
    readonly totalBytes: number;
  };
  readonly integrity: {
    readonly identifierRangesValid: boolean;
    readonly confusablesValid: boolean;
    readonly errors: string[];
  };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _STATUS_NAMES: readonly IdentifierStatus[] = ['Allowed', 'Disallowed', 'Restricted', 'Obsolete'] as const;

/**
 * Convert binary identifier ranges back to human-readable format
 */
function convertIdentifierRanges(binaryPath: string): UnicodeRangeEntry[] {
  try {
    const data = readFileSync(binaryPath);
    const ranges: UnicodeRangeEntry[] = [];
    
    console.log(`📖 Reading identifier ranges from: ${binaryPath}`);
    console.log(`📊 Binary file size: ${data.length} bytes`);
    
    // New optimized format: 8 bytes per range (4 start + 4 end, all 'Allowed')
    if (data.length % 8 !== 0) {
      throw new Error(`Invalid binary format: file size ${data.length} is not divisible by 8 (expected 8 bytes per range entry)`);
    }
    
    const expectedEntries = data.length / 8;
    console.log(`🔢 Expected entries: ${expectedEntries}`);
    
    for (let offset = 0; offset < data.length; offset += 8) {
      const start = data.readUInt32LE(offset);
      const end = data.readUInt32LE(offset + 4);
      // All stored ranges are 'Allowed' in optimized format
      const status: IdentifierStatus = 'Allowed';
      
      // Validate range
      if (start > end) {
        throw new Error(`Invalid range: start (${start}) > end (${end}) at offset ${offset}`);
      }
      
      if (start > 0x10FFFF || end > 0x10FFFF) {
        throw new Error(`Invalid Unicode code point: ${start} or ${end} exceeds Unicode maximum (0x10FFFF)`);
      }
      
      ranges.push({ start, end, status });
    }
    
    console.log(`✅ Successfully parsed ${ranges.length} identifier ranges`);
    return ranges;
  } catch (error) {
    console.error(`❌ Error reading identifier ranges:`, error);
    throw error;
  }
}

/**
 * Convert binary confusables back to human-readable format
 */
function convertConfusables(binaryPath: string): UnicodeConfusableEntry[] {
  try {
    const data = readFileSync(binaryPath);
    
    console.log(`📖 Reading confusables from: ${binaryPath}`);
    console.log(`📊 Binary file size: ${data.length} bytes`);
    
    if (data.length === 0) {
      console.log(`ℹ️ Empty confusables file (minimal profile)`);
      return [];
    }
    
    if (data.length < 8) {
      throw new Error(`Invalid binary format: file too small (${data.length} bytes, minimum 8 bytes for header)`);
    }
    
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let offset = 0;
    let stringTableSize: number;
    let mappingsCount: number;
    const isVersioned = data.length >= 16 && data[0] === 0x55 && data[1] === 0x31 && data[2] === 0x36 && data[3] === 0x43; // 'U16C'
    if (isVersioned) {
      const version = data[4];
      console.log(`🧾 Detected versioned confusables format v${version}`);
      if (version !== 1) throw new Error(`Unsupported confusables binary version ${version}`);
      stringTableSize = view.getUint32(8, true);
      mappingsCount = view.getUint32(12, true);
      offset = 16;
    } else {
      stringTableSize = view.getUint32(0, true);
      mappingsCount = view.getUint32(4, true);
      offset = 8;
    }

    console.log(`🔢 String table size: ${stringTableSize} bytes (offset ${offset})`);
    console.log(`🔢 Mappings count: ${mappingsCount}`);

    if (offset + stringTableSize + (mappingsCount * 4) > data.length) {
      throw new Error(`Invalid binary format: calculated size exceeds file size`);
    }

    // Decode string table
    const stringTableBytes = data.subarray(offset, offset + stringTableSize);
    const stringTableText = new TextDecoder().decode(stringTableBytes);
    const stringTable = stringTableText.split('\0').filter(s => s.length > 0);
    
    console.log(`📝 String table entries: ${stringTable.length}`);
    console.log(`🔤 Sample strings: ${stringTable.slice(0, 10).map(s => `"${s}"`).join(', ')}`);
    
    // Decode mappings
    const mappings: UnicodeConfusableEntry[] = [];
  offset += stringTableSize;
    
    for (let i = 0; i < mappingsCount; i++) {
      const sourceIndex = view.getUint16(offset, true);
      const targetIndex = view.getUint16(offset + 2, true);
      
      if (sourceIndex >= stringTable.length) {
        throw new Error(`Invalid source index ${sourceIndex} at mapping ${i} (max ${stringTable.length - 1})`);
      }
      
      if (targetIndex >= stringTable.length) {
        throw new Error(`Invalid target index ${targetIndex} at mapping ${i} (max ${stringTable.length - 1})`);
      }
      
      mappings.push({
        source: stringTable[sourceIndex] || '',
        target: stringTable[targetIndex] || ''
      });
      
      offset += 4;
    }
    
    console.log(`✅ Successfully parsed ${mappings.length} confusable mappings`);
    return mappings;
  } catch (error) {
    console.error(`❌ Error reading confusables:`, error);
    throw error;
  }
}

/**
 * Generate comprehensive audit report for a Unicode profile
 */
function generateAuditReport(profile: UnicodeProfile, basePath: string): AuditReport {
  console.log(`\n🔍 Auditing Unicode profile: ${profile.toUpperCase()}`);
  console.log(`📁 Base path: ${basePath}`);
  
  const identifierPath = join(basePath, `unicode-identifier-ranges-${profile}.bin`);
  const confusablesPath = join(basePath, `unicode-confusables-${profile}.bin`);
  
  // Convert binary data
  const identifierRanges = convertIdentifierRanges(identifierPath);
  const confusables = profile === 'minimal' ? [] : convertConfusables(confusablesPath);
  
  // Calculate statistics
  const statusBreakdown: Record<IdentifierStatus, number> = {
    'Allowed': 0,
    'Disallowed': 0,
    'Restricted': 0,
    'Obsolete': 0
  };
  
  let totalCodepoints = 0;
  
  for (const range of identifierRanges) {
    const count = range.end - range.start + 1;
    statusBreakdown[range.status] += count;
    totalCodepoints += count;
  }
  
  const confusablesStats = confusables.length > 0 ? {
    avgSourceLength: confusables.reduce((sum, c) => sum + c.source.length, 0) / confusables.length,
    avgTargetLength: confusables.reduce((sum, c) => sum + c.target.length, 0) / confusables.length,
  } : { avgSourceLength: 0, avgTargetLength: 0 };
  
  // Get file sizes
  const identifierBytes = readFileSync(identifierPath).length;
  const confusablesBytes = profile === 'minimal' ? 0 : readFileSync(confusablesPath).length;
  
  // Integrity checks
  const errors: string[] = [];
  let identifierRangesValid = true;
  let confusablesValid = true;
  
  // Check for overlapping ranges
  const sortedRanges = [...identifierRanges].sort((a, b) => a.start - b.start);
  if (sortedRanges.length > 1) {
    for (let i = 1; i < sortedRanges.length; i++) {
      const prev = sortedRanges[i - 1]!; // safe by loop bounds
      const curr = sortedRanges[i]!;     // safe by loop bounds
      if (prev.end >= curr.start) {
        errors.push(`Overlapping ranges: [${prev.start}-${prev.end}] and [${curr.start}-${curr.end}]`);
        identifierRangesValid = false;
      }
    }
  }
  
  // Check for self-referential confusables
  for (const conf of confusables) {
    if (conf.source === conf.target) {
      errors.push(`Self-referential confusable: "${conf.source}" -> "${conf.target}"`);
      confusablesValid = false;
    }
  }
  
  return {
    profile,
    identifierRanges: {
      count: identifierRanges.length,
      totalCodepoints,
      statusBreakdown,
      sampleRanges: identifierRanges.slice(0, 10)
    },
    confusables: {
      count: confusables.length,
      stringTableSize: 0, // Will be set by caller if needed
      ...confusablesStats,
      sampleMappings: confusables.slice(0, 10)
    },
    binarySize: {
      identifierBytes,
      confusablesBytes,
      totalBytes: identifierBytes + confusablesBytes
    },
    integrity: {
      identifierRangesValid,
      confusablesValid,
      errors
    }
  };
}

/**
 * Export identifier ranges to human-readable text format
 */
function exportIdentifierRangesToText(ranges: UnicodeRangeEntry[], outputPath: string): void {
  const lines: string[] = [];
  
  lines.push('# Unicode 16.0.0 Identifier Ranges - Reconstructed from Binary');
  lines.push('# Format: START..END ; STATUS # [COUNT] DESCRIPTION');
  lines.push('# Generated by binary-to-text-converter.ts');
  lines.push('');
  
  for (const range of ranges) {
    const start = range.start.toString(16).toUpperCase().padStart(4, '0');
    const end = range.end.toString(16).toUpperCase().padStart(4, '0');
    const count = range.end - range.start + 1;
    
    if (range.start === range.end) {
      lines.push(`${start}          ; ${range.status}    # 1        ${getUnicodeDescription(range.start)}`);
    } else {
      lines.push(`${start}..${end}    ; ${range.status}    # [${count}]     RANGE ${start}-${end}`);
    }
  }
  
  const content = lines.join('\n');
  writeFileSync(outputPath, content, 'utf8');
  console.log(`📝 Exported ${ranges.length} ranges to: ${outputPath}`);
}

/**
 * Export confusables to human-readable text format
 */
function exportConfusablesToText(confusables: UnicodeConfusableEntry[], outputPath: string): void {
  const lines: string[] = [];
  
  lines.push('# Unicode 16.0.0 Confusables - Reconstructed from Binary');
  lines.push('# Format: SOURCE -> TARGET');
  lines.push('# Generated by binary-to-text-converter.ts');
  lines.push('');
  
  for (const conf of confusables) {
    const sourceHex = Array.from(conf.source)
      .map(c => c.codePointAt(0)?.toString(16).toUpperCase().padStart(4, '0'))
      .join(' ');
    const targetHex = Array.from(conf.target)
      .map(c => c.codePointAt(0)?.toString(16).toUpperCase().padStart(4, '0'))
      .join(' ');
    
    lines.push(`"${conf.source}" (${sourceHex}) -> "${conf.target}" (${targetHex})`);
  }
  
  const content = lines.join('\n');
  writeFileSync(outputPath, content, 'utf8');
  console.log(`📝 Exported ${confusables.length} confusables to: ${outputPath}`);
}

/**
 * Get Unicode character description (simplified)
 */
function getUnicodeDescription(codePoint: number): string {
  if (codePoint >= 0x0020 && codePoint <= 0x007E) {
    return `ASCII: "${String.fromCodePoint(codePoint)}"`;
  }
  if (codePoint >= 0x0000 && codePoint <= 0x001F) {
    return 'ASCII Control Character';
  }
  if (codePoint >= 0x0080 && codePoint <= 0x00FF) {
    return 'Latin-1 Supplement';
  }
  if (codePoint >= 0x0100 && codePoint <= 0x017F) {
    return 'Latin Extended-A';
  }
  return `Unicode U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
}

/**
 * Main audit function - processes all profiles and generates reports
 */
export async function auditUnicodeData(
  generatedPath: string = join(process.cwd(), 'src/generated'),
  outputDir: string = join(process.cwd(), 'tests/unicode-audit/output')
): Promise<void> {
  console.log('🔍 Starting Unicode Binary Data Audit');
  console.log(`📁 Generated data path: ${generatedPath}`);
  console.log(`📁 Output directory: ${outputDir}`);
  
  // Ensure output directory exists
  try {
    const fs = await import('node:fs/promises');
    await fs.mkdir(outputDir, { recursive: true });
  } catch (error) {
    console.error('Failed to create output directory:', error);
    throw error;
  }
  
  const profiles: UnicodeProfile[] = ['minimal', 'standard', 'complete'];
  const allReports: AuditReport[] = [];
  
  for (const profile of profiles) {
    try {
      const report = generateAuditReport(profile, generatedPath);
      allReports.push(report);
      
      // Export to text files for manual inspection
      const profileOutputDir = join(outputDir, profile);
      try {
        const fs = await import('node:fs/promises');
        await fs.mkdir(profileOutputDir, { recursive: true });
      } catch {
        // Directory might already exist
      }
      
      exportIdentifierRangesToText(
        report.identifierRanges.sampleRanges, 
        join(profileOutputDir, 'identifier-ranges-sample.txt')
      );
      
      if (report.confusables.count > 0) {
        exportConfusablesToText(
          report.confusables.sampleMappings,
          join(profileOutputDir, 'confusables-sample.txt')
        );
      }
      
      // Generate JSON report
      const jsonReport = JSON.stringify(report, null, 2);
      writeFileSync(join(profileOutputDir, 'audit-report.json'), jsonReport);
      
    } catch (error) {
      console.error(`❌ Failed to audit profile ${profile}:`, error);
      allReports.push({
        profile,
        identifierRanges: { count: 0, totalCodepoints: 0, statusBreakdown: { Allowed: 0, Disallowed: 0, Restricted: 0, Obsolete: 0 }, sampleRanges: [] },
        confusables: { count: 0, stringTableSize: 0, avgSourceLength: 0, avgTargetLength: 0, sampleMappings: [] },
        binarySize: { identifierBytes: 0, confusablesBytes: 0, totalBytes: 0 },
        integrity: { identifierRangesValid: false, confusablesValid: false, errors: [error?.toString() || 'Unknown error'] }
      });
    }
  }
  
  // Generate summary report
  console.log('\n📊 AUDIT SUMMARY');
  console.log('================');
  
  for (const report of allReports) {
    console.log(`\n${report.profile.toUpperCase()} Profile:`);
    console.log(`  📏 Binary Size: ${(report.binarySize.totalBytes / 1024).toFixed(1)} KB`);
    console.log(`  🔢 Identifier Ranges: ${report.identifierRanges.count}`);
    console.log(`  🔤 Confusables: ${report.confusables.count}`);
    console.log(`  ✅ Integrity: ${report.integrity.identifierRangesValid && report.integrity.confusablesValid ? 'PASS' : 'FAIL'}`);
    
    if (report.integrity.errors.length > 0) {
      console.log(`  ⚠️  Errors: ${report.integrity.errors.length}`);
      for (const error of report.integrity.errors.slice(0, 3)) {
        console.log(`     - ${error}`);
      }
    }
  }
  
  // Write combined summary
  const summaryPath = join(outputDir, 'audit-summary.json');
  writeFileSync(summaryPath, JSON.stringify(allReports, null, 2));
  console.log(`\n📄 Complete audit report saved to: ${summaryPath}`);
  
  console.log('\n✅ Unicode Binary Data Audit Complete!');
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  auditUnicodeData().catch(console.error);
}