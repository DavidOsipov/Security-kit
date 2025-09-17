// SPDX-License-Identifier: LGPL-3.0-or-later
import { cpus } from 'os';
import process from "node:process";

/**
 * Get the optimal number of worker threads for parallel test execution.
 * Uses all available CPU cores minus 1-2 to prevent system overload.
 * Implements the user's requested logic: use all-1 or all-2 cores.
 */
export function getOptimalWorkerCount(): number {
  const totalCores = cpus().length;
  
  if (totalCores <= 1) {
    // Single core system - use the only available core
    return 1;
  } else if (totalCores <= 3) {
    // Low-core systems (2-3 cores) - use all but 1 core
    return totalCores - 1;
  } else {
    // High-core systems (4+ cores) - use all but 2 cores as requested
    return totalCores - 2;
  }
}

/**
 * Calculate optimal batch size for large test runs based on available memory.
 * Prevents JavaScript heap out of memory errors by limiting batch sizes.
 */
export function getOptimalBatchSize(totalRuns: number, memoryLimitMB: number = 1000): number {
  const _totalCores = cpus().length;
  const workerCount = getOptimalWorkerCount();
  
  // Estimate memory per test run (conservative estimate)
  const estimatedMemoryPerRun = 0.1; // MB per test run
  const maxRunsPerBatch = Math.floor(memoryLimitMB / (estimatedMemoryPerRun * workerCount));
  
  // Never exceed 5000 runs per batch to prevent memory issues
  const maxBatchSize = Math.min(5000, maxRunsPerBatch);
  
  // Calculate optimal batch size
  const optimalBatchSize = Math.min(
    maxBatchSize,
    Math.ceil(totalRuns / (workerCount * 4)) // Distribute work across 4 batches per worker
  );
  
  return Math.max(100, optimalBatchSize); // Minimum batch size of 100
}

/**
 * Split a large number of test runs into optimally sized batches for parallel execution.
 */
export function splitIntoOptimalBatches(totalRuns: number, memoryLimitMB?: number): number[] {
  const batchSize = getOptimalBatchSize(totalRuns, memoryLimitMB);
  const batches: number[] = [];
  
  let remaining = totalRuns;
  while (remaining > 0) {
    const currentBatch = Math.min(batchSize, remaining);
    batches.push(currentBatch);
    remaining -= currentBatch;
  }
  
  return batches;
}

/**
 * Get system information for debugging performance issues.
 */
export function getSystemInfo() {
  const systemCpus = cpus();
  const totalCores = systemCpus.length;
  const optimalWorkers = getOptimalWorkerCount();
  
  return {
    totalCores,
    optimalWorkers,
    cpuModel: systemCpus[0]?.model || 'Unknown',
    architecture: process.arch,
    platform: process.platform,
    nodeVersion: process.version,
    memoryUsage: process.memoryUsage(),
  };
}

/**
 * Log performance recommendations based on system capabilities.
 */
export function logPerformanceRecommendations() {
  const info = getSystemInfo();
  
  console.log(`🖥️ System Info:
  CPU Cores: ${info.totalCores}
  Optimal Workers: ${info.optimalWorkers}
  CPU Model: ${info.cpuModel}
  Architecture: ${info.architecture}
  Platform: ${info.platform}
  Node Version: ${info.nodeVersion}
  Memory Usage: ${JSON.stringify(info.memoryUsage, null, 2)}
  `);
  
  if (info.totalCores >= 8) {
    console.log('🚀 High-performance system detected! Using parallel test execution.');
  } else if (info.totalCores >= 4) {
    console.log('⚡ Multi-core system detected. Using optimized parallel execution.');
  } else {
    console.log('💻 Limited core system. Using conservative parallel settings.');
  }
}