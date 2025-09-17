// SPDX-License-Identifier: LGPL-3.0-or-later
import { getOptimalWorkerCount } from './cpu-detection.ts';
import fc from "fast-check";

/**
 * Configuration for parallel test execution
 */
export interface ParallelTestConfig {
  /** Maximum memory limit in MB per worker */
  memoryLimitMB?: number;
  /** Timeout per batch in milliseconds */
  batchTimeoutMs?: number;
  /** Whether to log progress updates */
  verbose?: boolean;
}

/**
 * Result from a single test batch
 */
export interface BatchResult {
  batchId: number;
  runs: number;
  passed: number;
  failed: number;
  errors: string[];
  duration: number;
}

/**
 * Combined results from all parallel batches
 */
export interface ParallelTestResult {
  totalRuns: number;
  totalPassed: number;
  totalFailed: number;
  allErrors: string[];
  totalDuration: number;
  batchResults: BatchResult[];
}

/**
 * Execute a test function in parallel using Promise.all() instead of Worker threads.
 * This avoids Worker thread serialization overhead and is more memory efficient.
 */
export async function runTestInParallel<T>(
  testFn: (data: T, batchId: number) => Promise<boolean>,
  testData: T[],
  config: ParallelTestConfig = {}
): Promise<ParallelTestResult> {
  const {
    memoryLimitMB: _memoryLimitMB = 400, // Reduced memory limit (unused but kept for API compatibility)
    batchTimeoutMs = 30000,
    verbose = false
  } = config;

  const workerCount = getOptimalWorkerCount();
  const batchSize = Math.max(50, Math.floor(testData.length / workerCount));
  
  if (verbose) {
    console.log(`🚀 Parallel Execution: ${workerCount} concurrent batches of ${batchSize} items each`);
  }

  const results: BatchResult[] = [];
  const batches: Promise<BatchResult>[] = [];

  // Split data into batches and process concurrently
  for (let i = 0; i < testData.length; i += batchSize) {
    const batchData = testData.slice(i, i + batchSize);
    const batchId = Math.floor(i / batchSize);
    
    // Create timeout promise
    const timeoutPromise = new Promise<BatchResult>((_, reject) => {
      setTimeout(() => reject(new Error(`Batch ${batchId} timed out`)), batchTimeoutMs);
    });

    // Create batch execution promise
    const batchPromise = (async () => {
      const startTime = performance.now();
      let passed = 0;
      let failed = 0;
      const errors: string[] = [];

      for (let j = 0; j < batchData.length; j++) {
        const testItem = batchData[j];
        if (testItem === undefined) continue; // Skip undefined items
        
        try {
          const result = await testFn(testItem, batchId);
          if (result) {
            passed++;
          } else {
            failed++;
            errors.push(`Test ${j} in batch ${batchId} returned false`);
          }
        } catch (error) {
          failed++;
          const errorMessage = error instanceof Error ? error.message : String(error);
          errors.push(`Test ${j} in batch ${batchId} threw: ${errorMessage}`);
        }

        // Yield control every 10 tests to prevent blocking
        if (j % 10 === 0) {
          await new Promise(resolve => setTimeout(resolve, 1));
        }
      }

      // Force garbage collection if available
      const gc = (globalThis as unknown as { gc?: () => void }).gc;
      if (gc && Math.random() < 0.1) { // Only 10% of the time to not impact performance
        gc();
      }

      return {
        batchId,
        runs: batchData.length,
        passed,
        failed,
        errors: errors.slice(0, 5), // Limit errors to prevent memory issues
        duration: performance.now() - startTime
      };
    })();

    // Race batch execution against timeout
    batches.push(Promise.race([batchPromise, timeoutPromise]));

    // Limit concurrent batches to prevent memory overflow
    if (batches.length >= workerCount) {
      const completedBatch = await Promise.race(batches.map((p, idx) => p.then(() => idx)));
      const result = await batches[completedBatch];
      if (result) {
        results.push(result);
      }
      batches.splice(completedBatch, 1);
    }
  }

  // Wait for remaining batches
  const remainingResults = await Promise.all(batches);
  results.push(...remainingResults);

  // Aggregate results
  const totalRuns = results.reduce((sum, r) => sum + r.runs, 0);
  const totalPassed = results.reduce((sum, r) => sum + r.passed, 0);
  const totalFailed = results.reduce((sum, r) => sum + r.failed, 0);
  const allErrors = results.flatMap(r => r.errors);
  const totalDuration = Math.max(...results.map(r => r.duration));

  return {
    totalRuns,
    totalPassed,
    totalFailed,
    allErrors,
    totalDuration,
    batchResults: results
  };
}

/**
 * Memory-optimized fast-check property runner for massive test suites.
 * Automatically splits large test runs across CPU cores to prevent memory overflow.
 */
export async function runMassivePropertyTest<T>(
  arb: fc.Arbitrary<T>,
  property: (value: T) => boolean | Promise<boolean>,
  numRuns: number,
  config: ParallelTestConfig = {}
): Promise<void> {
  const { verbose = false, memoryLimitMB = 400 } = config;

  if (verbose) {
    console.log(`🧪 Massive Property Test: ${numRuns} runs across ${getOptimalWorkerCount()} cores`);
  }

  // Calculate safe batch size to prevent memory issues
  const maxBatchSize = Math.min(500, Math.floor(memoryLimitMB / 2)); // Conservative batching
  const batchCount = Math.ceil(numRuns / maxBatchSize);
  
  let totalPassed = 0;
  let totalFailed = 0;
  const allErrors: string[] = [];

  for (let batchIndex = 0; batchIndex < batchCount; batchIndex++) {
    const remainingRuns = numRuns - (batchIndex * maxBatchSize);
    const batchSize = Math.min(maxBatchSize, remainingRuns);
    
    if (verbose && batchIndex % 10 === 0) {
      console.log(`🔄 Processing batch ${batchIndex + 1}/${batchCount} (${batchSize} runs)`);
    }

    // Generate test values for this batch only
    let testValues: T[] = [];
    try {
      testValues = fc.sample(arb, batchSize);

      // Run batch in parallel
      const result = await runTestInParallel(
        async (value: T) => {
          const result = await property(value);
          return result === true;
        },
        testValues,
        { ...config, memoryLimitMB: Math.floor(memoryLimitMB / 4) } // Further reduce memory per parallel batch
      );

      totalPassed += result.totalPassed;
      totalFailed += result.totalFailed;
      allErrors.push(...result.allErrors.slice(0, 3)); // Limit errors to prevent memory buildup

      // Aggressively clear test data to free memory
      if (testValues) {
        testValues.length = 0;
      }
    } finally {
      // Clear reference to help garbage collection
      testValues = [] as T[];
    }

    // Force garbage collection every 10 batches if available  
    const gc = (globalThis as unknown as { gc?: () => void }).gc;
    if (gc && batchIndex % 10 === 0) {
      gc();
    }
    
    // Add small delay to prevent overwhelming the system
    if (batchIndex % 20 === 0) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }

  if (verbose) {
    console.log(`✅ Massive Property Test Complete: ${totalPassed}/${numRuns} passed, ${totalFailed} failed`);
  }

  if (totalFailed > 0) {
    throw new Error(`Property test failed: ${totalFailed}/${numRuns} runs failed. First errors: ${allErrors.slice(0, 3).join(', ')}`);
  }
}