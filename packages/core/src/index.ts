/**
 * ClawScan Core
 * AI Agent Security Scanner Engine
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import type { Scanner, ScanContext, ScanResult, ScanOptions, Finding, Severity, Reporter } from './types';
import { apiKeysScanner } from './scanners/api-keys';
import { configSecretsScanner } from './scanners/config-secrets';
import { dockerScanner } from './scanners/docker';
import { gitignoreScanner } from './scanners/gitignore';
import { consoleReporter } from './reporters/console';
import { jsonReporter } from './reporters/json';
import { sarifReporter } from './reporters/sarif';

export * from './types';
export { apiKeysScanner } from './scanners/api-keys';
export { configSecretsScanner } from './scanners/config-secrets';
export { dockerScanner } from './scanners/docker';
export { gitignoreScanner } from './scanners/gitignore';
export { consoleReporter } from './reporters/console';
export { jsonReporter } from './reporters/json';
export { sarifReporter } from './reporters/sarif';

/**
 * Default scanners
 */
const DEFAULT_SCANNERS: Scanner[] = [
  apiKeysScanner,
  configSecretsScanner,
  dockerScanner,
  gitignoreScanner,
];

/**
 * Default reporters
 */
const REPORTERS: Record<string, Reporter> = {
  console: consoleReporter,
  json: jsonReporter,
  sarif: sarifReporter,
};

/**
 * Default exclude patterns
 */
const DEFAULT_EXCLUDES = [
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
  '*.lock',
  '*.lockb',
];

/**
 * Recursively get all files in a directory
 */
async function getAllFiles(dir: string, excludes: string[]): Promise<string[]> {
  const files: string[] = [];

  async function walk(currentDir: string) {
    const entries = await readdir(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      const relativePath = relative(dir, fullPath);

      // Check excludes
      const shouldExclude = excludes.some(pattern => {
        if (pattern.includes('*')) {
          // Simple glob matching
          const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
          return regex.test(entry.name);
        }
        return entry.name === pattern || relativePath.includes(pattern);
      });

      if (shouldExclude) {
        continue;
      }

      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        files.push(relativePath);
      }
    }
  }

  await walk(dir);
  return files;
}

/**
 * Create a scan context
 */
function createScanContext(root: string, files: string[]): ScanContext {
  return {
    root,
    files,
    async readFile(path: string): Promise<string> {
      const fullPath = join(root, path);
      return readFile(fullPath, 'utf-8');
    },
    async fileExists(path: string): Promise<boolean> {
      try {
        const fullPath = join(root, path);
        await stat(fullPath);
        return true;
      } catch {
        return false;
      }
    },
  };
}

/**
 * Main scan function
 */
export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const root = options.path;

  // Get all files
  const excludes = options.exclude || DEFAULT_EXCLUDES;
  const files = await getAllFiles(root, excludes);

  // Create context
  const context = createScanContext(root, files);

  // Get scanners to run
  const scannersToRun = options.scanners
    ? DEFAULT_SCANNERS.filter(s => options.scanners!.includes(s.name))
    : DEFAULT_SCANNERS;

  // Run all scanners
  const allFindings: Finding[] = [];

  for (const scanner of scannersToRun) {
    const findings = await scanner.scan(context);

    // Filter by minimum severity if specified
    const filteredFindings = options.minSeverity
      ? findings.filter(f => compareSeverity(f.severity, options.minSeverity!) >= 0)
      : findings;

    allFindings.push(...filteredFindings);
  }

  // Calculate summary
  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of allFindings) {
    summary[finding.severity]++;
  }

  const result: ScanResult = {
    root,
    filesScanned: files.length,
    findings: allFindings,
    durationMs: Date.now() - startTime,
    summary,
  };

  return result;
}

/**
 * Compare severity levels
 * Returns positive if a > b, negative if a < b, 0 if equal
 */
function compareSeverity(a: Severity, b: Severity): number {
  const order: Record<Severity, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  return order[a] - order[b];
}

/**
 * Format results using a reporter
 */
export async function formatResults(result: ScanResult, format: string = 'console'): Promise<string> {
  const reporter = REPORTERS[format];
  if (!reporter) {
    throw new Error(`Unknown format: ${format}. Available formats: ${Object.keys(REPORTERS).join(', ')}`);
  }
  return reporter.report(result);
}

/**
 * Quick scan function that returns formatted output
 */
export async function quickScan(path: string, format: string = 'console'): Promise<string> {
  const result = await scan({ path });
  return formatResults(result, format);
}

/**
 * Check if scan has critical or high findings
 */
export function hasBlockingFindings(result: ScanResult): boolean {
  return result.summary.critical > 0 || result.summary.high > 0;
}
