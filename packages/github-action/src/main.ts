/**
 * ClawScan GitHub Action
 * Runs security scans on PRs and pushes
 */

import { scan, formatResults, hasBlockingFindings, type Severity } from '@clawscan/core';
import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Read GitHub Action input
 */
function getInput(name: string, defaultValue: string = ''): string {
  return process.env[`INPUT_${name.toUpperCase()}`] || defaultValue;
}

/**
 * Set GitHub Action output
 */
function setOutput(name: string, value: string): void {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    const fs = require('node:fs');
    fs.appendFileSync(outputFile, `${name}=${value}\n`);
  }
}

/**
 * Log error annotation
 */
function logError(message: string, file?: string, line?: number): void {
  if (file && line) {
    console.log(`::error file=${file},line=${line}::${message}`);
  } else if (file) {
    console.log(`::error file=${file}::${message}`);
  } else {
    console.log(`::error::${message}`);
  }
}

/**
 * Log warning annotation
 */
function logWarning(message: string, file?: string, line?: number): void {
  if (file && line) {
    console.log(`::warning file=${file},line=${line}::${message}`);
  } else if (file) {
    console.log(`::warning file=${file}::${message}`);
  } else {
    console.log(`::warning::${message}`);
  }
}

/**
 * Main action runner
 */
async function run(): Promise<void> {
  console.log('🔍 ClawScan - AI Agent Security Scanner');
  console.log('');

  // Get inputs
  const path = getInput('path', '.');
  const failOn = getInput('fail-on', 'high') as Severity;
  const outputFormat = getInput('format', 'console');
  const scanners = getInput('scanners', '').split(',').filter(Boolean);
  const excludePatterns = getInput('exclude', '').split(',').filter(Boolean);

  console.log(`📁 Scanning: ${path}`);
  console.log(`🎯 Fail on: ${failOn} severity and above`);
  console.log(`📊 Format: ${outputFormat}`);

  try {
    // Run scan
    const result = await scan({
      path,
      scanners: scanners.length > 0 ? scanners : undefined,
      exclude: excludePatterns.length > 0 ? excludePatterns : undefined,
    });

    // Output console format for logs
    const consoleOutput = await formatResults(result, 'console');
    console.log(consoleOutput);

    // Add PR annotations for each finding
    for (const finding of result.findings) {
      const message = `[${finding.scanner}] ${finding.title}: ${finding.description}`;
      const file = finding.file;
      const line = finding.line;

      if (finding.severity === 'critical' || finding.severity === 'high') {
        logError(message, file, line);
      } else {
        logWarning(message, file, line);
      }
    }

    // Generate SARIF for GitHub Security tab
    const sarifOutput = await formatResults(result, 'sarif');
    const sarifDir = process.env.GITHUB_WORKSPACE || '.';
    const sarifPath = join(sarifDir, 'clawscan-results.sarif');

    await writeFile(sarifPath, sarifOutput);
    console.log(`\n📄 SARIF report written to: ${sarifPath}`);

    // Set outputs
    setOutput('sarif-path', sarifPath);
    setOutput('findings-count', String(result.findings.length));
    setOutput('critical-count', String(result.summary.critical));
    setOutput('high-count', String(result.summary.high));
    setOutput('medium-count', String(result.summary.medium));
    setOutput('low-count', String(result.summary.low));

    // Check if we should fail
    const severityOrder: Record<Severity, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
    };

    const failThreshold = severityOrder[failOn];
    let shouldFail = false;

    if (result.summary.critical > 0 && failThreshold <= 4) shouldFail = true;
    if (result.summary.high > 0 && failThreshold <= 3) shouldFail = true;
    if (result.summary.medium > 0 && failThreshold <= 2) shouldFail = true;
    if (result.summary.low > 0 && failThreshold <= 1) shouldFail = true;

    if (shouldFail) {
      console.log(`\n❌ Failing due to findings at or above ${failOn} severity`);
      process.exit(1);
    }

    console.log('\n✅ Security scan complete');
  } catch (error) {
    console.error(`\n❌ Error: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
