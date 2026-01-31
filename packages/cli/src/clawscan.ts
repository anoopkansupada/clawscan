#!/usr/bin/env bun
/**
 * ClawScan CLI
 * AI Agent Security Scanner
 */

import { scan, formatResults, hasBlockingFindings, type ScanOptions, type Severity } from '../../core/src/index';
import { resolve } from 'node:path';

const VERSION = '0.1.0';

const HELP = `
${'\x1b[1m'}${'\x1b[36m'}ClawScan${'\x1b[0m'} - AI Agent Security Scanner

${'\x1b[1m'}USAGE${'\x1b[0m'}
  clawscan scan <path>           Scan a directory for security issues
  clawscan scan .                Scan current directory
  clawscan --help                Show this help
  clawscan --version             Show version

${'\x1b[1m'}OPTIONS${'\x1b[0m'}
  -f, --format <format>          Output format: console, json, sarif (default: console)
  -s, --severity <level>         Minimum severity to report: critical, high, medium, low, info
  --scanners <list>              Comma-separated list of scanners to run
  --exclude <patterns>           Comma-separated patterns to exclude
  --no-color                     Disable colored output
  --fail-on <level>              Exit with code 1 if findings >= severity (default: high)

${'\x1b[1m'}EXAMPLES${'\x1b[0m'}
  clawscan scan .                                    # Scan current directory
  clawscan scan ~/projects/my-app                    # Scan specific path
  clawscan scan . --format json                      # JSON output
  clawscan scan . --severity high                    # Only show high and critical
  clawscan scan . --fail-on critical                 # Only fail on critical issues

${'\x1b[1m'}SCANNERS${'\x1b[0m'}
  api-keys          Detect exposed API keys and secrets
  config-secrets    Find secrets in config files (coming soon)
  docker            Docker security misconfigurations (coming soon)
  gitignore         Missing gitignore coverage (coming soon)
  volumes           Insecure volume mounts (coming soon)

${'\x1b[1m'}LEARN MORE${'\x1b[0m'}
  https://github.com/anoopkansupada/clawscan
`;

interface CliOptions {
  path: string;
  format: 'console' | 'json' | 'sarif';
  severity?: Severity;
  scanners?: string[];
  exclude?: string[];
  failOn: Severity;
  noColor: boolean;
}

function parseArgs(args: string[]): CliOptions | null {
  const options: CliOptions = {
    path: '.',
    format: 'console',
    failOn: 'high',
    noColor: false,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      console.log(HELP);
      process.exit(0);
    }

    if (arg === '--version' || arg === '-v') {
      console.log(VERSION);
      process.exit(0);
    }

    if (arg === 'scan') {
      i++;
      if (i < args.length && !args[i].startsWith('-')) {
        options.path = args[i];
        i++;
      }
      continue;
    }

    if (arg === '-f' || arg === '--format') {
      i++;
      if (i < args.length) {
        const format = args[i];
        if (['console', 'json', 'sarif'].includes(format)) {
          options.format = format as 'console' | 'json' | 'sarif';
        } else {
          console.error(`Invalid format: ${format}. Use: console, json, sarif`);
          process.exit(1);
        }
      }
      i++;
      continue;
    }

    if (arg === '-s' || arg === '--severity') {
      i++;
      if (i < args.length) {
        const severity = args[i];
        if (['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
          options.severity = severity as Severity;
        } else {
          console.error(`Invalid severity: ${severity}. Use: critical, high, medium, low, info`);
          process.exit(1);
        }
      }
      i++;
      continue;
    }

    if (arg === '--scanners') {
      i++;
      if (i < args.length) {
        options.scanners = args[i].split(',');
      }
      i++;
      continue;
    }

    if (arg === '--exclude') {
      i++;
      if (i < args.length) {
        options.exclude = args[i].split(',');
      }
      i++;
      continue;
    }

    if (arg === '--fail-on') {
      i++;
      if (i < args.length) {
        const severity = args[i];
        if (['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
          options.failOn = severity as Severity;
        }
      }
      i++;
      continue;
    }

    if (arg === '--no-color') {
      options.noColor = true;
      i++;
      continue;
    }

    // Unknown argument - might be a path
    if (!arg.startsWith('-')) {
      options.path = arg;
    }
    i++;
  }

  return options;
}

async function main() {
  const args = process.argv.slice(2);

  // No arguments - show help
  if (args.length === 0) {
    console.log(HELP);
    process.exit(0);
  }

  const options = parseArgs(args);
  if (!options) {
    process.exit(1);
  }

  // Disable colors if requested
  if (options.noColor) {
    process.env.NO_COLOR = '1';
  }

  // Resolve path
  const scanPath = resolve(options.path);

  console.log(`\n🔍 Scanning ${scanPath}...\n`);

  try {
    const scanOptions: ScanOptions = {
      path: scanPath,
      format: options.format,
      minSeverity: options.severity,
      scanners: options.scanners,
      exclude: options.exclude,
    };

    const result = await scan(scanOptions);
    const output = await formatResults(result, options.format);

    console.log(output);

    // Exit with error code if blocking findings
    if (hasBlockingFindings(result)) {
      const failLevel = options.failOn;
      const severityOrder: Record<Severity, number> = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
        info: 0,
      };

      let shouldFail = false;
      if (result.summary.critical > 0 && severityOrder[failLevel] <= 4) shouldFail = true;
      if (result.summary.high > 0 && severityOrder[failLevel] <= 3) shouldFail = true;
      if (result.summary.medium > 0 && severityOrder[failLevel] <= 2) shouldFail = true;
      if (result.summary.low > 0 && severityOrder[failLevel] <= 1) shouldFail = true;

      if (shouldFail) {
        process.exit(1);
      }
    }

    process.exit(0);
  } catch (error) {
    console.error(`\n❌ Error: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}

main();
