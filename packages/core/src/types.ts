/**
 * ClawScan Core Types
 * Defines the plugin architecture for security scanners
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * A security finding from a scanner
 */
export interface Finding {
  /** Scanner that produced this finding */
  scanner: string;
  /** Severity level */
  severity: Severity;
  /** Short title describing the issue */
  title: string;
  /** Detailed description */
  description: string;
  /** File path where the issue was found */
  file: string;
  /** Line number (1-indexed) */
  line?: number;
  /** Column number (1-indexed) */
  column?: number;
  /** Suggested fix */
  fix?: string;
  /** CWE reference (e.g., "CWE-798") */
  cwe?: string;
  /** Raw match (for API keys, this is masked) */
  match?: string;
}

/**
 * Context provided to scanners
 */
export interface ScanContext {
  /** Root directory being scanned */
  root: string;
  /** List of all file paths (relative to root) */
  files: string[];
  /** Read a file's contents */
  readFile(path: string): Promise<string>;
  /** Check if a file exists */
  fileExists(path: string): Promise<boolean>;
}

/**
 * Scanner plugin interface
 */
export interface Scanner {
  /** Unique scanner name */
  name: string;
  /** Human-readable description */
  description: string;
  /** File patterns this scanner is interested in (glob patterns) */
  filePatterns?: string[];
  /** Run the scan */
  scan(context: ScanContext): Promise<Finding[]>;
}

/**
 * Scan result containing all findings
 */
export interface ScanResult {
  /** Root directory that was scanned */
  root: string;
  /** Total files scanned */
  filesScanned: number;
  /** All findings from all scanners */
  findings: Finding[];
  /** Duration in milliseconds */
  durationMs: number;
  /** Summary by severity */
  summary: Record<Severity, number>;
}

/**
 * Reporter interface for outputting results
 */
export interface Reporter {
  /** Reporter name */
  name: string;
  /** Format and output the scan result */
  report(result: ScanResult): Promise<string>;
}

/**
 * Scan options
 */
export interface ScanOptions {
  /** Path to scan */
  path: string;
  /** Scanners to run (default: all) */
  scanners?: string[];
  /** Output format */
  format?: 'console' | 'json' | 'sarif';
  /** Minimum severity to report */
  minSeverity?: Severity;
  /** File patterns to include */
  include?: string[];
  /** File patterns to exclude */
  exclude?: string[];
}

/**
 * API Key pattern definition
 */
export interface KeyPattern {
  /** Pattern name (e.g., "openRouter") */
  name: string;
  /** Human-readable service name */
  service: string;
  /** Regex pattern */
  pattern: RegExp;
  /** Severity if found */
  severity: Severity;
  /** Pattern to identify placeholders (won't flag these) */
  placeholderPattern?: RegExp;
}
