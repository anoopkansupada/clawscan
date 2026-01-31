/**
 * JSON Reporter
 * Outputs scan results in JSON format
 */

import type { Reporter, ScanResult } from '../types';

export class JsonReporter implements Reporter {
  name = 'json';
  description = 'JSON output format';

  async report(result: ScanResult): Promise<string> {
    const output = {
      version: '1.0.0',
      scanner: 'ClawScan',
      timestamp: new Date().toISOString(),
      root: result.root,
      filesScanned: result.filesScanned,
      durationMs: result.durationMs,
      summary: result.summary,
      findings: result.findings.map(f => ({
        scanner: f.scanner,
        severity: f.severity,
        title: f.title,
        description: f.description,
        file: f.file,
        line: f.line,
        column: f.column,
        match: f.match,
        fix: f.fix,
        cwe: f.cwe,
      })),
    };

    return JSON.stringify(output, null, 2);
  }
}

export const jsonReporter = new JsonReporter();
