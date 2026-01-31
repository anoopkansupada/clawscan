/**
 * Console Reporter
 * Pretty-prints scan results to the terminal
 */

import type { Reporter, ScanResult, Finding, Severity } from '../types';

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: COLORS.bgRed + COLORS.white,
  high: COLORS.red,
  medium: COLORS.yellow,
  low: COLORS.blue,
  info: COLORS.cyan,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '🚨',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
  info: 'ℹ️',
};

function formatSeverity(severity: Severity): string {
  const color = SEVERITY_COLORS[severity];
  const icon = SEVERITY_ICONS[severity];
  return `${icon} ${color}${severity.toUpperCase()}${COLORS.reset}`;
}

function formatFinding(finding: Finding, index: number): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${COLORS.bold}${index + 1}. ${finding.title}${COLORS.reset}`);
  lines.push(`   ${formatSeverity(finding.severity)}`);
  lines.push(`   ${COLORS.dim}Scanner:${COLORS.reset} ${finding.scanner}`);
  lines.push(`   ${COLORS.dim}File:${COLORS.reset} ${COLORS.cyan}${finding.file}${COLORS.reset}${finding.line ? `:${finding.line}` : ''}`);

  if (finding.match) {
    lines.push(`   ${COLORS.dim}Match:${COLORS.reset} ${COLORS.magenta}${finding.match}${COLORS.reset}`);
  }

  lines.push(`   ${COLORS.dim}Description:${COLORS.reset} ${finding.description}`);

  if (finding.fix) {
    lines.push(`   ${COLORS.green}Fix:${COLORS.reset} ${finding.fix}`);
  }

  if (finding.cwe) {
    lines.push(`   ${COLORS.dim}Reference:${COLORS.reset} https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`);
  }

  return lines.join('\n');
}

export class ConsoleReporter implements Reporter {
  name = 'console';

  async report(result: ScanResult): Promise<string> {
    const lines: string[] = [];

    // Header
    lines.push('');
    lines.push(`${COLORS.bold}${COLORS.cyan}╔══════════════════════════════════════════════════════════════╗${COLORS.reset}`);
    lines.push(`${COLORS.bold}${COLORS.cyan}║${COLORS.reset}              ${COLORS.bold}ClawScan Security Report${COLORS.reset}                      ${COLORS.cyan}║${COLORS.reset}`);
    lines.push(`${COLORS.bold}${COLORS.cyan}╚══════════════════════════════════════════════════════════════╝${COLORS.reset}`);
    lines.push('');

    // Summary
    lines.push(`${COLORS.dim}Scanned:${COLORS.reset} ${result.root}`);
    lines.push(`${COLORS.dim}Files:${COLORS.reset} ${result.filesScanned}`);
    lines.push(`${COLORS.dim}Duration:${COLORS.reset} ${result.durationMs}ms`);
    lines.push('');

    // Findings summary
    const totalFindings = result.findings.length;
    if (totalFindings === 0) {
      lines.push(`${COLORS.green}${COLORS.bold}✅ No security issues found!${COLORS.reset}`);
    } else {
      lines.push(`${COLORS.bold}Found ${totalFindings} issue${totalFindings === 1 ? '' : 's'}:${COLORS.reset}`);
      lines.push('');

      // Summary by severity
      const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
      for (const severity of severities) {
        const count = result.summary[severity];
        if (count > 0) {
          lines.push(`   ${formatSeverity(severity)}: ${count}`);
        }
      }

      // Detailed findings
      lines.push('');
      lines.push(`${COLORS.bold}═══════════════════════════════════════════════════════════════${COLORS.reset}`);
      lines.push(`${COLORS.bold}                        Findings${COLORS.reset}`);
      lines.push(`${COLORS.bold}═══════════════════════════════════════════════════════════════${COLORS.reset}`);

      // Sort by severity
      const sortedFindings = [...result.findings].sort((a, b) => {
        const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return order[a.severity] - order[b.severity];
      });

      for (let i = 0; i < sortedFindings.length; i++) {
        lines.push(formatFinding(sortedFindings[i], i));
      }

      // Footer with action items
      lines.push('');
      lines.push(`${COLORS.bold}═══════════════════════════════════════════════════════════════${COLORS.reset}`);

      if (result.summary.critical > 0) {
        lines.push(`${COLORS.red}${COLORS.bold}⚠️  CRITICAL issues found! Fix these immediately.${COLORS.reset}`);
      } else if (result.summary.high > 0) {
        lines.push(`${COLORS.yellow}${COLORS.bold}⚠️  HIGH severity issues found. Review and fix soon.${COLORS.reset}`);
      }
    }

    lines.push('');

    return lines.join('\n');
  }
}

export const consoleReporter = new ConsoleReporter();
