/**
 * SARIF Reporter
 * Outputs scan results in SARIF 2.1.0 format for GitHub Security tab
 */

import type { Reporter, ScanResult, Severity } from '../types';

/**
 * SARIF severity levels
 */
function getSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
    default:
      return 'warning';
  }
}

/**
 * SARIF security severity
 */
function getSecuritySeverity(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return '9.0';
    case 'high':
      return '7.0';
    case 'medium':
      return '5.0';
    case 'low':
      return '3.0';
    case 'info':
      return '1.0';
    default:
      return '5.0';
  }
}

export class SarifReporter implements Reporter {
  name = 'sarif';
  description = 'SARIF 2.1.0 output format for GitHub Security tab';

  async report(result: ScanResult): Promise<string> {
    // Build rules from unique findings
    const rulesMap = new Map<string, {
      id: string;
      name: string;
      shortDescription: string;
      fullDescription: string;
      help: string;
      severity: Severity;
      cwe?: string;
    }>();

    for (const finding of result.findings) {
      const ruleId = `${finding.scanner}/${finding.title.toLowerCase().replace(/\s+/g, '-')}`;
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: finding.title,
          shortDescription: finding.title,
          fullDescription: finding.description,
          help: finding.fix || 'No fix suggestion available.',
          severity: finding.severity,
          cwe: finding.cwe,
        });
      }
    }

    const rules = Array.from(rulesMap.values()).map(rule => ({
      id: rule.id,
      name: rule.name,
      shortDescription: {
        text: rule.shortDescription,
      },
      fullDescription: {
        text: rule.fullDescription,
      },
      help: {
        text: rule.help,
        markdown: `**Fix:** ${rule.help}`,
      },
      properties: {
        'security-severity': getSecuritySeverity(rule.severity),
        tags: [
          'security',
          rule.cwe ? `external/cwe/${rule.cwe.replace('CWE-', '')}` : null,
        ].filter(Boolean),
      },
    }));

    const results = result.findings.map(finding => {
      const ruleId = `${finding.scanner}/${finding.title.toLowerCase().replace(/\s+/g, '-')}`;

      return {
        ruleId,
        level: getSarifLevel(finding.severity),
        message: {
          text: finding.description,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: finding.file,
                uriBaseId: '%SRCROOT%',
              },
              region: {
                startLine: finding.line || 1,
                startColumn: finding.column || 1,
              },
            },
          },
        ],
        fixes: finding.fix ? [
          {
            description: {
              text: finding.fix,
            },
          },
        ] : undefined,
      };
    });

    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'ClawScan',
              informationUri: 'https://github.com/anoopkansupada/clawscan',
              version: '0.1.0',
              rules,
            },
          },
          results,
          invocations: [
            {
              executionSuccessful: true,
              endTimeUtc: new Date().toISOString(),
            },
          ],
        },
      ],
    };

    return JSON.stringify(sarif, null, 2);
  }
}

export const sarifReporter = new SarifReporter();
