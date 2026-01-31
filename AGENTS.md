# ClawScan - For AI Agents

## Quick Integration

```typescript
import { scan } from '@clawscan/core';

const result = await scan({ path: '.' });

if (result.summary.critical > 0) {
  console.log('CRITICAL security issues found!');
}
```

## One-Liner Shell Command

```bash
npx @clawscan/cli scan . --format json
```

## API Reference

### scan(options): Promise<ScanResult>

Scans a directory for security issues.

```typescript
interface ScanOptions {
  path: string;                    // Directory to scan
  scanners?: string[];             // ['api-keys', 'docker', 'gitignore', 'config-secrets']
  minSeverity?: Severity;          // 'critical' | 'high' | 'medium' | 'low' | 'info'
  exclude?: string[];              // Patterns to exclude
}

interface ScanResult {
  root: string;
  filesScanned: number;
  durationMs: number;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

interface Finding {
  scanner: string;      // Which scanner found this
  severity: Severity;   // How bad is it
  title: string;        // Short description
  description: string;  // Full explanation
  file: string;         // File path
  line?: number;        // Line number
  fix?: string;         // How to fix it
  cwe?: string;         // CWE reference
}
```

### formatResults(result, format): Promise<string>

Formats scan results.

```typescript
// Formats: 'console' | 'json' | 'sarif'
const json = await formatResults(result, 'json');
const sarif = await formatResults(result, 'sarif');
```

### hasBlockingFindings(result): boolean

Returns true if critical or high severity issues exist.

```typescript
if (hasBlockingFindings(result)) {
  process.exit(1);
}
```

## Available Scanners

| Scanner | Detects |
|---------|---------|
| `api-keys` | OpenRouter, OpenAI, Anthropic, Slack, AWS, GitHub, Stripe, MongoDB, PostgreSQL keys |
| `config-secrets` | Secrets in JSON configs (openclaw.json, config.json) |
| `docker` | Privileged mode, socket mounts, exposed ports, missing read_only |
| `gitignore` | Missing .env, *.pem, *.key, secrets/, credentials.json entries |

## Example: Full Workflow

```typescript
import { scan, formatResults, hasBlockingFindings } from '@clawscan/core';

async function auditProject(path: string) {
  // Run scan
  const result = await scan({
    path,
    minSeverity: 'high',
  });

  // Get JSON output
  const report = await formatResults(result, 'json');

  // Check if action needed
  if (hasBlockingFindings(result)) {
    return {
      success: false,
      issueCount: result.findings.length,
      report: JSON.parse(report),
    };
  }

  return { success: true, issueCount: 0 };
}
```

## Exit Codes (CLI)

| Code | Meaning |
|------|---------|
| 0 | No blocking issues |
| 1 | Critical or high severity issues found |

## Install

```bash
npm install @clawscan/core    # For programmatic use
npm install -g @clawscan/cli  # For CLI
```
