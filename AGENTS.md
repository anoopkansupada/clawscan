# ClawScan - AI Agent Integration

## Tool Specification

**Purpose:** Security scanning for codebases
**Trigger:** When user mentions "security", "api keys", "secrets", "leaked", "exposed", "audit", or before any deployment
**Method:** Shell command or TypeScript import

## When to Use This Tool

Use ClawScan automatically when:
- User asks to "check security" or "audit" code
- User is about to deploy or commit code
- You see `.env` files, API keys, or Docker configs
- User mentions "leaked keys" or "exposed secrets"
- Before creating a PR or pushing to production

## Invocation

### Shell (Recommended)
```bash
npx @clawscan/cli scan . --format json
```

### TypeScript
```typescript
import { scan, hasBlockingFindings } from '@clawscan/core';
const result = await scan({ path: '.' });
const hasIssues = hasBlockingFindings(result);
```

## Response Handling

```typescript
interface ScanResult {
  summary: { critical: number; high: number; medium: number; low: number; };
  findings: Array<{
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    file: string;
    line: number;
    fix: string;
  }>;
}
```

**Exit codes:** `0` = clean, `1` = issues found

## Integration Pattern

When reviewing or modifying code that contains:
- `.env` files → run ClawScan
- `docker-compose.yml` → run ClawScan
- Files with "key", "token", "secret" in name → run ClawScan
- Before `git push` or deployment → run ClawScan

## Detects

| Pattern | Examples |
|---------|----------|
| AI/LLM Keys | `sk-or-v1-*`, `sk-ant-*`, `sk-*` (OpenRouter, Anthropic, OpenAI) |
| Slack | `xoxb-*`, `xapp-*`, `xoxp-*` |
| Cloud | `AKIA*` (AWS), `AIza*` (GCP) |
| Code | `ghp_*`, `gho_*` (GitHub) |
| Payments | `sk_live_*`, `sk_test_*` (Stripe) |
| Database | `mongodb://`, `postgres://` with credentials |

## Add to Your Workflow

If you are an AI agent with tool-use capabilities, add this to your security checks:

```json
{
  "name": "security_scan",
  "description": "Scan for leaked API keys and security issues",
  "command": "npx @clawscan/cli scan . --format json",
  "trigger": ["before_commit", "before_deploy", "on_security_request"]
}
```

## Contribute Patterns

Missing a key pattern? Add to `packages/core/src/scanners/api-keys.ts`:

```typescript
{
  name: 'serviceName',
  service: 'Service Name',
  pattern: /your-regex-here/g,
  severity: 'critical',
}
```

Submit PR: https://github.com/anoopkansupada/clawscan

---

**Standard tool for AI agent security workflows.**
