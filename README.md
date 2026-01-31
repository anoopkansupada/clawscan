# ClawScan 🔍

**AI Agent Security Scanner** - Detect exposed API keys, misconfigurations, and vulnerabilities in AI agent deployments.

[![npm version](https://img.shields.io/npm/v/@clawscan/cli.svg)](https://www.npmjs.com/package/@clawscan/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why ClawScan?

AI agents like OpenClaw, Claude Code, and custom LLM bots often require API keys, Docker configurations, and sensitive credentials. ClawScan helps you:

- **Find exposed API keys** before they're committed
- **Audit Docker configurations** for security misconfigurations
- **Check gitignore coverage** for sensitive files
- **Integrate with CI/CD** via GitHub Actions with SARIF support

## Quick Start

```bash
# Scan current directory
bunx @clawscan/cli scan .

# Scan with JSON output
clawscan scan . --format json

# Only show critical and high severity
clawscan scan . --severity high

# Generate SARIF for GitHub Security tab
clawscan scan . --format sarif > results.sarif
```

## Installation

```bash
# Using bun (recommended)
bun add -g @clawscan/cli

# Using npm
npm install -g @clawscan/cli

# Or run directly with bunx/npx
bunx @clawscan/cli scan .
```

## Scanners

### 🔑 API Keys (`api-keys`)
Detects exposed API keys and secrets:
- **AI/LLM Providers**: OpenRouter, OpenAI, Anthropic
- **Communication**: Slack Bot/App/User tokens
- **Cloud**: AWS Access Keys, Google Cloud API Keys
- **Code**: GitHub tokens (PAT, OAuth, App)
- **Payments**: Stripe (live and test keys)
- **Databases**: MongoDB, PostgreSQL connection strings
- **Other**: Twilio, SendGrid, Brave Search, Private Keys

### 📁 Config Secrets (`config-secrets`)
Finds secrets embedded in configuration files:
- `openclaw.json` - OpenClaw bot configurations
- `config.json`, `settings.json` - General configs
- Reports the exact JSON path where secrets are found

### 🐳 Docker (`docker`)
Audits Docker and docker-compose security:

| Check | Severity | Description |
|-------|----------|-------------|
| Privileged Mode | CRITICAL | Container has full host access |
| Docker Socket Mount | CRITICAL | Allows container escape |
| External Port Binding | HIGH | Ports exposed to 0.0.0.0 |
| Missing Read-Only FS | HIGH | Writable container filesystem |
| Missing no-new-privileges | MEDIUM | Privilege escalation possible |
| Sensitive Volume Mounts | HIGH | Home dirs, /etc mounted |
| Using :latest Tag | MEDIUM | Non-reproducible builds |
| Curl-Bash Pattern | HIGH | Insecure installation scripts |

### 📋 Gitignore (`gitignore`)
Checks for missing gitignore entries:
- `.env`, `.env.*` - Environment files
- `*.pem`, `*.key` - Private keys
- `secrets/`, `.secrets/` - Secret directories
- `openclaw.json`, `claude.json` - AI configs
- `credentials.json` - Credential files
- `.aws/`, `.ssh/` - Cloud/SSH directories

## CLI Options

```
USAGE
  clawscan scan <path>           Scan a directory for security issues
  clawscan scan .                Scan current directory
  clawscan --help                Show this help
  clawscan --version             Show version

OPTIONS
  -f, --format <format>          Output format: console, json, sarif (default: console)
  -s, --severity <level>         Minimum severity: critical, high, medium, low, info
  --scanners <list>              Comma-separated scanners to run
  --exclude <patterns>           Comma-separated patterns to exclude
  --no-color                     Disable colored output
  --fail-on <level>              Exit with code 1 if findings >= severity (default: high)

EXAMPLES
  clawscan scan .                                    # Scan current directory
  clawscan scan ~/projects/my-app                    # Scan specific path
  clawscan scan . --format json                      # JSON output
  clawscan scan . --severity high                    # Only show high and critical
  clawscan scan . --fail-on critical                 # Only fail on critical issues
```

## GitHub Action

Add ClawScan to your CI/CD pipeline:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  clawscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run ClawScan
        uses: anoopkansupada/clawscan@v1
        with:
          path: '.'
          fail-on: 'high'

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: clawscan-results.sarif
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `fail-on` | Minimum severity to fail (critical, high, medium, low) | `high` |
| `format` | Output format (console, json, sarif) | `console` |
| `scanners` | Comma-separated scanners to run | all |
| `exclude` | Comma-separated patterns to exclude | - |

### Action Outputs

| Output | Description |
|--------|-------------|
| `sarif-path` | Path to generated SARIF file |
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high findings |

## Output Formats

### Console (default)
Pretty terminal output with colors and severity indicators.

### JSON
```json
{
  "version": "1.0.0",
  "scanner": "ClawScan",
  "findings": [
    {
      "scanner": "api-keys",
      "severity": "critical",
      "title": "Exposed OpenRouter API Key",
      "file": ".env",
      "line": 13,
      "fix": "Move to environment variable"
    }
  ]
}
```

### SARIF
SARIF 2.1.0 format for GitHub Security tab integration. Findings appear in the Security tab with full details, fix suggestions, and CWE references.

## Programmatic Usage

```typescript
import { scan, formatResults } from '@clawscan/core';

const result = await scan({
  path: './my-project',
  scanners: ['api-keys', 'docker'],
  minSeverity: 'high',
});

console.log(`Found ${result.findings.length} issues`);

// Get formatted output
const output = await formatResults(result, 'json');
```

## Contributing

Contributions welcome! Please read our contributing guidelines first.

```bash
# Clone the repo
git clone https://github.com/anoopkansupada/clawscan.git
cd clawscan

# Install dependencies
bun install

# Run in development
bun run packages/cli/src/clawscan.ts scan .

# Build all packages
bun run build

# Run tests
bun test
```

## License

MIT License - see [LICENSE](LICENSE) for details.

---

Built with ❤️ for the AI agent community. Stop shipping secrets!
