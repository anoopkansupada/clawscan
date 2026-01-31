/**
 * API Keys Scanner
 * Detects exposed API keys and secrets in source files
 */

import type { Scanner, ScanContext, Finding, KeyPattern } from '../types';

/**
 * Mask a secret, showing only first and last 4 characters
 */
function maskSecret(secret: string): string {
  if (secret.length <= 12) {
    return secret.slice(0, 4) + '...' + secret.slice(-4);
  }
  return secret.slice(0, 4) + '...' + secret.slice(-4);
}

/**
 * Check if a match looks like a placeholder
 */
function isPlaceholder(match: string, pattern?: RegExp): boolean {
  if (pattern && pattern.test(match)) {
    return true;
  }
  // Common placeholder patterns
  const commonPlaceholders = [
    /your[_-]?.*[_-]?key/i,
    /xxx+/i,
    /placeholder/i,
    /example/i,
    /test[_-]?key/i,
    /dummy/i,
    /fake/i,
    /sample/i,
  ];
  return commonPlaceholders.some(p => p.test(match));
}

/**
 * API key patterns to detect
 */
export const KEY_PATTERNS: KeyPattern[] = [
  // AI/LLM Providers
  {
    name: 'openRouter',
    service: 'OpenRouter',
    pattern: /sk-or-v1-[a-zA-Z0-9]{64}/g,
    severity: 'critical',
  },
  {
    name: 'openAI',
    service: 'OpenAI',
    pattern: /sk-[a-zA-Z0-9]{48}/g,
    severity: 'critical',
    placeholderPattern: /sk-your|sk-xxx|sk-test|sk-example/i,
  },
  {
    name: 'anthropic',
    service: 'Anthropic',
    pattern: /sk-ant-[a-zA-Z0-9\-_]{95}/g,
    severity: 'critical',
  },

  // Slack
  {
    name: 'slackBotToken',
    service: 'Slack Bot Token',
    pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,
    severity: 'critical',
  },
  {
    name: 'slackAppToken',
    service: 'Slack App Token',
    pattern: /xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]{64}/g,
    severity: 'critical',
  },
  {
    name: 'slackUserToken',
    service: 'Slack User Token',
    pattern: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}/g,
    severity: 'critical',
  },

  // Cloud Providers
  {
    name: 'awsAccessKey',
    service: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
  },
  // NOTE: AWS Secret Key removed - pattern too broad, causes 1000+ false positives
  // AWS secrets are 40 chars of base64 which matches too many things (XML namespaces, comment dividers, etc.)
  // Detection requires context-awareness (looking for aws_secret_access_key=, AWS_SECRET=, etc.)
  // This will be re-added in Phase 2 with context-aware scanning
  {
    name: 'gcpApiKey',
    service: 'Google Cloud API Key',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    severity: 'critical',
  },

  // GitHub
  {
    name: 'githubToken',
    service: 'GitHub Token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
    severity: 'critical',
  },
  {
    name: 'githubOAuth',
    service: 'GitHub OAuth',
    pattern: /gho_[A-Za-z0-9_]{36}/g,
    severity: 'critical',
  },

  // Other Services
  {
    name: 'braveSearch',
    service: 'Brave Search API',
    pattern: /BSA[A-Za-z0-9]{20,}/g,
    severity: 'high',
  },
  {
    name: 'stripeKey',
    service: 'Stripe API Key',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'critical',
  },
  {
    name: 'stripeTestKey',
    service: 'Stripe Test Key',
    pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
    severity: 'medium',
  },
  {
    name: 'twilioKey',
    service: 'Twilio API Key',
    pattern: /SK[a-f0-9]{32}/g,
    severity: 'critical',
  },
  {
    name: 'sendgridKey',
    service: 'SendGrid API Key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: 'critical',
  },

  // Database
  {
    name: 'mongodbUri',
    service: 'MongoDB Connection String',
    pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\/]+/g,
    severity: 'critical',
  },
  {
    name: 'postgresUri',
    service: 'PostgreSQL Connection String',
    pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\/]+/g,
    severity: 'critical',
  },

  // Private Keys
  {
    name: 'privateKey',
    service: 'Private Key',
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    severity: 'critical',
  },
];

/**
 * Files to skip (binary, generated, etc.)
 */
const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
  '.woff', '.woff2', '.ttf', '.eot',
  '.zip', '.tar', '.gz', '.rar',
  '.pdf', '.doc', '.docx',
  '.exe', '.dll', '.so', '.dylib',
  '.lock', '.lockb',
]);

/**
 * Specific files to skip (contain many hashes/base64)
 */
const SKIP_FILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'Cargo.lock',
  'Gemfile.lock',
  'composer.lock',
  'poetry.lock',
]);

/**
 * Directories to skip
 */
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
]);

export class ApiKeysScanner implements Scanner {
  name = 'api-keys';
  description = 'Detects exposed API keys and secrets';
  filePatterns = ['**/*'];

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      // Skip binary files and certain directories
      if (this.shouldSkip(filePath)) {
        continue;
      }

      try {
        const content = await context.readFile(filePath);
        const fileFindings = this.scanContent(filePath, content);
        findings.push(...fileFindings);
      } catch (error) {
        // File might not be readable, skip it
        continue;
      }
    }

    return findings;
  }

  private shouldSkip(filePath: string): boolean {
    // Check extension
    const ext = filePath.substring(filePath.lastIndexOf('.'));
    if (SKIP_EXTENSIONS.has(ext.toLowerCase())) {
      return true;
    }

    // Check specific filenames (lock files contain many hashes that cause false positives)
    const fileName = filePath.split('/').pop() || '';
    if (SKIP_FILES.has(fileName)) {
      return true;
    }

    // Check directory
    const parts = filePath.split('/');
    for (const part of parts) {
      if (SKIP_DIRS.has(part)) {
        return true;
      }
    }

    return false;
  }

  private scanContent(filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const keyPattern of KEY_PATTERNS) {
      // Reset regex state
      keyPattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = keyPattern.pattern.exec(content)) !== null) {
        const matchedText = match[0];

        // Skip placeholders
        if (isPlaceholder(matchedText, keyPattern.placeholderPattern)) {
          continue;
        }

        // Find line number
        const beforeMatch = content.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        const lineContent = lines[lineNumber - 1] || '';
        const column = match.index - beforeMatch.lastIndexOf('\n');

        findings.push({
          scanner: this.name,
          severity: keyPattern.severity,
          title: `Exposed ${keyPattern.service} API Key`,
          description: `Found a ${keyPattern.service} API key. This secret should be stored in environment variables or a secrets manager, not in source code.`,
          file: filePath,
          line: lineNumber,
          column: column,
          match: maskSecret(matchedText),
          fix: `Move this secret to an environment variable (e.g., .env file) and reference it as process.env.${keyPattern.name.toUpperCase()}`,
          cwe: 'CWE-798', // Use of Hard-coded Credentials
        });
      }
    }

    return findings;
  }
}

export const apiKeysScanner = new ApiKeysScanner();
