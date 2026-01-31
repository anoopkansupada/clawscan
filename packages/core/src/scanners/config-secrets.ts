/**
 * Config Secrets Scanner
 * Detects secrets embedded in configuration files (JSON, YAML)
 * Specifically targets openclaw.json, config.json, settings.json
 */

import type { Scanner, ScanContext, Finding, Severity } from '../types';
import { KEY_PATTERNS } from './api-keys';

/**
 * Config files to check
 */
const CONFIG_FILES = [
  'openclaw.json',
  'config.json',
  'settings.json',
  'credentials.json',
  'secrets.json',
  '.clawrc',
  '.clawrc.json',
];

/**
 * Sensitive JSON paths that commonly contain secrets
 */
const SENSITIVE_PATHS = [
  'env',
  'env.vars',
  'environment',
  'secrets',
  'credentials',
  'api_key',
  'apiKey',
  'api_keys',
  'apiKeys',
  'token',
  'tokens',
  'auth',
  'authentication',
  'channels.slack',
  'integrations',
  'openai',
  'openrouter',
  'anthropic',
  'slack',
  'aws',
  'database',
];

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
 * Check if a value looks like a placeholder
 */
function isPlaceholder(value: string): boolean {
  const placeholders = [
    /^your[_-]/i,
    /xxx+/i,
    /placeholder/i,
    /example/i,
    /test[_-]?key/i,
    /dummy/i,
    /fake/i,
    /sample/i,
    /\$\{.*\}/,  // ${VAR} template
    /\{\{.*\}\}/,  // {{VAR}} template
    /^<.*>$/,  // <placeholder>
    /^TODO/i,
    /^FIXME/i,
    /^CHANGE[_-]?ME/i,
    /^INSERT[_-]/i,
    /^PUT[_-]/i,
    /^REPLACE[_-]/i,
  ];
  return placeholders.some(p => p.test(value));
}

/**
 * Check if a key name suggests it contains a secret
 */
function isSensitiveKey(key: string): boolean {
  const sensitivePatterns = [
    /key$/i,
    /token$/i,
    /secret/i,
    /password/i,
    /credential/i,
    /api[_-]?key/i,
    /auth/i,
    /^sk[_-]/i,
    /^pk[_-]/i,
    /bearer/i,
    /oauth/i,
    /jwt/i,
    /private/i,
    /signing/i,
  ];
  return sensitivePatterns.some(p => p.test(key));
}

/**
 * Recursively extract all string values with their JSON paths
 */
function extractStrings(obj: unknown, path: string = ''): Array<{ path: string; value: string }> {
  const results: Array<{ path: string; value: string }> = [];

  if (typeof obj === 'string') {
    results.push({ path, value: obj });
  } else if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      results.push(...extractStrings(item, `${path}[${index}]`));
    });
  } else if (obj && typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj)) {
      const newPath = path ? `${path}.${key}` : key;
      results.push(...extractStrings(value, newPath));
    }
  }

  return results;
}

/**
 * Determine severity based on key pattern match
 */
function getSeverity(patternName: string): Severity {
  const criticalPatterns = [
    'openRouter',
    'openAI',
    'anthropic',
    'slackBotToken',
    'slackAppToken',
    'awsAccessKey',
    'githubToken',
    'stripeKey',
    'mongodbUri',
    'postgresUri',
    'privateKey',
  ];

  if (criticalPatterns.includes(patternName)) {
    return 'critical';
  }
  return 'high';
}

export class ConfigSecretsScanner implements Scanner {
  name = 'config-secrets';
  description = 'Detects secrets embedded in configuration files';
  filePatterns = CONFIG_FILES.map(f => `**/${f}`);

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      const fileName = filePath.split('/').pop() || '';

      // Only scan known config files
      if (!CONFIG_FILES.includes(fileName)) {
        continue;
      }

      try {
        const content = await context.readFile(filePath);
        const fileFindings = this.scanConfigFile(filePath, content);
        findings.push(...fileFindings);
      } catch (error) {
        // File might not be readable, skip it
        continue;
      }
    }

    return findings;
  }

  private scanConfigFile(filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];

    // Try to parse as JSON
    let config: unknown;
    try {
      config = JSON.parse(content);
    } catch {
      // Not valid JSON, skip
      return findings;
    }

    // Extract all string values with their paths
    const strings = extractStrings(config);

    for (const { path, value } of strings) {
      // Skip empty or very short values
      if (!value || value.length < 10) {
        continue;
      }

      // Skip placeholders
      if (isPlaceholder(value)) {
        continue;
      }

      // Check against known API key patterns
      for (const pattern of KEY_PATTERNS) {
        pattern.pattern.lastIndex = 0;

        if (pattern.pattern.test(value)) {
          // Check if this path or key suggests it's a secret
          const pathLower = path.toLowerCase();
          const isSensitivePath = SENSITIVE_PATHS.some(sp => pathLower.includes(sp.toLowerCase()));
          const keyName = path.split('.').pop() || '';

          findings.push({
            scanner: this.name,
            severity: getSeverity(pattern.name),
            title: `${pattern.service} API Key in Config File`,
            description: `Found a ${pattern.service} API key embedded in configuration file at path "${path}". Secrets should not be stored in config files that may be committed to version control.`,
            file: filePath,
            line: this.findLineNumber(content, value),
            match: maskSecret(value),
            fix: `Move this secret to a .env file and reference it using environment variable substitution. For OpenClaw configs, use "\${OPENROUTER_API_KEY}" syntax.`,
            cwe: 'CWE-312', // Cleartext Storage of Sensitive Information
          });
          break; // Only report once per value
        }
      }

      // Also check for values that look like secrets based on context
      const keyName = path.split('.').pop() || '';
      if (isSensitiveKey(keyName) && this.looksLikeSecret(value)) {
        // Check if we already reported this via pattern matching
        const alreadyReported = findings.some(f => f.file === filePath && f.match === maskSecret(value));

        if (!alreadyReported) {
          findings.push({
            scanner: this.name,
            severity: 'high',
            title: `Potential Secret in Config: ${keyName}`,
            description: `Found a value at "${path}" that appears to be a secret based on its key name and format. Review if this should be moved to environment variables.`,
            file: filePath,
            line: this.findLineNumber(content, value),
            match: maskSecret(value),
            fix: `Move this secret to a .env file and reference it using environment variable substitution.`,
            cwe: 'CWE-312',
          });
        }
      }
    }

    return findings;
  }

  /**
   * Check if a value looks like a secret based on its format
   */
  private looksLikeSecret(value: string): boolean {
    // Too short to be a secret
    if (value.length < 16) {
      return false;
    }

    // Contains mostly alphanumeric with some special chars - typical of API keys
    const alphanumericRatio = (value.match(/[a-zA-Z0-9]/g) || []).length / value.length;
    if (alphanumericRatio < 0.7) {
      return false;
    }

    // Has mixed case and/or numbers - typical of secrets
    const hasUppercase = /[A-Z]/.test(value);
    const hasLowercase = /[a-z]/.test(value);
    const hasNumbers = /[0-9]/.test(value);

    // URLs, paths, etc. are not secrets
    if (value.includes('://') || value.startsWith('/') || value.includes('..')) {
      return false;
    }

    // If it has high entropy characteristics
    return (hasUppercase && hasLowercase) || (hasNumbers && value.length >= 20);
  }

  /**
   * Find the line number where a value appears
   */
  private findLineNumber(content: string, value: string): number {
    const index = content.indexOf(value);
    if (index === -1) {
      return 1;
    }
    return content.substring(0, index).split('\n').length;
  }
}

export const configSecretsScanner = new ConfigSecretsScanner();
