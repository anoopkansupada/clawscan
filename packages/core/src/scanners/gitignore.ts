/**
 * Gitignore Coverage Scanner
 * Detects missing gitignore entries for sensitive files
 */

import type { Scanner, ScanContext, Finding, Severity } from '../types';

/**
 * Required ignore entries and their importance
 */
interface RequiredIgnore {
  pattern: string;
  description: string;
  severity: Severity;
  checkFiles?: string[]; // If these files exist, it's more important
}

const REQUIRED_IGNORES: RequiredIgnore[] = [
  // Environment files
  {
    pattern: '.env',
    description: 'Environment files often contain API keys and secrets',
    severity: 'critical',
    checkFiles: ['.env', '.env.local', '.env.production'],
  },
  {
    pattern: '.env.*',
    description: 'Environment variant files (.env.local, .env.production) contain secrets',
    severity: 'critical',
  },

  // Private keys and certificates
  {
    pattern: '*.pem',
    description: 'PEM files may contain private keys',
    severity: 'critical',
  },
  {
    pattern: '*.key',
    description: 'Key files contain private cryptographic keys',
    severity: 'critical',
  },
  {
    pattern: '*.p12',
    description: 'P12/PKCS12 files contain certificates and private keys',
    severity: 'high',
  },
  {
    pattern: '*.pfx',
    description: 'PFX files contain certificates and private keys',
    severity: 'high',
  },

  // Common secrets directories
  {
    pattern: 'secrets/',
    description: 'Secrets directories should never be committed',
    severity: 'critical',
    checkFiles: ['secrets/'],
  },
  {
    pattern: '.secrets/',
    description: 'Hidden secrets directories should never be committed',
    severity: 'critical',
  },

  // AI Agent configs that may contain secrets
  {
    pattern: 'openclaw.json',
    description: 'OpenClaw config may contain embedded API keys',
    severity: 'high',
    checkFiles: ['openclaw.json'],
  },
  {
    pattern: 'claude.json',
    description: 'Claude config may contain API keys',
    severity: 'high',
  },

  // Credential files
  {
    pattern: 'credentials.json',
    description: 'Credentials file contains authentication secrets',
    severity: 'critical',
  },
  {
    pattern: '*.credentials',
    description: 'Credential files should not be committed',
    severity: 'high',
  },

  // AWS
  {
    pattern: '.aws/',
    description: 'AWS config directory contains credentials',
    severity: 'critical',
  },

  // SSH
  {
    pattern: '.ssh/',
    description: 'SSH directory contains private keys',
    severity: 'critical',
  },
  {
    pattern: 'id_rsa',
    description: 'SSH private key',
    severity: 'critical',
  },
  {
    pattern: 'id_ed25519',
    description: 'SSH private key',
    severity: 'critical',
  },

  // Database files
  {
    pattern: '*.sqlite',
    description: 'SQLite databases may contain sensitive data',
    severity: 'medium',
  },
  {
    pattern: '*.db',
    description: 'Database files may contain sensitive data',
    severity: 'medium',
  },

  // IDE and editor settings with potential secrets
  {
    pattern: '.idea/',
    description: 'IDE config may contain project-specific secrets',
    severity: 'low',
  },
  {
    pattern: '.vscode/settings.json',
    description: 'VS Code settings may contain project secrets',
    severity: 'low',
  },

  // Logs that may contain sensitive data
  {
    pattern: '*.log',
    description: 'Log files may contain sensitive information',
    severity: 'low',
  },
];

/**
 * Parse gitignore file into patterns
 */
function parseGitignore(content: string): Set<string> {
  const patterns = new Set<string>();

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    // Skip comments and empty lines
    if (trimmed === '' || trimmed.startsWith('#')) {
      continue;
    }
    // Normalize pattern
    patterns.add(trimmed);
    // Also add variations
    if (!trimmed.startsWith('*') && !trimmed.startsWith('/')) {
      patterns.add(`/${trimmed}`);
      patterns.add(`**/${trimmed}`);
    }
  }

  return patterns;
}

/**
 * Check if a pattern is covered by gitignore entries
 */
function isPatternCovered(pattern: string, ignorePatterns: Set<string>): boolean {
  // Direct match
  if (ignorePatterns.has(pattern)) {
    return true;
  }

  // Check with leading slash
  if (ignorePatterns.has(`/${pattern}`)) {
    return true;
  }

  // Check with glob prefix
  if (ignorePatterns.has(`**/${pattern}`)) {
    return true;
  }

  // Check for glob patterns that would match
  const basePattern = pattern.replace(/^\*+\./, '');
  for (const ignorePattern of ignorePatterns) {
    // *.ext matches pattern *.ext
    if (ignorePattern === pattern) {
      return true;
    }
    // .env.* covers .env.local etc
    if (pattern.startsWith('.env') && ignorePattern.includes('.env')) {
      return true;
    }
    // Check if a directory pattern covers subdirectory
    if (pattern.endsWith('/') && ignorePattern.endsWith('/')) {
      if (ignorePattern.includes(pattern.slice(0, -1))) {
        return true;
      }
    }
  }

  return false;
}

export class GitignoreScanner implements Scanner {
  name = 'gitignore';
  description = 'Detects missing gitignore entries for sensitive files';
  filePatterns = ['**/.gitignore'];

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check if .gitignore exists at root
    const hasGitignore = await context.fileExists('.gitignore');

    if (!hasGitignore) {
      // Check if this is a git repo
      const hasGit = await context.fileExists('.git');
      if (hasGit) {
        findings.push({
          scanner: this.name,
          severity: 'critical',
          title: 'Missing .gitignore File',
          description: 'This Git repository has no .gitignore file. Sensitive files could be accidentally committed.',
          file: '.gitignore',
          fix: 'Create a .gitignore file with appropriate entries for your project type. Use https://gitignore.io for templates.',
          cwe: 'CWE-200',
        });
      }
      return findings;
    }

    // Read and parse .gitignore
    let gitignoreContent: string;
    try {
      gitignoreContent = await context.readFile('.gitignore');
    } catch {
      return findings;
    }

    const ignorePatterns = parseGitignore(gitignoreContent);

    // Check each required pattern
    for (const required of REQUIRED_IGNORES) {
      if (!isPatternCovered(required.pattern, ignorePatterns)) {
        // Check if the sensitive file actually exists (makes it more urgent)
        let fileExists = false;
        if (required.checkFiles) {
          for (const checkFile of required.checkFiles) {
            if (await context.fileExists(checkFile)) {
              fileExists = true;
              break;
            }
          }
        }

        // Only flag as critical if file exists, otherwise lower severity
        const effectiveSeverity = fileExists ? required.severity :
          (required.severity === 'critical' ? 'high' : required.severity);

        findings.push({
          scanner: this.name,
          severity: effectiveSeverity,
          title: `Missing Gitignore: ${required.pattern}`,
          description: `Pattern "${required.pattern}" is not in .gitignore. ${required.description}.${fileExists ? ' WARNING: This file exists in your repository!' : ''}`,
          file: '.gitignore',
          fix: `Add "${required.pattern}" to your .gitignore file`,
          cwe: 'CWE-200',
        });
      }
    }

    return findings;
  }
}

export const gitignoreScanner = new GitignoreScanner();
