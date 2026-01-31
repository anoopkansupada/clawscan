/**
 * Docker Security Scanner
 * Detects security misconfigurations in Docker and docker-compose files
 */

import type { Scanner, ScanContext, Finding, Severity } from '../types';

/**
 * Docker files to check
 */
const DOCKER_FILES = [
  'Dockerfile',
  'dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  'compose.yml',
  'compose.yaml',
];

/**
 * Dockerfile checks
 */
interface DockerCheck {
  name: string;
  pattern: RegExp;
  antiPattern?: RegExp; // If this pattern is found, don't flag
  severity: Severity;
  title: string;
  description: string;
  fix: string;
  cwe: string;
}

/**
 * Dockerfile checks
 */
const DOCKERFILE_CHECKS: DockerCheck[] = [
  {
    name: 'running-as-root',
    pattern: /^FROM\s+/m, // Has a FROM (is a Dockerfile)
    antiPattern: /^USER\s+(?!root\b)(?!0\b)\w/m, // Has USER instruction with non-root user
    severity: 'high',
    title: 'Dockerfile Runs as Root',
    description: 'No USER instruction found. Container will run as root by default, increasing attack surface.',
    fix: 'Add a USER instruction to run as a non-root user: "USER nonroot" or "USER 1000"',
    cwe: 'CWE-250',
  },
  {
    name: 'using-latest-tag',
    pattern: /FROM\s+\S+:latest\b/i,
    severity: 'medium',
    title: 'Using :latest Tag',
    description: 'Using the :latest tag makes builds non-reproducible and could introduce unexpected changes.',
    fix: 'Pin to a specific version tag, e.g., "FROM node:20-alpine" instead of "FROM node:latest"',
    cwe: 'CWE-1357',
  },
  {
    name: 'add-instead-of-copy',
    pattern: /^ADD\s+(?!https?:)/m,
    severity: 'low',
    title: 'Using ADD Instead of COPY',
    description: 'ADD has extra features (URL fetching, auto-extraction) that could introduce security issues. COPY is more explicit.',
    fix: 'Use COPY instead of ADD unless you specifically need URL fetching or auto-extraction.',
    cwe: 'CWE-829',
  },
  {
    name: 'exposed-secrets-in-env',
    pattern: /ENV\s+\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH)\w*\s*[=\s]\s*["']?[A-Za-z0-9+/=]{16,}/i,
    severity: 'critical',
    title: 'Hardcoded Secret in ENV',
    description: 'Dockerfile contains a hardcoded secret in an ENV instruction. Secrets in Dockerfiles are visible in image layers.',
    fix: 'Use build arguments (ARG) or runtime environment variables. Never commit secrets to Dockerfiles.',
    cwe: 'CWE-798',
  },
  {
    name: 'curl-bash-pattern',
    pattern: /curl\s+[^|]*\|\s*(ba)?sh/i,
    severity: 'high',
    title: 'Curl-Bash Installation Pattern',
    description: 'Piping curl to bash is dangerous. Downloaded scripts could be tampered with or change unexpectedly.',
    fix: 'Download the script first, verify its checksum, then execute it.',
    cwe: 'CWE-829',
  },
  {
    name: 'sensitive-copy',
    pattern: /COPY\s+[^\n]*\.(pem|key|crt|env)\b/i,
    severity: 'high',
    title: 'Copying Sensitive Files',
    description: 'Dockerfile copies potentially sensitive files (.pem, .key, .env). These files may contain secrets.',
    fix: 'Use Docker secrets, environment variables at runtime, or ensure these files are in .dockerignore.',
    cwe: 'CWE-312',
  },
];

/**
 * Docker-compose checks (regex-based for reliability)
 */
const COMPOSE_CHECKS: DockerCheck[] = [
  {
    name: 'privileged-mode',
    pattern: /^\s+privileged:\s*true\b/m,
    severity: 'critical',
    title: 'Privileged Container Mode',
    description: 'A service is running in privileged mode, giving it full access to the host system. This allows container escape and complete host compromise.',
    fix: 'Remove "privileged: true" unless absolutely necessary. Use specific capabilities instead with cap_add.',
    cwe: 'CWE-250',
  },
  {
    name: 'docker-socket-mount',
    pattern: /\/var\/run\/docker\.sock/,
    severity: 'critical',
    title: 'Docker Socket Mount',
    description: 'A service mounts the Docker socket (/var/run/docker.sock). This allows the container to control Docker and escape to the host.',
    fix: 'Remove the Docker socket mount. If Docker access is needed, use Docker-in-Docker (dind) or a remote Docker host.',
    cwe: 'CWE-269',
  },
  {
    name: 'external-port-binding',
    pattern: /ports:\s*\n(?:\s+-\s*["']?(?:0\.0\.0\.0:)?(\d+:\d+)["']?\s*\n?)+/m,
    severity: 'high',
    title: 'Externally Exposed Port',
    description: 'A service has ports exposed that default to 0.0.0.0 (all interfaces). This makes it accessible from outside the host.',
    fix: 'Bind to localhost only: "127.0.0.1:PORT:PORT" or use internal Docker networks.',
    cwe: 'CWE-668',
  },
  {
    name: 'missing-read-only',
    pattern: /^\s+image:/m, // Has a service definition
    antiPattern: /^\s+read_only:\s*true\b/m, // Has read_only
    severity: 'high',
    title: 'Missing Read-Only Filesystem',
    description: 'Services do not have read_only: true. An attacker could write malicious files if a container is compromised.',
    fix: 'Add "read_only: true" to services. Use tmpfs for directories that need writes (e.g., /tmp, /var/run).',
    cwe: 'CWE-732',
  },
  {
    name: 'missing-security-opt',
    pattern: /^\s+image:/m, // Has a service definition
    antiPattern: /no-new-privileges:\s*true/m,
    severity: 'medium',
    title: 'Missing No-New-Privileges',
    description: 'Services are missing the no-new-privileges security option. Processes could escalate privileges using setuid binaries.',
    fix: 'Add "security_opt: [no-new-privileges:true]" to services.',
    cwe: 'CWE-269',
  },
  {
    name: 'sensitive-volume-mount',
    pattern: /~\/\.[a-z]+|\/root\/|\/home\/\w+\/\.[a-z]+|\/etc\/(?!localtime|timezone)/,
    severity: 'high',
    title: 'Sensitive Directory Mounted',
    description: 'A sensitive directory (home dotfiles, /root, /etc) is mounted. Container compromise could access or modify host files.',
    fix: 'Use granular mounts for specific files needed, and mount as read-only (:ro) where possible.',
    cwe: 'CWE-732',
  },
  {
    name: 'using-latest-tag',
    pattern: /image:\s*\S+:latest\b/i,
    severity: 'medium',
    title: 'Using :latest Tag',
    description: 'Using the :latest tag makes builds non-reproducible and could introduce unexpected changes.',
    fix: 'Pin to a specific version tag, e.g., "image: node:20-alpine" instead of "image: node:latest"',
    cwe: 'CWE-1357',
  },
];

export class DockerScanner implements Scanner {
  name = 'docker';
  description = 'Detects security misconfigurations in Docker and docker-compose files';
  filePatterns = DOCKER_FILES.map(f => `**/${f}`);

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      const fileName = filePath.split('/').pop() || '';

      // Check if it's a Docker file
      if (!DOCKER_FILES.some(f => fileName.toLowerCase() === f.toLowerCase())) {
        continue;
      }

      try {
        const content = await context.readFile(filePath);

        if (fileName.toLowerCase() === 'dockerfile') {
          const dockerfileFindings = this.scanWithChecks(filePath, content, DOCKERFILE_CHECKS);
          findings.push(...dockerfileFindings);
        } else {
          const composeFindings = this.scanWithChecks(filePath, content, COMPOSE_CHECKS);
          findings.push(...composeFindings);
        }
      } catch (error) {
        continue;
      }
    }

    return findings;
  }

  private scanWithChecks(filePath: string, content: string, checks: DockerCheck[]): Finding[] {
    const findings: Finding[] = [];

    for (const check of checks) {
      // Check if pattern matches
      if (!check.pattern.test(content)) {
        continue;
      }

      // Check if anti-pattern exists (means issue is fixed)
      if (check.antiPattern && check.antiPattern.test(content)) {
        continue;
      }

      // Find line number where pattern appears
      const lines = content.split('\n');
      let lineNumber = 1;

      for (let i = 0; i < lines.length; i++) {
        if (check.pattern.test(lines[i])) {
          lineNumber = i + 1;
          break;
        }
      }

      findings.push({
        scanner: this.name,
        severity: check.severity,
        title: check.title,
        description: check.description,
        file: filePath,
        line: lineNumber,
        fix: check.fix,
        cwe: check.cwe,
      });
    }

    return findings;
  }
}

export const dockerScanner = new DockerScanner();
