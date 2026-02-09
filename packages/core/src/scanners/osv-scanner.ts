/**
 * OSV-Scanner integration - Dependency vulnerability scanning
 * https://github.com/google/osv-scanner
 */

import { execSync } from "child_process";

export interface OsvFinding {
  id: string;
  package: string;
  version: string;
  severity: "CRITICAL" | "HIGH" | "MODERATE" | "LOW";
  summary: string;
  fixed?: string;
}

export interface OsvResult {
  success: boolean;
  findings: OsvFinding[];
  error?: string;
}

export async function scanDependencies(targetPath: string): Promise<OsvResult> {
  try {
    const result = execSync(
      `osv-scanner scan source -r "${targetPath}" --format json 2>/dev/null || true`,
      { encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 }
    );

    if (!result.trim()) {
      return { success: true, findings: [] };
    }

    const parsed = JSON.parse(result);
    const findings: OsvFinding[] = [];

    for (const result of parsed.results || []) {
      for (const pkg of result.packages || []) {
        for (const vuln of pkg.vulnerabilities || []) {
          findings.push({
            id: vuln.id,
            package: pkg.package?.name || "unknown",
            version: pkg.package?.version || "unknown",
            severity: mapSeverity(vuln.database_specific?.severity),
            summary: vuln.summary || vuln.details?.substring(0, 200) || "No description",
            fixed: vuln.affected?.[0]?.ranges?.[0]?.events?.find((e: any) => e.fixed)?.fixed,
          });
        }
      }
    }

    return { success: true, findings };
  } catch (error) {
    return {
      success: false,
      findings: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function mapSeverity(severity?: string): OsvFinding["severity"] {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MODERATE":
    case "MEDIUM":
      return "MODERATE";
    default:
      return "LOW";
  }
}
