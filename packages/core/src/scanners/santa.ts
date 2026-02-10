/**
 * Santa integration - macOS binary authorization status
 * https://github.com/google/santa
 * 
 * Reports Santa status and recent blocked/allowed binaries
 */

import { execSync } from "child_process";
import { platform } from "os";

export interface SantaStatus {
  installed: boolean;
  mode?: "Monitor" | "Lockdown";
  version?: string;
  syncServer?: string;
  clientMode?: string;
  rulesCount?: number;
}

export interface SantaEvent {
  path: string;
  decision: "ALLOW" | "BLOCK" | "PENDING";
  reason?: string;
  sha256?: string;
  timestamp?: string;
}

export interface SantaResult {
  success: boolean;
  status: SantaStatus;
  recentEvents?: SantaEvent[];
  error?: string;
}

export async function getSantaStatus(): Promise<SantaResult> {
  if (platform() !== "darwin") {
    return {
      success: false,
      status: { installed: false },
      error: "Santa is only available on macOS",
    };
  }

  try {
    // Check if Santa is installed
    const versionOutput = execSync("santactl version 2>/dev/null || echo 'not installed'", {
      encoding: "utf-8",
    });

    if (versionOutput.includes("not installed")) {
      return {
        success: true,
        status: { installed: false },
      };
    }

    // Parse version
    const versionMatch = versionOutput.match(/santactl\s+\|\s+([\d.]+)/);
    const version = versionMatch?.[1];

    // Get status
    const statusOutput = execSync("santactl status 2>/dev/null || true", {
      encoding: "utf-8",
    });

    const modeMatch = statusOutput.match(/Client Mode\s+\|\s+(\w+)/);
    const rulesMatch = statusOutput.match(/Binary Rules\s+\|\s+(\d+)/);
    const syncMatch = statusOutput.match(/Sync Server\s+\|\s+(.+)/);

    const status: SantaStatus = {
      installed: true,
      version,
      mode: modeMatch?.[1] as "Monitor" | "Lockdown" | undefined,
      rulesCount: rulesMatch ? parseInt(rulesMatch[1]) : undefined,
      syncServer: syncMatch?.[1]?.trim(),
    };

    return { success: true, status };
  } catch (error) {
    return {
      success: false,
      status: { installed: false },
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Check if a specific binary is allowed by Santa
 */
export async function checkBinary(binaryPath: string): Promise<{
  allowed: boolean;
  reason?: string;
}> {
  if (platform() !== "darwin") {
    return { allowed: true, reason: "Santa not available (not macOS)" };
  }

  try {
    const result = execSync(`santactl fileinfo "${binaryPath}" 2>/dev/null || echo 'error'`, {
      encoding: "utf-8",
    });

    if (result.includes("error") || !result.trim()) {
      return { allowed: true, reason: "Unable to check (file may not exist)" };
    }

    const decisionMatch = result.match(/Decision\s+\|\s+(\w+)/);
    const decision = decisionMatch?.[1]?.toUpperCase();

    return {
      allowed: decision !== "BLOCK",
      reason: decision || "Unknown",
    };
  } catch {
    return { allowed: true, reason: "Check failed" };
  }
}
