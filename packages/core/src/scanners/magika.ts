/**
 * Magika integration - AI-powered file type detection
 * https://github.com/google/magika
 * 
 * Detects disguised malware, misnamed files, and suspicious content
 */

import { execSync } from "child_process";

export interface MagikaResult {
  path: string;
  detectedType: string;
  expectedType?: string;
  confidence: number;
  suspicious: boolean;
  reason?: string;
}

export interface MagikaScanResult {
  success: boolean;
  results: MagikaResult[];
  suspicious: MagikaResult[];
  error?: string;
}

// File extensions that should match their detected type
const EXPECTED_TYPES: Record<string, string[]> = {
  ".js": ["javascript"],
  ".ts": ["typescript"],
  ".py": ["python"],
  ".sh": ["shell"],
  ".json": ["json"],
  ".yml": ["yaml"],
  ".yaml": ["yaml"],
  ".md": ["markdown"],
  ".txt": ["text"],
  ".html": ["html"],
  ".css": ["css"],
  ".exe": ["peexe"],
  ".dll": ["peexe"],
  ".dmg": ["dmg"],
  ".pkg": ["xar"],
  ".zip": ["zip"],
  ".tar": ["tar"],
  ".gz": ["gzip"],
};

export async function scanFiles(targetPath: string): Promise<MagikaScanResult> {
  try {
    const result = execSync(
      `magika -r --json "${targetPath}" 2>/dev/null || true`,
      { encoding: "utf-8", maxBuffer: 50 * 1024 * 1024 }
    );

    if (!result.trim()) {
      return { success: true, results: [], suspicious: [] };
    }

    const lines = result.trim().split("\n").filter(Boolean);
    const results: MagikaResult[] = [];
    const suspicious: MagikaResult[] = [];

    for (const line of lines) {
      try {
        const parsed = JSON.parse(line);
        const path = parsed.path;
        const detectedType = parsed.result?.value?.toUpperCase() || "unknown";
        const confidence = parsed.score || 0;

        // Check if file extension matches detected type
        const ext = path.substring(path.lastIndexOf(".")).toLowerCase();
        const expectedTypes = EXPECTED_TYPES[ext];
        
        let isSuspicious = false;
        let reason: string | undefined;

        if (expectedTypes && !expectedTypes.some(t => detectedType.toLowerCase().includes(t))) {
          isSuspicious = true;
          reason = `Extension ${ext} but detected as ${detectedType}`;
        }

        // Flag executables in unexpected places
        if (["peexe", "macho", "elf"].some(t => detectedType.toLowerCase().includes(t))) {
          if (!path.includes("node_modules") && !path.includes(".git")) {
            isSuspicious = true;
            reason = `Executable detected: ${detectedType}`;
          }
        }

        const result: MagikaResult = {
          path,
          detectedType,
          expectedType: expectedTypes?.join("/"),
          confidence,
          suspicious: isSuspicious,
          reason,
        };

        results.push(result);
        if (isSuspicious) {
          suspicious.push(result);
        }
      } catch {
        // Skip unparseable lines
      }
    }

    return { success: true, results, suspicious };
  } catch (error) {
    return {
      success: false,
      results: [],
      suspicious: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
