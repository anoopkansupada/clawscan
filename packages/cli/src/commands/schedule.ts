/**
 * clawscan schedule - Set up automated security scanning
 * 
 * Supports:
 * - macOS launchd (LaunchAgent)
 * - Linux systemd (timer)
 * - GitHub Actions workflow
 * - cron (fallback)
 */

import { existsSync, mkdirSync, writeFileSync, chmodSync } from "fs";
import { homedir, platform } from "os";
import { join } from "path";
import { execSync } from "child_process";

interface ScheduleOptions {
  frequency: "daily" | "weekly" | "hourly";
  time?: string; // HH:MM for daily/weekly
  day?: string;  // day of week for weekly (0-6, Sun=0)
  path: string;  // path to scan
  notify?: boolean;
  output?: "json" | "table";
}

export async function schedule(options: ScheduleOptions): Promise<void> {
  const os = platform();
  
  console.log("🔧 Setting up automated ClawScan...\n");

  if (os === "darwin") {
    await setupMacOS(options);
  } else if (os === "linux") {
    await setupLinux(options);
  } else {
    await setupCron(options);
  }

  console.log("\n✅ Automated scanning configured!");
  console.log("💡 Run 'clawscan schedule --status' to check setup");
}

async function setupMacOS(options: ScheduleOptions): Promise<void> {
  const launchAgentsDir = join(homedir(), "Library", "LaunchAgents");
  const plistPath = join(launchAgentsDir, "com.clawscan.scheduler.plist");
  
  if (!existsSync(launchAgentsDir)) {
    mkdirSync(launchAgentsDir, { recursive: true });
  }

  const hour = options.time ? parseInt(options.time.split(":")[0]) : 9;
  const minute = options.time ? parseInt(options.time.split(":")[1]) : 0;
  const weekday = options.day ? parseInt(options.day) : 0;

  const calendarInterval = options.frequency === "weekly"
    ? `<key>Weekday</key><integer>${weekday}</integer>
        <key>Hour</key><integer>${hour}</integer>
        <key>Minute</key><integer>${minute}</integer>`
    : options.frequency === "daily"
    ? `<key>Hour</key><integer>${hour}</integer>
        <key>Minute</key><integer>${minute}</integer>`
    : `<key>Minute</key><integer>0</integer>`;

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.clawscan.scheduler</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/env</string>
        <string>npx</string>
        <string>@clawscan/cli</string>
        <string>scan</string>
        <string>${options.path}</string>
        <string>--format</string>
        <string>${options.output || "table"}</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        ${calendarInterval}
    </dict>
    <key>StandardOutPath</key>
    <string>${homedir()}/Library/Logs/clawscan.log</string>
    <key>StandardErrorPath</key>
    <string>${homedir()}/Library/Logs/clawscan.error.log</string>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>`;

  writeFileSync(plistPath, plist);
  console.log(`📄 Created: ${plistPath}`);

  try {
    execSync(`launchctl unload "${plistPath}" 2>/dev/null || true`);
    execSync(`launchctl load "${plistPath}"`);
    console.log("✅ LaunchAgent loaded");
  } catch (e) {
    console.log("⚠️  Run manually: launchctl load " + plistPath);
  }
}

async function setupLinux(options: ScheduleOptions): Promise<void> {
  const systemdUserDir = join(homedir(), ".config", "systemd", "user");
  const servicePath = join(systemdUserDir, "clawscan.service");
  const timerPath = join(systemdUserDir, "clawscan.timer");

  if (!existsSync(systemdUserDir)) {
    mkdirSync(systemdUserDir, { recursive: true });
  }

  const service = `[Unit]
Description=ClawScan Security Scanner

[Service]
Type=oneshot
ExecStart=/usr/bin/env npx @clawscan/cli scan ${options.path} --format ${options.output || "table"}
StandardOutput=append:${homedir()}/.local/share/clawscan/scan.log
StandardError=append:${homedir()}/.local/share/clawscan/error.log

[Install]
WantedBy=default.target`;

  const onCalendar = options.frequency === "weekly"
    ? `Sun *-*-* ${options.time || "09:00"}:00`
    : options.frequency === "daily"
    ? `*-*-* ${options.time || "09:00"}:00`
    : "*:00:00";

  const timer = `[Unit]
Description=ClawScan Scheduled Scan

[Timer]
OnCalendar=${onCalendar}
Persistent=true

[Install]
WantedBy=timers.target`;

  writeFileSync(servicePath, service);
  writeFileSync(timerPath, timer);
  console.log(`📄 Created: ${servicePath}`);
  console.log(`📄 Created: ${timerPath}`);

  try {
    execSync("systemctl --user daemon-reload");
    execSync("systemctl --user enable clawscan.timer");
    execSync("systemctl --user start clawscan.timer");
    console.log("✅ Systemd timer enabled");
  } catch (e) {
    console.log("⚠️  Run manually: systemctl --user enable --now clawscan.timer");
  }
}

async function setupCron(options: ScheduleOptions): Promise<void> {
  const hour = options.time ? options.time.split(":")[0] : "9";
  const minute = options.time ? options.time.split(":")[1] : "0";
  const day = options.day || "0";

  const schedule = options.frequency === "weekly"
    ? `${minute} ${hour} * * ${day}`
    : options.frequency === "daily"
    ? `${minute} ${hour} * * *`
    : `0 * * * *`;

  const cronLine = `${schedule} npx @clawscan/cli scan ${options.path} >> ${homedir()}/.clawscan.log 2>&1`;

  console.log("📋 Add this to your crontab (crontab -e):\n");
  console.log(cronLine);
  console.log("\n");
}

export function generateGitHubAction(scanPath: string = "."): string {
  return `name: Security Scan

on:
  schedule:
    - cron: '0 9 * * 0'  # Weekly on Sunday at 9am UTC
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run ClawScan
        run: npx @clawscan/cli scan ${scanPath} --fail-on high
        
      - name: Run OSV Scanner
        run: |
          go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
          ~/go/bin/osv-scanner scan source -r ${scanPath}
        continue-on-error: true
        
      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: clawscan-report.json
          retention-days: 30
`;
}

export async function showStatus(): Promise<void> {
  const os = platform();
  console.log("📊 ClawScan Schedule Status\n");

  if (os === "darwin") {
    try {
      const result = execSync("launchctl list | grep clawscan || echo 'Not scheduled'", {
        encoding: "utf-8",
      });
      console.log("macOS LaunchAgent:", result.includes("clawscan") ? "✅ Active" : "❌ Not configured");
      
      const logPath = join(homedir(), "Library", "Logs", "clawscan.log");
      if (existsSync(logPath)) {
        console.log(`📄 Logs: ${logPath}`);
      }
    } catch {
      console.log("macOS LaunchAgent: ❌ Not configured");
    }
  } else if (os === "linux") {
    try {
      const result = execSync("systemctl --user is-active clawscan.timer 2>/dev/null || echo 'inactive'", {
        encoding: "utf-8",
      });
      console.log("Systemd Timer:", result.trim() === "active" ? "✅ Active" : "❌ Not configured");
    } catch {
      console.log("Systemd Timer: ❌ Not configured");
    }
  }

  console.log("\n💡 To set up: clawscan schedule --frequency weekly --path .");
}
