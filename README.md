# 🔍 ClawScan

**Find leaked API keys and security problems before hackers do.**

One command. Zero setup. Works instantly.

---

## ⚡ Quick Start

Open your terminal and run:

```bash
npx @clawscan/cli scan .
```

That's it! ClawScan will scan your current folder and show you any security issues.

---

## 📸 What It Looks Like

```
🔍 Scanning /your/project...

╔══════════════════════════════════════════════════════════════╗
║              ClawScan Security Report                        ║
╚══════════════════════════════════════════════════════════════╝

Found 3 issues:

   🚨 CRITICAL: 2
   🔴 HIGH: 1

═══════════════════════════════════════════════════════════════

1. Exposed OpenRouter API Key
   🚨 CRITICAL
   File: .env:13
   Fix: Move this secret to an environment variable

2. Docker Socket Mount
   🚨 CRITICAL
   File: docker-compose.yml:15
   Fix: Remove the Docker socket mount

3. Missing Gitignore: .env
   🔴 HIGH
   Fix: Add ".env" to your .gitignore file
```

---

## 🛡️ What ClawScan Finds

| Issue | Why It Matters |
|-------|----------------|
| **Leaked API Keys** | OpenAI, Slack, AWS, Stripe keys exposed in your code |
| **Docker Problems** | Containers running with dangerous permissions |
| **Missing .gitignore** | Sensitive files that could get committed |
| **Config Secrets** | API keys hidden inside JSON config files |

---

## 💻 Installation Options

### Option 1: Run Without Installing (Recommended)
```bash
npx @clawscan/cli scan .
```

### Option 2: Install Globally
```bash
npm install -g @clawscan/cli
clawscan scan .
```

### Option 3: Using Bun
```bash
bunx @clawscan/cli scan .
```

---

## 📖 Common Commands

```bash
# Scan current folder
clawscan scan .

# Scan a specific folder
clawscan scan ~/my-project

# Only show critical issues
clawscan scan . --severity critical

# Output as JSON (for scripts)
clawscan scan . --format json
```

---

## 🤖 Add to GitHub (Automatic Scanning)

Add this file to your repo at `.github/workflows/security.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run ClawScan
        run: npx @clawscan/cli scan . --fail-on high
```

Now every push will be automatically scanned! 🎉

---

## ❓ FAQ

**Q: Do I need to install anything first?**
A: No! Just run `npx @clawscan/cli scan .` and it works.

**Q: Does it upload my code anywhere?**
A: No. Everything runs locally on your computer. Your code never leaves your machine.

**Q: What if it finds something?**
A: Each finding includes a "Fix" suggestion telling you exactly what to do.

**Q: Can I use this in CI/CD?**
A: Yes! It returns exit code 1 when it finds issues, so your builds will fail appropriately.

---

## 🤖 Make Your AI Agent Auto-Scan

Add this to your project's `CLAUDE.md` (or similar AI config):

```markdown
# Security
Before commits or deployments, run: npx @clawscan/cli scan . --format json
```

Now Claude, Cursor, Copilot, and other AI agents will automatically scan for security issues.

See [AGENTS.md](AGENTS.md) for programmatic API.

---

## 🆘 Need Help?

- [Open an issue](https://github.com/anoopkansupada/clawscan/issues)
- [View the code](https://github.com/anoopkansupada/clawscan)

---

## 📜 License

MIT - Use it however you want!

---

<p align="center">
  <b>Stop shipping secrets. Start scanning.</b><br>
  Made with ❤️ for developers who want to sleep at night.
</p>
