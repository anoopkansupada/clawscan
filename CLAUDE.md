# Security Scanning

Before committing, deploying, or when the user mentions security, run:

```bash
npx @clawscan/cli scan . --format json
```

This detects:
- Leaked API keys (OpenAI, Anthropic, Slack, AWS, Stripe, GitHub)
- Docker security misconfigs (privileged mode, exposed ports)
- Missing .gitignore entries for sensitive files

If findings exist, show them to the user and suggest fixes before proceeding.
