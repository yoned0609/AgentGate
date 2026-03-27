# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AgentGate, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **yoned0609 (via GitHub private message)**
or use [GitHub Security Advisories](https://github.com/yoned0609/AgentGate/security/advisories/new).

We will acknowledge your report within 48 hours and work with you to address the issue.

## Important Security Notes

### Master API Key

The default `MASTER_API_KEY` in `.env.example` is for development only:

```
MASTER_API_KEY=ag_dev_change_me_in_production
```

**You MUST change this before any production or internet-facing deployment.**

### Recommendations

- Always use a strong, unique `MASTER_API_KEY` in production
- Run behind a reverse proxy (nginx, Caddy) with TLS in production
- Restrict network access to the AgentGate port
- Rotate agent API keys regularly via the `/agents/{id}/rotate-key` endpoint
- Monitor audit logs for suspicious patterns

## Supported Versions

| Version | Supported |
|---------|:---------:|
| 0.1.x   | Yes      |
