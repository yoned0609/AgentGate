<p align="center">
  <h1 align="center">AgentGate</h1>
  <p align="center"><strong>The authorization layer MCP doesn't have.</strong></p>
  <p align="center">A JIT (Just-in-Time) authorization proxy that intercepts AI agent requests in real time,<br/>analyzes intent, and enforces least-privilege policies — in under 5 ms of overhead.</p>
</p>

<p align="center">
  <a href="https://github.com/yoned0609/AgentGate/actions/workflows/ci.yaml"><img src="https://github.com/yoned0609/AgentGate/actions/workflows/ci.yaml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+"></a>
  <a href="https://github.com/yoned0609/AgentGate/stargazers"><img src="https://img.shields.io/github/stars/yoned0609/AgentGate?style=social" alt="GitHub Stars"></a>
</p>

<p align="center">
  <strong>If AgentGate is useful to you, please consider giving it a star! Your support helps the project grow and reach more developers.</strong>
</p>

---

## The Problem

AI agents are getting powerful API access — but **zero authorization guardrails**.

- **MCP has no enforcement layer.** `readOnlyHint` and `destructiveHint` are advisory annotations. Nothing stops an agent from ignoring them.
- **API keys grant full access.** Most agent integrations use a single OAuth token or API key with no per-action scoping.
- **No audit trail.** When an agent deletes data or exceeds rate limits, there's no centralized log to investigate.

## The Solution

AgentGate is a **transparent proxy** that sits between your AI agent and SaaS APIs. Every request is analyzed, authorized against YAML policies, rate-limited, and logged.

```
AI Agent (MCP Client)
    |
    v
+---------------------------+
|        AgentGate          |
|                           |
|  1. Request Validation    |  <- Path sanitization, body size, header checks
|  2. Agent Authentication  |  <- X-Agent-Key / X-Master-Key
|  3. Rate Limiter          |  <- Sliding window per agent
|  4. Intent Analyzer       |  <- L1 method + L2 path + L3 escalation
|  5. Policy Engine v2      |  <- YAML rules, intent/resource/time matching
|  6. Workflow Guard         |  <- Cross-provider exfiltration detection
|  7. Webhook Notifier      |  <- Deny/alert notifications
|  8. Audit Logger          |  <- SQLite with analytics + export
+---------------------------+
    |
    v
  SaaS API / MCP Server
  (Google, Microsoft, Slack, GitHub, Jira, Notion, Linear, HubSpot, Salesforce, AWS)
```

### How is AgentGate different?

| Solution | Scope | AI Agent Aware? | MCP Support | Intent Analysis |
|----------|-------|:-:|:-:|:-:|
| **AgentGate** | AI agent authorization proxy | Yes | Yes — JSON-RPC interception | L1 method + L2 path + L3 escalation |
| OPA / Rego | General-purpose policy engine | No | No | No |
| Ory Oathkeeper | Identity-aware reverse proxy | No | No | No |
| Kong / Envoy | API gateway / service mesh | No | No | No |
| MCP Annotations | Protocol-level hints | Advisory only | Hints, not enforced | No |

---

## Key Numbers

| Metric | Value |
|--------|-------|
| **Authorization latency** | **0.16 ms** average |
| **Policy accuracy** | **100%** (vs 94% for full-LLM competitor) |
| **Providers supported** | **10** (Google, Microsoft, Slack, GitHub, Jira, Notion, Linear, HubSpot, Salesforce, AWS) |
| **Tests passing** | **277** |
| **Red team attacks survived** | **40 / 40** (after self-healing patches) |

> We built a full-LLM competitor to try to kill AgentGate. It couldn't.
> AgentGate: 100% accuracy, 0.16 ms. LLM competitor: 94% accuracy, 721 ms.
> See [`competitor/`](competitor/) for the full benchmark.

---

## Features

| Feature | Description |
|---------|-------------|
| **Policy Engine v2** | YAML-based rules with intent matching, AND/OR conditions, hot reload, schema validation |
| **10-Provider Proxy** | Google Calendar, Microsoft Graph, Slack, GitHub, Jira, Notion, Linear, HubSpot, Salesforce, AWS |
| **MCP Auth Proxy** | JSON-RPC `tools/call` interception with annotation-to-policy auto-conversion |
| **Intent Analysis (L1-L3)** | L1 HTTP method + L2 path pattern + L3 async escalation with human-in-the-loop |
| **Workflow Guard** | Cross-provider data exfiltration detection |
| **Natural Language Policies** | English-to-YAML instant generation and loading |
| **Rate Limiting** | Per-agent sliding window (minute/hour), configurable per policy |
| **Request Validation** | Path traversal protection, RFC 3986 path normalization, body size limits, header injection prevention |
| **Analytics** | 6 endpoints — time series, deny trends, anomaly detection, latency percentiles, heatmaps |
| **Audit Logging** | SQLite-backed, with stats aggregation, CSV/JSON export, auto-purge |
| **Webhook Alerts** | Deny/rate-limit notifications, threshold-based alerts with cooldown |
| **Agent Management** | SQLite store, API key rotation, per-agent usage statistics |
| **Self-Evolving Red Team** | GateBreaker attack suite (Obfuscator + LogicBomber + Sniper) with automatic patch generation |
| **Docker + CI** | Dockerfile, docker-compose, GitHub Actions (lint + test + build) |

---

## Quick Start

### Local

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # Change MASTER_API_KEY before deploying!
python3 -m uvicorn app.main:app --reload --port 8100
```

### Docker

```bash
docker compose up --build
```

### Basic Usage

```bash
# Register an agent
curl -X POST http://localhost:8100/agents \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-agent", "policy": "default", "provider": "google"}'

# Proxy request (allowed — GET is read-only)
curl http://localhost:8100/proxy/google/calendars/primary/events \
  -H "X-Agent-Key: <api_key>" \
  -H "Authorization: Bearer <oauth_token>"

# Proxy request (denied — DELETE blocked by policy)
curl -X DELETE http://localhost:8100/proxy/google/calendars/primary/events/abc \
  -H "X-Agent-Key: <api_key>"

# View audit logs
curl http://localhost:8100/audit/logs \
  -H "X-Master-Key: ag_dev_change_me_in_production"

# Build a policy from natural language
curl -X POST http://localhost:8100/policies/build \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{"description": "Allow read-only access to GitHub repos and issues"}'
```

### MCP Auth Proxy

```bash
# Register an MCP server with tool annotations
curl -X POST http://localhost:8100/mcp/servers \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-mcp",
    "url": "http://localhost:3001/mcp",
    "tools": [
      {"name": "read_calendar", "annotations": {"readOnlyHint": true}},
      {"name": "delete_event", "annotations": {"destructiveHint": true}}
    ]
  }'

# Send JSON-RPC request through AgentGate
curl -X POST http://localhost:8100/mcp/my-mcp \
  -H "X-Agent-Key: <api_key>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_calendar","arguments":{}}}'
```

---

## API Endpoints

### Proxy
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `*` | `/proxy/{provider}/{path}` | Agent Key | Forward request through policy engine |
| `POST` | `/mcp/{server_name}` | Agent Key | MCP JSON-RPC proxy with authorization |

### Agent Management
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/agents` | Master Key | Register agent |
| `GET` | `/agents` | Master Key | List agents |
| `DELETE` | `/agents/{id}` | Master Key | Delete agent |
| `POST` | `/agents/{id}/rotate-key` | Master Key | Rotate API key |
| `GET` | `/agents/{id}/stats` | Master Key | Usage statistics |

### Analytics
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/analytics/timeseries` | Master Key | Request volume over time |
| `GET` | `/analytics/deny-trends` | Master Key | Denial pattern analysis |
| `GET` | `/analytics/anomalies` | Master Key | Anomaly detection |
| `GET` | `/analytics/latency` | Master Key | Latency percentiles |
| `GET` | `/analytics/heatmap` | Master Key | Activity heatmap |
| `GET` | `/analytics/top-agents` | Master Key | Top agents by volume |

### Audit
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/audit/logs` | Master Key | Query logs (filter, paginate) |
| `GET` | `/audit/stats` | Master Key | Aggregated statistics |
| `GET` | `/audit/export` | Master Key | Export as JSON or CSV |
| `POST` | `/audit/purge` | Master Key | Delete old logs |

### Configuration
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/policies` | Master Key | List loaded policies |
| `POST` | `/policies/build` | Master Key | Natural language policy builder |
| `POST` | `/webhooks` | Master Key | Register webhook |
| `POST` | `/alerts/thresholds` | Master Key | Register alert threshold |
| `POST` | `/mcp/servers` | Master Key | Register MCP server |

### Discovery
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | — | Health check |
| `GET` | `/providers` | — | Available providers |
| `GET` | `/` | — | Service info |

---

## Policy Example

```yaml
name: default
description: "Read-only access"

rules:
  - resource: "/calendars/*/events"
    methods: ["GET"]
    effect: allow

  - resource: "/calendars/*/events"
    methods: ["POST", "DELETE"]
    effect: deny
    reason: "Write operations not permitted"

  # Intent-based rule (v2)
  - intent: ["read", "query"]
    effect: allow

  # Compound conditions (v2)
  - resource: "/sensitive/*"
    effect: allow
    conditions:
      and:
        - intent: read
        - methods: ["GET"]

default_effect: deny

rate_limit:
  enabled: true
  requests_per_minute: 30
  requests_per_hour: 500
```

12 built-in policy templates are included for all supported providers. See [`backend/policies/`](backend/policies/).

---

## SDKs

### Python

```bash
pip install agentgate-sdk
```

```python
from agentgate_sdk import AgentGateClient

# Admin client (master key for management operations)
client = AgentGateClient(base_url="http://localhost:8100", master_key="your-master-key")

# Register an agent
agent = client.agents.create("my-agent", policy="default", provider="google")

# Proxy a request (agent key for proxy operations)
proxy_client = AgentGateClient(base_url="http://localhost:8100", agent_key=agent.api_key)
resp = proxy_client.proxy.request("google", "calendars/primary/events", method="GET")

# Query audit logs
logs = client.audit.logs(limit=10)
```

Async is also supported — see [Python SDK README](sdks/python/README.md).

### TypeScript / Node.js

```bash
npm install agentgate-sdk
```

```typescript
import { AgentGateClient } from 'agentgate-sdk';

const client = new AgentGateClient({
  baseUrl: 'http://localhost:8100',
  masterKey: 'your-master-key',
});

const agent = await client.agents.create({ name: 'my-agent', policy: 'default', provider: 'google' });

const proxyClient = new AgentGateClient({
  baseUrl: 'http://localhost:8100',
  agentKey: agent.apiKey,
});
const events = await proxyClient.proxy.request({ provider: 'google', path: 'calendars/primary/events', method: 'GET' });
```

See [TypeScript SDK README](sdks/typescript/README.md) for full documentation.

---

## Security

AgentGate includes a **self-evolving red team** test suite ([`test_gatebreaker.py`](backend/tests/test_gatebreaker.py)) that attacks its own defenses:

- **Obfuscator** — Path obfuscation (double slashes, URL encoding, Unicode variants)
- **LogicBomber** — ReDoS patterns, policy priority conflicts, permission boundary bugs
- **Sniper** — Concurrency stress, long-path performance degradation

All discovered vulnerabilities are automatically patched and regression-tested. See [`vulnerability_report.json`](backend/vulnerability_report.json) for the latest results.

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12 + FastAPI (async) |
| Proxy | httpx |
| Policy | YAML + fnmatch + segment-aware matching + intent analysis |
| Rate Limit | In-memory sliding window |
| Audit DB | SQLite (aiosqlite) |
| Analytics | Time series, anomaly detection, percentile analysis |
| MCP | JSON-RPC 2.0 proxy |
| Logging | loguru |
| Config | Pydantic BaseSettings |
| Lint | ruff |
| CI | GitHub Actions |
| Container | Docker + docker-compose |

## Tests

277 tests passing — run with:

```bash
# Backend (201 tests)
cd backend && python3 -m pytest -v

# Python SDK (44 tests)
cd sdks/python && python3 -m pytest tests/ -v

# TypeScript SDK (32 tests)
cd sdks/typescript && npm test
```

---

## Docs

| Document | Link |
|----------|------|
| Business Plan | [English](docs/business_plan_en.md) / [Japanese](docs/business_plan.md) |
| Dev Roadmap | [English](docs/mvp_dev_roadmap_en.md) / [Japanese](docs/mvp_dev_roadmap.md) |
| Red Team Report | [vulnerability_report.json](backend/vulnerability_report.json) |
| Market Gap Analysis | [market_gap_analysis.md](competitor/market_gap_analysis.md) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)

---

<p align="center">
  <strong>AgentGate is free and open source.</strong><br/>
  If this project helps secure your AI agents, please <a href="https://github.com/yoned0609/AgentGate">give it a star on GitHub</a>.<br/>
  Stars help others discover the project and motivate continued development.
</p>
