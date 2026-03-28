# AgentGate

[![CI](https://github.com/yoned0609/AgentGate/actions/workflows/ci.yaml/badge.svg)](https://github.com/yoned0609/AgentGate/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)

> The authorization layer MCP doesn't have.

A JIT (Just-in-Time) authorization proxy for AI agents.
Intercepts agent requests in real time, analyzes intent, and enforces least-privilege policies.

---

## Why AgentGate?

AI agents are getting powerful API access — but **zero authorization guardrails**.

- **MCP has no enforcement layer.** `readOnlyHint` and `destructiveHint` are advisory annotations. Nothing stops an agent from ignoring them.
- **API keys grant full access.** Most agent integrations use a single OAuth token or API key with no per-action scoping.
- **No audit trail.** When an agent deletes data or exceeds rate limits, there's no centralized log to investigate.

AgentGate is a **transparent proxy** that sits between your AI agent and SaaS APIs. Every request is analyzed, authorized against YAML policies, rate-limited, and logged — in under 5ms of overhead.

### How is AgentGate different?

| Solution | Scope | AI Agent Aware? | MCP Support | Intent Analysis |
|----------|-------|:-:|:-:|:-:|
| **AgentGate** | AI agent authorization proxy | Yes | Yes — JSON-RPC interception | L1 method + L2 path pattern |
| OPA / Rego | General-purpose policy engine | No | No | No |
| Ory Oathkeeper | Identity-aware reverse proxy | No | No | No |
| Kong / Envoy | API gateway / service mesh | No | No | No |
| MCP Annotations | Protocol-level hints | Advisory only | Hints, not enforced | No |

---

## Features

| Feature | Description |
|---------|-------------|
| **Policy Engine v2** | YAML-based rules with intent matching, AND/OR conditions, hot reload, schema validation |
| **Multi-Provider Proxy** | Google Calendar, Microsoft Graph, Slack — pluggable connector architecture |
| **MCP Auth Proxy** | JSON-RPC `tools/call` interception with annotation-to-policy auto-conversion |
| **Intent Analysis** | L1 (HTTP method) + L2 (path pattern) two-stage classification |
| **Rate Limiting** | Per-agent sliding window (minute/hour), configurable per policy |
| **Request Validation** | Path traversal protection, body size limits, header injection prevention |
| **Audit Logging** | SQLite-backed, with stats aggregation, CSV/JSON export, auto-purge |
| **Webhook Alerts** | Deny/rate-limit notifications, threshold-based alerts with cooldown |
| **Agent Management** | SQLite store, API key rotation, per-agent usage statistics |
| **Docker + CI** | Dockerfile, docker-compose, GitHub Actions (lint + test + build) |

## Architecture

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
|  4. Intent Analyzer       |  <- L1 method + L2 path pattern
|  5. Policy Engine         |  <- YAML rules, intent/resource/time matching
|  6. Webhook Notifier      |  <- Deny/alert notifications
|  7. Audit Logger          |  <- SQLite with stats + export
+---------------------------+
    |
    v
  SaaS API / MCP Server
  (Google, Microsoft, Slack, ...)
```

## Quick Start

### Local

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # ⚠️ Change MASTER_API_KEY before deploying!
python3 -m uvicorn app.main:app --reload --port 8100
```

### Docker

```bash
docker compose up --build
```

### Usage

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

# Audit stats
curl http://localhost:8100/audit/stats \
  -H "X-Master-Key: ag_dev_change_me_in_production"
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
| `POST` | `/webhooks` | Master Key | Register webhook |
| `POST` | `/alerts/thresholds` | Master Key | Register alert threshold |
| `POST` | `/mcp/servers` | Master Key | Register MCP server |

### Discovery
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | — | Health check |
| `GET` | `/providers` | — | Available providers |
| `GET` | `/` | — | Service info |

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

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12 + FastAPI (async) |
| Proxy | httpx |
| Policy | YAML + fnmatch + intent matching |
| Rate Limit | In-memory sliding window |
| Audit DB | SQLite (aiosqlite) |
| Agent Store | SQLite (aiosqlite) |
| MCP | JSON-RPC 2.0 proxy |
| Logging | loguru |
| Config | Pydantic BaseSettings |
| Lint | ruff |
| CI | GitHub Actions |
| Container | Docker + docker-compose |

## Tests

187 tests passing — run with:

```bash
# Backend (111 tests)
cd backend && python3 -m pytest -v

# Python SDK (44 tests)
cd sdks/python && python3 -m pytest tests/ -v

# TypeScript SDK (32 tests)
cd sdks/typescript && npm test
```

| Suite | File | Tests | Scope |
|-------|------|:-----:|-------|
| Backend | test_connectors.py | 8 | Provider connectors |
| Backend | test_e2e.py | 20 | End-to-end integration |
| Backend | test_intent.py | 10 | Intent analysis |
| Backend | test_mcp.py | 14 | MCP Auth Proxy |
| Backend | test_policy.py | 20 | Policy engine v1 |
| Backend | test_policy_v2.py | 19 | Policy v2 (intent/reload/validation) |
| Backend | test_rate_limiter.py | 7 | Rate limiting |
| Backend | test_validation.py | 7 | Request validation |
| Backend | test_webhook.py | 6 | Webhooks & alerts |
| Python SDK | test_client.py | 44 | Sync/async client, exceptions |
| TS SDK | client.test.ts | 32 | All resources, error mapping |

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

// Admin client (masterKey for management operations)
const client = new AgentGateClient({
  baseUrl: 'http://localhost:8100',
  masterKey: 'your-master-key',
});

const agent = await client.agents.create({ name: 'my-agent', policy: 'default', provider: 'google' });

// Proxy client (agentKey for proxy operations)
const proxyClient = new AgentGateClient({
  baseUrl: 'http://localhost:8100',
  agentKey: agent.apiKey,
});
const events = await proxyClient.proxy.request({ provider: 'google', path: 'calendars/primary/events', method: 'GET' });

// Query audit logs
const logs = await client.audit.logs({ limit: 10 });
```

See [TypeScript SDK README](sdks/typescript/README.md) for full documentation.

## Docs

| Document | Link |
|----------|------|
| Business Plan | [English](docs/business_plan_en.md) / [Japanese](docs/business_plan.md) |
| Dev Roadmap | [English](docs/mvp_dev_roadmap_en.md) / [Japanese](docs/mvp_dev_roadmap.md) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting policy.

## License

[MIT](LICENSE)
