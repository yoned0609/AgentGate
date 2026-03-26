# AgentGate

> The authorization layer MCP doesn't have.

AIエージェント専用のJIT (Just-in-Time) 認可プロキシ。
エージェントのリクエストをリアルタイムで解析し、最小限の権限をその瞬間だけ許可する。

A JIT authorization proxy for AI agents.
Intercepts agent requests in real time, evaluates intent, and enforces least-privilege policies.

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
cp .env.example .env
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

111 tests — run with:

```bash
cd backend
python3 -m pytest -v
```

| File | Tests | Scope |
|------|:-----:|-------|
| test_connectors.py | 8 | Provider connectors |
| test_e2e.py | 20 | End-to-end integration |
| test_intent.py | 10 | Intent analysis |
| test_mcp.py | 14 | MCP Auth Proxy |
| test_policy.py | 20 | Policy engine v1 |
| test_policy_v2.py | 19 | Policy v2 (intent/reload/validation) |
| test_rate_limiter.py | 7 | Rate limiting |
| test_validation.py | 7 | Request validation |
| test_webhook.py | 6 | Webhooks & alerts |

## Docs

| Document | JP | EN |
|----------|----|----|
| Business Plan | [事業企画書](docs/business_plan.md) | [Business Plan](docs/business_plan_en.md) |
| MVP Roadmap | [開発ロードマップ](docs/mvp_dev_roadmap.md) | [Dev Roadmap](docs/mvp_dev_roadmap_en.md) |

## License

TBD
