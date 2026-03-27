# AgentGate MVP Development Roadmap

> JIT Authorization Proxy for AI Agents
> Created: 2026-03-24 / Updated: 2026-03-27

---

## Overall Schedule

```
Phase 1: Proxy Foundation
  Step 1: Project Foundation        ✅ Complete
  Step 2: Policy Engine             ✅ Complete
  Step 3: Reverse Proxy             ✅ Complete
  Step 4: Audit Logging             ✅ Complete
  Step 5: Agent Authentication      ✅ Complete

Phase 2: Multi-Provider + Intent Analysis
  Step 6: Multi-Provider Support    ✅ Complete
  (Google Calendar / Microsoft Graph / Slack)

Phase 3: Backend Hardening
  Step 7: Rate Limiting + Quotas    ✅ Complete
  Step 8: Request Validation        ✅ Complete
  Step 9: Policy Engine v2          ✅ Complete
  Step 10: Agent Store Enhancement  ✅ Complete

Phase 4: Operational Quality
  Step 11: Audit Log Enhancement    ✅ Complete
  Step 12: Webhooks / Alerts        ✅ Complete
  Step 13: Docker + CI              ✅ Complete

Phase 5: Integration + Launch Prep
  Step 14: E2E Tests                ✅ Complete
  Step 15: MCP Auth Proxy           ✅ Complete

Phase 6: OSS Preparation + SDKs
  Step 16: MIT License + README      ✅ Complete
  Step 17: Python SDK                ✅ Complete
  Step 18: TypeScript SDK            ✅ Complete
  Step 19: CI SDK Test Jobs          ✅ Complete
```

---

## Phase 1: Proxy Foundation ✅

### Step 1: Project Foundation ✅

- FastAPI project structure
- Pydantic BaseSettings configuration management
- 3-tier logging with loguru (console / file / error-only)
- OWASP security headers middleware
- CORS configuration + health check endpoint

### Step 2: Policy Engine ✅

- Load YAML policy files
- Authorization by HTTP method + URL path (wildcard support)
- Time restrictions (day-of-week + time range, timezone-aware)
- First-match-wins rule evaluation, default deny

### Step 3: Reverse Proxy ✅

Transparent proxy powered by httpx.

```
1. Agent sends request to /proxy/{provider}/{path}
2. Authenticate via X-Agent-Key header
3. Verify provider-agent binding
4. Rate limit check
5. Intent analysis (L1/L2)
6. Policy evaluation
7. Allow → forward to upstream API / Deny → 403 + structured response
8. Record all requests in audit log
```

### Step 4: Audit Logging ✅

Async SQLite storage with provider / intent / intent_confidence columns.

### Step 5: Agent Authentication ✅

API key-based auth + SQLite-backed registry.

---

## Phase 2: Multi-Provider + Intent Analysis ✅

### Step 6: Multi-Provider Support ✅

- Connector architecture: Google Calendar / Microsoft Graph / Slack
- L1 (HTTP method) + L2 (path pattern) two-stage intent analysis
- Slack POST-as-read handling
- Provider-specific policies (5 files)
- Structured denial responses (intent info + alternative suggestions)

---

## Phase 3: Backend Hardening

### Step 7: Rate Limiting + Quotas ✅

- Per-agent sliding window rate limiting (minute/hour)
- `rate_limit` section in policy YAML
- 429 response + `Retry-After` header
- `rate_limited` decision in audit log
- Tests: 7 cases

### Step 8: Request Validation ✅

- Path sanitization (path traversal / null byte prevention)
- Header injection detection
- Request body size limit (1MB)
- Provider-agent binding verification (provider_mismatch 403)
- Tests: 7 cases

### Step 9: Policy Engine v2 ✅

- Intent-based rule evaluation (`intent` field matching)
- Hot reload (`reload_if_changed()` — mtime detection)
- YAML schema validation (required fields, effect values, rule structure)
- Compound conditions (`conditions` with `and`/`or` logic)
- Tests: 19 cases

### Step 10: Agent Store Enhancement ✅

- JSON → SQLite migration (`agents.db`) + auto-migration from legacy JSON
- API key rotation (`POST /agents/{id}/rotate-key`)
- Per-agent usage statistics (`GET /agents/{id}/stats`)
- O(1) API key lookup (in-memory cache)
- `request_count`, `deny_count`, `deny_rate`, `last_request_at` tracking

---

## Phase 4: Operational Quality

### Step 11: Audit Log Enhancement ✅

- Export (`GET /audit/export?format=json|csv`)
- Auto-purge (`POST /audit/purge?retention_days=90`)
- Stats endpoint (`GET /audit/stats` — by_decision, by_provider, deny_rate, avg/max latency)

### Step 12: Webhooks / Alerts ✅

- Deny/rate_limited webhook notifications (`POST /webhooks`)
- Threshold-based alerts (`POST /alerts/thresholds` — count/window/agent_id)
- Cooldown (prevent duplicate alert firing)
- Event log auto-pruning
- Tests: 6 cases

### Step 13: Docker + CI ✅

- Dockerfile (python:3.12-slim, non-root user)
- docker-compose.yaml (volume mount, health check)
- GitHub Actions CI (ruff lint/format + pytest + Docker build verification)

---

## Phase 5: Integration + Launch Prep

### Step 14: E2E Tests ✅

- Full-flow integration tests with mocked upstream (20 cases)
- Allow/deny/rate_limit/provider_mismatch/auth flow verification
- Audit log integration verification (allow/deny → audit entry confirmation)
- Agent lifecycle (create → list → stats → rotate-key → delete)
- Webhook/alert registration flow
- Health/Discovery/Policies endpoints

### Step 15: MCP Auth Proxy ✅

- **MCP JSON-RPC Proxy** — intercepts `tools/call` for policy evaluation
- **Annotation → Policy auto-conversion** — `readOnlyHint`, `destructiveHint`, `idempotentHint` → intent classification → auto-generated rules
- **API endpoints:**
  - `POST /mcp/servers` — Register MCP server + bulk tool annotation registration
  - `POST /mcp/{server_name}` — Forward JSON-RPC requests with authorization
- Non-tools/call methods (resources/list, etc.) are forwarded transparently
- Audit log records provider=mcp, method=MCP:tools/call
- Tests: 14 cases

---

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

---

## Test Status

187 tests passing (as of 2026-03-27)

### Backend (111 tests)

| Test File | Cases | Scope |
|-----------|:-----:|-------|
| test_connectors.py | 8 | Provider connectors |
| test_e2e.py | 20 | E2E integration |
| test_intent.py | 10 | Intent analysis |
| test_mcp.py | 14 | MCP Auth Proxy |
| test_policy.py | 20 | Policy engine v1 |
| test_policy_v2.py | 19 | Policy v2 (intent/reload/validation/conditions) |
| test_rate_limiter.py | 7 | Rate limiting |
| test_validation.py | 7 | Request validation |
| test_webhook.py | 6 | Webhooks & alerts |

### Python SDK (44 tests)

| Test File | Cases | Scope |
|-----------|:-----:|-------|
| test_client.py | 44 | Sync/async client, exception mapping, context managers |

### TypeScript SDK (32 tests)

| Test File | Cases | Scope |
|-----------|:-----:|-------|
| client.test.ts | 32 | All resources, error mapping, auth validation |

---

## Verification Steps

```bash
# Local start
cd backend
python3 -m uvicorn app.main:app --reload --port 8100

# Docker start
docker compose up --build

# Register agent
curl -X POST http://localhost:8100/agents \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-agent", "policy": "default", "provider": "google"}'

# Proxy GET (allowed)
curl http://localhost:8100/proxy/google/calendars/primary/events \
  -H "X-Agent-Key: <returned_api_key>" \
  -H "Authorization: Bearer <Google OAuth token>"

# Proxy DELETE (denied)
curl -X DELETE http://localhost:8100/proxy/google/calendars/primary/events/abc123 \
  -H "X-Agent-Key: <returned_api_key>"

# Audit logs
curl http://localhost:8100/audit/logs \
  -H "X-Master-Key: ag_dev_change_me_in_production"

# Run tests
cd backend && python3 -m pytest -v
```
