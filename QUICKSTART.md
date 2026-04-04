# AgentGate — Quick Start Guide for Testers

This guide gets you from zero to a working AgentGate instance in under 5 minutes, **no real API tokens required**.

---

## 1. Start AgentGate (Test Mode)

Test mode returns mock API responses so you can verify all proxy behavior without real credentials.

**Docker (recommended):**

```bash
git clone https://github.com/yoned0609/AgentGate.git
cd AgentGate
TEST_MODE=true docker compose up --build
```

**Local:**

```bash
cd AgentGate/backend
pip install -r requirements.txt
cp .env.example .env
TEST_MODE=true python3 -m uvicorn app.main:app --reload --port 8100
```

Verify it's running:

```bash
curl -s http://localhost:8100/health | jq .
```

Expected output:

```json
{
  "status": "ok",
  "version": "0.3.0",
  "providers": ["google", "microsoft", "slack", "github", "jira", "notion", "linear", "hubspot", "salesforce", "aws"],
  "policy_loaded": true,
  "agents_count": 0,
  "audit_db": "ok"
}
```

---

## 2. Register a Test Agent

```bash
curl -s -X POST http://localhost:8100/agents \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{"name": "tester", "policy": "default", "provider": "google"}' | jq .
```

**Save the `api_key` from the response** — you'll use it as `X-Agent-Key` for all proxy requests.

```json
{
  "agent_id": "abc123...",
  "name": "tester",
  "api_key": "ag_xxxxxxxxxxxxxxxx",   <-- copy this
  "policy": "default",
  "provider": "google"
}
```

---

## 3. Test Proxy Requests

Replace `YOUR_KEY` below with the `api_key` from step 2.

### Allowed request (GET — read-only):

```bash
curl -s http://localhost:8100/proxy/google/calendars/primary/events \
  -H "X-Agent-Key: YOUR_KEY" | jq .
```

You'll get mock calendar events (test mode).

### Denied request (DELETE — blocked by policy):

```bash
curl -s -X DELETE http://localhost:8100/proxy/google/calendars/primary/events/mock-event-001 \
  -H "X-Agent-Key: YOUR_KEY" | jq .
```

You'll get a structured denial:

```json
{
  "error": "access_denied",
  "reason": "Write operations are not permitted under the default policy",
  "intent": { "type": "delete", "resource": "event", "confidence": 0.95 },
  "suggestion": "Use GET to read resources instead, or request a policy that permits delete operations."
}
```

---

## 4. View Audit Logs

Every request (allowed or denied) is logged.

```bash
# Pretty-printed JSON
curl -s "http://localhost:8100/audit/logs?pretty=true" \
  -H "X-Master-Key: ag_dev_change_me_in_production"

# Aggregate stats
curl -s http://localhost:8100/audit/stats \
  -H "X-Master-Key: ag_dev_change_me_in_production" | jq .

# Export as CSV
curl -s "http://localhost:8100/audit/export?format=csv" \
  -H "X-Master-Key: ag_dev_change_me_in_production" -o audit.csv
```

---

## 5. Try Different Policies

AgentGate ships with multiple policies. Register agents with different policies to compare behavior:

| Policy | Description | Rate Limit |
|--------|-------------|------------|
| `default` | Read-only Google Calendar | 30/min |
| `readwrite` | Read + create, no delete | 60/min |
| `read_only` | Strict read-only (GET/HEAD only) | 10/min |
| `rate_limited` | Read + write, very tight limits | 5/min |

```bash
# Register an agent with a strict read-only policy
curl -s -X POST http://localhost:8100/agents \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{"name": "readonly-tester", "policy": "read_only", "provider": "google"}' | jq .

# Register an agent with rate-limited policy (5 req/min)
curl -s -X POST http://localhost:8100/agents \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{"name": "limited-tester", "policy": "rate_limited", "provider": "google"}' | jq .
```

Test rate limiting by making 6+ rapid requests with the `rate_limited` agent:

```bash
for i in $(seq 1 6); do
  echo "--- Request $i ---"
  curl -s http://localhost:8100/proxy/google/calendars/primary/events \
    -H "X-Agent-Key: YOUR_RATE_LIMITED_KEY" | jq -r '.error // .kind'
done
```

---

## 6. Authentication Headers Reference

| Header | Purpose | Example |
|--------|---------|---------|
| `X-Master-Key` | Admin operations | `X-Master-Key: ag_dev_change_me_in_production` |
| `X-Agent-Key` | Proxy requests (per-agent) | `X-Agent-Key: ag_xxxxxxxx` |
| `Authorization` | Upstream API credentials | `Authorization: Bearer <oauth_token>` (not needed in test mode) |

---

## 7. Integration with AI SDKs

AgentGate is a transparent proxy — point your AI framework at `http://localhost:8100/proxy/{provider}/` instead of the real API.

**Python (httpx / requests):**

```python
import httpx

resp = httpx.get(
    "http://localhost:8100/proxy/google/calendars/primary/events",
    headers={"X-Agent-Key": "YOUR_KEY"},
)
print(resp.json())
```

**LangChain:**

Override the base URL in your tool's HTTP client to route through AgentGate, adding the `X-Agent-Key` header.

**TypeScript (fetch):**

```typescript
const res = await fetch(
  'http://localhost:8100/proxy/google/calendars/primary/events',
  { headers: { 'X-Agent-Key': 'YOUR_KEY' } }
);
const data = await res.json();
```

---

## 8. Other Useful Endpoints

```bash
# List available providers
curl -s http://localhost:8100/providers | jq .

# List loaded policies
curl -s http://localhost:8100/policies \
  -H "X-Master-Key: ag_dev_change_me_in_production" | jq .

# List registered agents
curl -s http://localhost:8100/agents \
  -H "X-Master-Key: ag_dev_change_me_in_production" | jq .

# Analytics — latency percentiles
curl -s http://localhost:8100/analytics/latency \
  -H "X-Master-Key: ag_dev_change_me_in_production" | jq .

# Build a policy from natural language
curl -s -X POST http://localhost:8100/policies/build \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{"description": "Allow read-only access to GitHub repos and issues"}' | jq .
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Missing X-Agent-Key header` | Add `-H "X-Agent-Key: YOUR_KEY"` to the request |
| `Invalid agent key` | Check the api_key from the `/agents` POST response |
| `Invalid master key` | Use `ag_dev_change_me_in_production` (default dev key) |
| `Unknown policy` | Check `GET /policies` for available policy names |
| `Provider mismatch` | Agent's `provider` must match the URL (e.g., `google` for `/proxy/google/...`) |

---

*Generated for AgentGate v0.3.0*
