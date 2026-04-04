# AgentGate — Live Demo Guide

Run this demo locally to see AgentGate block a dangerous AI agent request in real time.

**Time required:** ~2 minutes  
**Prerequisites:** Docker (or Python 3.12+), curl, jq (optional)

---

## Option A: Automated Demo Script

```bash
# 1. Start the server in test mode (no real API tokens needed)
TEST_MODE=true docker compose up --build -d

# 2. Wait for the server to be ready
curl --retry 5 --retry-delay 2 --retry-connrefused -sf http://localhost:8100/health > /dev/null

# 3. Run the demo
./scripts/demo.sh
```

The script will walk you through each step with color-coded output:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Step 2 — Allowed Request (GET → read events)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ GET /proxy/google/calendars/primary/events

  ┌──────────────────────────────────────────────────────┐
  │  HTTP 200 — ALLOWED                                   │
  └──────────────────────────────────────────────────────┘
  { "kind": "calendar#events", "items": [...] }

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Step 3 — Blocked Request (DELETE → policy denies)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ DELETE /proxy/google/calendars/primary/events/important-meeting

  ┌──────────────────────────────────────────────────────┐
  │  HTTP 403 — BLOCKED BY POLICY                        │
  └──────────────────────────────────────────────────────┘
  {
    "error": "access_denied",
    "reason": "Write operations are not permitted under the default policy",
    "intent": { "type": "delete", "confidence": 0.95 },
    "suggestion": "Use GET to read resources instead..."
  }
```

Press Enter between each step — perfect for screen recording.

---

## Option B: Step-by-Step Manual Demo

### 1. Start the server

```bash
TEST_MODE=true docker compose up --build -d
```

Verify:

```bash
curl -s http://localhost:8100/health | jq .
```

Expected:

```json
{
  "status": "ok",
  "version": "0.3.0",
  "providers": ["google", "microsoft", "slack", "github", "jira",
                "notion", "linear", "hubspot", "salesforce", "aws"],
  "policy_loaded": true
}
```

> **Screenshot point** — shows 10 providers and healthy status.

---

### 2. Register a test agent

```bash
curl -s -X POST http://localhost:8100/agents \
  -H "X-Master-Key: ag_dev_change_me_in_production" \
  -H "Content-Type: application/json" \
  -d '{"name": "demo-bot", "policy": "default", "provider": "google"}' | jq .
```

Copy the `api_key` from the response.

> **Screenshot point** — agent registered with read-only policy.

---

### 3. Allowed request (read events)

```bash
curl -s http://localhost:8100/proxy/google/calendars/primary/events \
  -H "X-Agent-Key: YOUR_API_KEY" | jq .
```

Result: **HTTP 200** with mock calendar events.

> **Screenshot point** — green path: agent reads data successfully.

---

### 4. Blocked request (delete events)

```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X DELETE http://localhost:8100/proxy/google/calendars/primary/events/important-meeting \
  -H "X-Agent-Key: YOUR_API_KEY" | jq .
```

Result: **HTTP 403** with structured denial.

```json
{
  "error": "access_denied",
  "reason": "Write operations are not permitted under the default policy",
  "intent": {
    "type": "delete",
    "resource": "event",
    "confidence": 0.95,
    "level": "L2"
  },
  "suggestion": "Use GET to read resources instead, or request a policy that permits delete operations."
}
```

> **Screenshot point** — red path: destructive action blocked with explanation.

---

### 5. Audit trail

```bash
curl -s "http://localhost:8100/audit/logs?pretty=true&limit=5" \
  -H "X-Master-Key: ag_dev_change_me_in_production"
```

Both the allowed and denied requests are logged with:
- Timestamp, agent name, method, path
- Decision (allow / deny) and reason
- Intent type and confidence score
- Latency in milliseconds

> **Screenshot point** — full audit trail for compliance.

---

### 6. Statistics

```bash
curl -s http://localhost:8100/audit/stats \
  -H "X-Master-Key: ag_dev_change_me_in_production" | jq .
```

```json
{
  "total_requests": 2,
  "by_decision": { "allow": 1, "deny": 1 },
  "deny_rate": 0.5,
  "avg_latency_ms": 0.15
}
```

> **Screenshot point** — aggregated analytics.

---

### 7. Cleanup

```bash
# Stop the server
docker compose down
```

---

## Tips for Screen Recording

| Tip | Detail |
|-----|--------|
| **Terminal theme** | Dark background with large font (14-16pt) |
| **Window size** | 120 columns x 30 rows works well |
| **jq** | Install it — `jq .` makes JSON output much more readable |
| **Pause between steps** | The demo script has built-in pauses |
| **Split screen** | Terminal on left, architecture diagram on right |

## Recording Tools

- **asciinema** — `asciinema rec demo.cast` for terminal recordings
- **terminalizer** — generates GIF from terminal sessions
- **OBS Studio** — for video with overlays

---

## What to Highlight

| Moment | Key Message |
|--------|-------------|
| GET → 200 | "Read access passes through seamlessly" |
| DELETE → 403 | "Destructive action blocked instantly — with a reason" |
| Audit log | "Every decision is recorded — who, what, when, why" |
| Latency | "All of this in under 1 ms of overhead" |

---

*AgentGate v0.3.0 — The authorization layer MCP doesn't have.*
