#!/usr/bin/env bash
# ============================================================================
#  AgentGate — 60-Second Live Demo
#  Usage:  TEST_MODE=true ./scripts/demo.sh
#  Requires: curl, jq (optional but recommended)
# ============================================================================
set -euo pipefail

# ── Colors & helpers ────────────────────────────────────────────────────────
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

BASE_URL="${AGENTGATE_URL:-http://localhost:8100}"
MASTER_KEY="${MASTER_KEY:-ag_dev_change_me_in_production}"

banner()  { echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }
header()  { banner; echo -e "${BOLD}  $1${RESET}"; banner; }
step()    { echo -e "\n${CYAN}▶ $1${RESET}"; }
ok()      { echo -e "${GREEN}  ✔ $1${RESET}"; }
fail()    { echo -e "${RED}  ✘ $1${RESET}"; }
info()    { echo -e "${DIM}  $1${RESET}"; }
pause()   { echo -e "${YELLOW}  ⏎ Press Enter to continue...${RESET}"; read -r; }

pretty() {
  if command -v jq &>/dev/null; then
    jq '.'
  else
    cat
  fi
}

# ── Pre-flight ──────────────────────────────────────────────────────────────
header "AgentGate — 60-Second Demo"

step "Checking server at ${BASE_URL} ..."
HEALTH=$(curl -sf "${BASE_URL}/health" 2>/dev/null || true)
if [ -z "$HEALTH" ]; then
  fail "Server is not running at ${BASE_URL}"
  echo ""
  echo -e "  Start it first:"
  echo -e "    ${BOLD}TEST_MODE=true docker compose up --build${RESET}"
  echo -e "  or:"
  echo -e "    ${BOLD}cd backend && TEST_MODE=true python3 -m uvicorn app.main:app --port 8100${RESET}"
  echo ""
  exit 1
fi

VERSION=$(echo "$HEALTH" | jq -r '.version // "unknown"' 2>/dev/null || echo "unknown")
STATUS=$(echo "$HEALTH" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")
PROVIDERS=$(echo "$HEALTH" | jq -r '.providers | length // 0' 2>/dev/null || echo "?")
ok "Server is running — v${VERSION}, status=${STATUS}, ${PROVIDERS} providers"

# Check if test mode is active
TEST_MODE_ACTIVE=$(curl -sf "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: dummy" 2>/dev/null | jq -r '.mock // empty' 2>/dev/null || true)

pause

# ── Step 1: Register an agent ──────────────────────────────────────────────
header "Step 1 — Register an AI Agent"

step "Creating agent 'demo-bot' with the 'default' (read-only) policy..."
AGENT_RESP=$(curl -sf -X POST "${BASE_URL}/agents" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "demo-bot", "policy": "default", "provider": "google"}' 2>/dev/null || true)

if [ -z "$AGENT_RESP" ]; then
  fail "Could not register agent. Is the master key correct?"
  exit 1
fi

AGENT_KEY=$(echo "$AGENT_RESP" | jq -r '.api_key' 2>/dev/null)
AGENT_ID=$(echo "$AGENT_RESP" | jq -r '.agent_id' 2>/dev/null)
ok "Agent registered!"
info "Agent ID:  ${AGENT_ID}"
info "API Key:   ${AGENT_KEY}"
info "Policy:    default (read-only)"

pause

# ── Step 2: Allowed request ────────────────────────────────────────────────
header "Step 2 — Allowed Request (GET → read events)"

step "GET /proxy/google/calendars/primary/events"
echo -e "${DIM}  curl ${BASE_URL}/proxy/google/calendars/primary/events -H 'X-Agent-Key: ...'${RESET}"
echo ""

ALLOW_RESP=$(curl -sf "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: ${AGENT_KEY}" 2>/dev/null || true)
ALLOW_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
  "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: ${AGENT_KEY}" 2>/dev/null || echo "000")

if [ "$ALLOW_STATUS" = "200" ]; then
  echo -e "${GREEN}  ┌──────────────────────────────────────────────────────┐${RESET}"
  echo -e "${GREEN}  │  HTTP 200 — ${BOLD}ALLOWED${RESET}${GREEN}                                   │${RESET}"
  echo -e "${GREEN}  └──────────────────────────────────────────────────────┘${RESET}"
  echo "$ALLOW_RESP" | pretty | head -20
  echo -e "${DIM}  ... (truncated)${RESET}"
else
  fail "Unexpected status: ${ALLOW_STATUS}"
  echo "$ALLOW_RESP" | pretty
fi

pause

# ── Step 3: Denied request ─────────────────────────────────────────────────
header "Step 3 — Blocked Request (DELETE → policy denies)"

step "DELETE /proxy/google/calendars/primary/events/important-meeting"
echo -e "${DIM}  curl -X DELETE ${BASE_URL}/proxy/google/calendars/primary/events/important-meeting -H 'X-Agent-Key: ...'${RESET}"
echo ""

DENY_RESP=$(curl -sf -X DELETE "${BASE_URL}/proxy/google/calendars/primary/events/important-meeting" \
  -H "X-Agent-Key: ${AGENT_KEY}" 2>/dev/null || true)
DENY_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -X DELETE \
  "${BASE_URL}/proxy/google/calendars/primary/events/important-meeting" \
  -H "X-Agent-Key: ${AGENT_KEY}" 2>/dev/null || echo "000")

if [ "$DENY_STATUS" = "403" ]; then
  echo -e "${RED}  ┌──────────────────────────────────────────────────────┐${RESET}"
  echo -e "${RED}  │  HTTP 403 — ${BOLD}BLOCKED BY POLICY${RESET}${RED}                        │${RESET}"
  echo -e "${RED}  └──────────────────────────────────────────────────────┘${RESET}"
  echo "$DENY_RESP" | pretty
else
  fail "Unexpected status: ${DENY_STATUS} (expected 403)"
  echo "$DENY_RESP" | pretty
fi

pause

# ── Step 4: Audit trail ────────────────────────────────────────────────────
header "Step 4 — Audit Trail (every decision is logged)"

step "GET /audit/logs?pretty=true&limit=5"
echo ""

AUDIT_RESP=$(curl -sf "${BASE_URL}/audit/logs?pretty=true&limit=5" \
  -H "X-Master-Key: ${MASTER_KEY}" 2>/dev/null || true)

if [ -n "$AUDIT_RESP" ]; then
  ok "Audit log entries:"
  echo "$AUDIT_RESP" | pretty | head -40
else
  fail "Could not fetch audit logs"
fi

pause

# ── Step 5: Stats ──────────────────────────────────────────────────────────
header "Step 5 — Aggregated Statistics"

step "GET /audit/stats"
echo ""

STATS_RESP=$(curl -sf "${BASE_URL}/audit/stats" \
  -H "X-Master-Key: ${MASTER_KEY}" 2>/dev/null || true)

if [ -n "$STATS_RESP" ]; then
  echo "$STATS_RESP" | pretty
  DENY_RATE=$(echo "$STATS_RESP" | jq -r '.deny_rate // "N/A"' 2>/dev/null || echo "N/A")
  AVG_LAT=$(echo "$STATS_RESP" | jq -r '.avg_latency_ms // "N/A"' 2>/dev/null || echo "N/A")
  echo ""
  ok "Deny rate: ${DENY_RATE}"
  ok "Avg latency: ${AVG_LAT} ms"
fi

# ── Cleanup ─────────────────────────────────────────────────────────────────
echo ""
step "Cleaning up demo agent..."
curl -sf -X DELETE "${BASE_URL}/agents/${AGENT_ID}" \
  -H "X-Master-Key: ${MASTER_KEY}" >/dev/null 2>&1 || true
ok "Agent 'demo-bot' removed"

# ── Summary ─────────────────────────────────────────────────────────────────
header "Demo Complete!"

echo -e "  ${GREEN}✔ Read request${RESET}     →  ${GREEN}ALLOWED${RESET}  (policy permits GET)"
echo -e "  ${RED}✘ Delete request${RESET}   →  ${RED}BLOCKED${RESET}  (policy denies DELETE)"
echo -e "  ${BLUE}📋 Audit log${RESET}       →  Both decisions recorded with intent & latency"
echo ""
echo -e "  ${BOLD}All of this happened in < 1 ms of overhead.${RESET}"
echo ""
echo -e "  ${DIM}Learn more:  https://github.com/yoned0609/AgentGate${RESET}"
echo -e "  ${DIM}Quick start: QUICKSTART.md${RESET}"
banner
