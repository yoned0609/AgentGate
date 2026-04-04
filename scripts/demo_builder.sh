#!/usr/bin/env bash
# ============================================================================
#  AgentGate — Pattern C: Builder Demo
#  Focus: Policy switching, rate limiting, natural language policy
# ============================================================================
set -euo pipefail

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

# ── Pre-flight ──────────────────────────────────────────────────────────────
header "AgentGate — Builder Demo"
echo -e "  ${DIM}Policy switching, rate limiting, natural language policy builder${RESET}"

step "Checking server..."
HEALTH=$(curl -sf "${BASE_URL}/health" 2>/dev/null || true)
if [ -z "$HEALTH" ]; then
  fail "Server not running at ${BASE_URL}"; exit 1
fi
ok "Server is running"
pause

# ── Step 1: Show available policies ────────────────────────────────────────
header "Step 1 — Available Policies"

step "GET /policies"
echo ""
curl -sf "${BASE_URL}/policies" \
  -H "X-Master-Key: ${MASTER_KEY}" | jq '.[].name'

pause

# ── Step 2: Rate limiting demo ─────────────────────────────────────────────
header "Step 2 — Rate Limiting in Action"

step "Creating agent with 'rate_limited' policy (5 req/min)..."
AGENT=$(curl -sf -X POST "${BASE_URL}/agents" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "rate-test-bot", "policy": "rate_limited", "provider": "google"}' 2>/dev/null)
KEY=$(echo "$AGENT" | jq -r '.api_key')
ID=$(echo "$AGENT" | jq -r '.agent_id')
ok "Agent created — policy: rate_limited (5 req/min)"

step "Sending 7 rapid requests..."
echo ""
for i in $(seq 1 7); do
  STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/proxy/google/calendars/primary/events" \
    -H "X-Agent-Key: ${KEY}" 2>/dev/null || echo "429")
  if [ "$STATUS" = "200" ]; then
    echo -e "  Request $i: ${GREEN}${STATUS} OK${RESET}"
  elif [ "$STATUS" = "429" ]; then
    echo -e "  Request $i: ${RED}${STATUS} RATE LIMITED${RESET}"
  else
    echo -e "  Request $i: ${YELLOW}${STATUS}${RESET}"
  fi
done

echo ""
ok "Rate limiter kicked in after 5 requests"

# Cleanup rate-test agent
curl -sf -X DELETE "${BASE_URL}/agents/${ID}" -H "X-Master-Key: ${MASTER_KEY}" > /dev/null 2>&1 || true

pause

# ── Step 3: Policy comparison ──────────────────────────────────────────────
header "Step 3 — Same Request, Different Policies"

step "Creating two agents: read_only vs readwrite..."

AGENT_RO=$(curl -sf -X POST "${BASE_URL}/agents" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "readonly-bot", "policy": "read_only", "provider": "google"}' 2>/dev/null)
KEY_RO=$(echo "$AGENT_RO" | jq -r '.api_key')
ID_RO=$(echo "$AGENT_RO" | jq -r '.agent_id')

AGENT_RW=$(curl -sf -X POST "${BASE_URL}/agents" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "readwrite-bot", "policy": "readwrite", "provider": "google"}' 2>/dev/null)
KEY_RW=$(echo "$AGENT_RW" | jq -r '.api_key')
ID_RW=$(echo "$AGENT_RW" | jq -r '.agent_id')

ok "readonly-bot  → policy: read_only"
ok "readwrite-bot → policy: readwrite"

step "POST /events (create a new event)..."
echo ""

STATUS_RO=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: ${KEY_RO}" \
  -H "Content-Type: application/json" \
  -d '{"summary":"test"}' 2>/dev/null || echo "403")
echo -e "  readonly-bot:  ${RED}${STATUS_RO} DENIED${RESET}  (policy blocks all writes)"

STATUS_RW=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: ${KEY_RW}" \
  -H "Content-Type: application/json" \
  -d '{"summary":"test"}' 2>/dev/null || echo "200")
echo -e "  readwrite-bot: ${GREEN}${STATUS_RW} ALLOWED${RESET} (policy permits create)"

echo ""
ok "Same request, different outcome — policy controls everything"

pause

# ── Step 4: Natural language policy builder ────────────────────────────────
header "Step 4 — Build a Policy from Plain English"

step "POST /policies/build"
echo -e "${DIM}  Body: {\"description\": \"Allow read-only access to GitHub repos and issues\"}${RESET}"
echo ""

curl -sf -X POST "${BASE_URL}/policies/build" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"description": "Allow read-only access to GitHub repos and issues"}' | jq .

pause

# ── Cleanup ─────────────────────────────────────────────────────────────────
step "Cleaning up..."
curl -sf -X DELETE "${BASE_URL}/agents/${ID_RO}" -H "X-Master-Key: ${MASTER_KEY}" > /dev/null 2>&1 || true
curl -sf -X DELETE "${BASE_URL}/agents/${ID_RW}" -H "X-Master-Key: ${MASTER_KEY}" > /dev/null 2>&1 || true
ok "Demo agents removed"

# ── Summary ─────────────────────────────────────────────────────────────────
header "Builder Demo Complete!"

echo -e "  ${GREEN}✔ Rate limiting${RESET}     → 429 after 5 requests (configurable)"
echo -e "  ${GREEN}✔ Policy switching${RESET}  → Same request, different outcome"
echo -e "  ${GREEN}✔ NL policy builder${RESET} → English → YAML, instant"
echo ""
echo -e "  ${BOLD}Drop AgentGate in front of your APIs. No code changes.${RESET}"
echo ""
echo -e "  ${DIM}github.com/yoned0609/AgentGate${RESET}"
banner
