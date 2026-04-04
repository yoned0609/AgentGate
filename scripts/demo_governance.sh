#!/usr/bin/env bash
# ============================================================================
#  AgentGate — Pattern B: Governance & Compliance Demo
#  Focus: Audit trail, stats, export, "who did what when"
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
header "AgentGate — Governance & Compliance Demo"
echo -e "  ${DIM}\"Which AI agent accessed what, when, and was it authorized?\"${RESET}"

step "Checking server..."
HEALTH=$(curl -sf "${BASE_URL}/health" 2>/dev/null || true)
if [ -z "$HEALTH" ]; then
  fail "Server not running at ${BASE_URL}"; exit 1
fi
ok "Server is running"
pause

# ── Step 1: Register two agents with different policies ────────────────────
header "Step 1 — Two Agents, Two Policies"

step "Creating 'sales-bot' (read-only) and 'admin-bot' (readwrite)..."

AGENT1=$(curl -sf -X POST "${BASE_URL}/agents" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "sales-bot", "policy": "default", "provider": "google"}' 2>/dev/null)
KEY1=$(echo "$AGENT1" | jq -r '.api_key')
ID1=$(echo "$AGENT1" | jq -r '.agent_id')

AGENT2=$(curl -sf -X POST "${BASE_URL}/agents" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "admin-bot", "policy": "readwrite", "provider": "google"}' 2>/dev/null)
KEY2=$(echo "$AGENT2" | jq -r '.api_key')
ID2=$(echo "$AGENT2" | jq -r '.agent_id')

ok "sales-bot → policy: default (read-only)"
ok "admin-bot → policy: readwrite (read + create)"
pause

# ── Step 2: Generate activity ──────────────────────────────────────────────
header "Step 2 — Simulate Agent Activity"

step "sales-bot reads events (allowed)..."
curl -sf "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: ${KEY1}" > /dev/null
echo -e "${GREEN}  ✔ GET /events → 200 ALLOWED${RESET}"

step "sales-bot tries to create event (denied)..."
curl -sf -X POST "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: ${KEY1}" \
  -H "Content-Type: application/json" \
  -d '{"summary":"hack"}' > /dev/null 2>&1 || true
echo -e "${RED}  ✘ POST /events → 403 DENIED${RESET}"

step "admin-bot reads events (allowed)..."
curl -sf "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: ${KEY2}" > /dev/null
echo -e "${GREEN}  ✔ GET /events → 200 ALLOWED${RESET}"

step "admin-bot creates event (allowed)..."
curl -sf -X POST "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: ${KEY2}" \
  -H "Content-Type: application/json" \
  -d '{"summary":"new meeting"}' > /dev/null 2>&1 || true
echo -e "${GREEN}  ✔ POST /events → 200 ALLOWED${RESET}"

step "admin-bot tries to delete (denied)..."
curl -sf -X DELETE "${BASE_URL}/proxy/google/calendars/primary/events/evt-123" \
  -H "X-Agent-Key: ${KEY2}" > /dev/null 2>&1 || true
echo -e "${RED}  ✘ DELETE /events → 403 DENIED${RESET}"

ok "5 requests generated — mix of allow and deny"
pause

# ── Step 3: Full audit trail ───────────────────────────────────────────────
header "Step 3 — Full Audit Trail"
echo -e "  ${DIM}Every decision is recorded: who, what, when, why${RESET}"

step "GET /audit/logs?pretty=true&limit=5"
echo ""
curl -sf "${BASE_URL}/audit/logs?pretty=true&limit=5" \
  -H "X-Master-Key: ${MASTER_KEY}" | jq '.logs[] | {timestamp, agent_name, method, path, decision, deny_reason, latency_ms}'

pause

# ── Step 4: Aggregated statistics ──────────────────────────────────────────
header "Step 4 — Compliance Dashboard (Stats)"

step "GET /audit/stats"
echo ""
curl -sf "${BASE_URL}/audit/stats" \
  -H "X-Master-Key: ${MASTER_KEY}" | jq .

pause

# ── Step 5: Export for auditors ────────────────────────────────────────────
header "Step 5 — Export for Auditors"

step "JSON export..."
JSON_COUNT=$(curl -sf "${BASE_URL}/audit/export?format=json&limit=100" \
  -H "X-Master-Key: ${MASTER_KEY}" | jq '.count')
ok "JSON export: ${JSON_COUNT} records ready"

step "CSV export..."
CSV_LINES=$(curl -sf "${BASE_URL}/audit/export?format=csv&limit=100" \
  -H "X-Master-Key: ${MASTER_KEY}" | wc -l)
ok "CSV export: ${CSV_LINES} lines (including header)"
info "→ curl .../audit/export?format=csv > audit_report.csv"

pause

# ── Cleanup ─────────────────────────────────────────────────────────────────
step "Cleaning up..."
curl -sf -X DELETE "${BASE_URL}/agents/${ID1}" -H "X-Master-Key: ${MASTER_KEY}" > /dev/null 2>&1 || true
curl -sf -X DELETE "${BASE_URL}/agents/${ID2}" -H "X-Master-Key: ${MASTER_KEY}" > /dev/null 2>&1 || true
ok "Demo agents removed"

# ── Summary ─────────────────────────────────────────────────────────────────
header "Governance Demo Complete!"

echo -e "  ${BOLD}AgentGate answers:${RESET}"
echo ""
echo -e "  ${CYAN}Q: Which agent accessed what?${RESET}"
echo -e "     → Audit log with agent name, method, path, intent"
echo ""
echo -e "  ${CYAN}Q: Was it authorized?${RESET}"
echo -e "     → Decision field: allow / deny with reason"
echo ""
echo -e "  ${CYAN}Q: Can I export for compliance?${RESET}"
echo -e "     → JSON and CSV export, one API call"
echo ""
echo -e "  ${DIM}github.com/yoned0609/AgentGate${RESET}"
banner
