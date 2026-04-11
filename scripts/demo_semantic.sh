#!/usr/bin/env bash
# ============================================================================
#  AgentGate �� Semantic Poka-yoke Demo
#  Usage:  TEST_MODE=true ./scripts/demo_semantic.sh
#  Requires: curl, jq (optional but recommended)
# ============================================================================
set -euo pipefail

# ── Colors & helpers ────────────────────────────────────────────────────────
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
MAGENTA='\033[1;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

BASE_URL="${AGENTGATE_URL:-http://localhost:8100}"
MASTER_KEY="${MASTER_KEY:-ag_dev_change_me_in_production}"

banner()  { echo -e "\n${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }
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
header "AgentGate — Semantic Poka-yoke Demo"

echo -e "  ${BOLD}Response-level business rule validation${RESET}"
echo -e "  ${DIM}Intercepts API responses BEFORE they reach the AI agent.${RESET}"
echo -e "  ${DIM}Blocks PII leakage, credential exposure, and financial anomalies.${RESET}"

step "Checking server at ${BASE_URL} ..."
HEALTH=$(curl -sf "${BASE_URL}/health" 2>/dev/null || true)
if [ -z "$HEALTH" ]; then
  fail "Server is not running at ${BASE_URL}"
  echo ""
  echo -e "  Start it first:"
  echo -e "    ${BOLD}TEST_MODE=true cd backend && python3 -m uvicorn app.main:app --port 8100${RESET}"
  exit 1
fi

VERSION=$(echo "$HEALTH" | jq -r '.version // "unknown"' 2>/dev/null || echo "unknown")
ok "Server running — v${VERSION}"

pause

# ── Step 1: Show loaded semantic rules ─────────────────────────────────────
header "Step 1 — Default Semantic Rules (loaded from YAML)"

step "GET /semantic/rules"
RULES_RESP=$(curl -sf "${BASE_URL}/semantic/rules" \
  -H "X-Master-Key: ${MASTER_KEY}" 2>/dev/null || true)

if [ -n "$RULES_RESP" ]; then
  RULE_COUNT=$(echo "$RULES_RESP" | jq '.rules | length' 2>/dev/null || echo "0")
  ok "${RULE_COUNT} rules loaded"
  echo ""
  echo "$RULES_RESP" | jq '.rules[] | {name, severity, mode}' 2>/dev/null || echo "$RULES_RESP"
fi

pause

# ── Step 2: Register agent ─────────────────────────────────────────────────
header "Step 2 — Register Agent"

step "Creating agent 'semantic-demo-bot'..."
AGENT_RESP=$(curl -sf -X POST "${BASE_URL}/agents" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "semantic-demo-bot", "policy": "default", "provider": "google"}' 2>/dev/null || true)

AGENT_KEY=$(echo "$AGENT_RESP" | jq -r '.api_key' 2>/dev/null)
AGENT_ID=$(echo "$AGENT_RESP" | jq -r '.agent_id' 2>/dev/null)
ok "Agent registered: ${AGENT_ID}"

pause

# ── Step 3: Normal request passes semantic checks ─────────────────────────
header "Step 3 — Clean Response (passes all checks)"

step "GET /proxy/google/calendars/primary/events"
info "Normal calendar data — no PII, no secrets"
echo ""

CLEAN_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
  "${BASE_URL}/proxy/google/calendars/primary/events" \
  -H "X-Agent-Key: ${AGENT_KEY}" 2>/dev/null || echo "000")

if [ "$CLEAN_STATUS" = "200" ]; then
  echo -e "${GREEN}  ┌──────────────────────────────────────────────────────┐${RESET}"
  echo -e "${GREEN}  │  HTTP 200 — ${BOLD}PASSED semantic validation${RESET}${GREEN}               │${RESET}"
  echo -e "${GREEN}  │  No PII, no secrets, no anomalies detected          │${RESET}"
  echo -e "${GREEN}  └──────────────────────────────────────────────────────┘${RESET}"
  ok "Response delivered to agent safely"
else
  fail "Unexpected status: ${CLEAN_STATUS}"
fi

pause

# ── Step 4: Add a custom rule (detect "password" in responses) ─────────────
header "Step 4 — Add Custom Rule: Block Password Leakage"

step "POST /semantic/rules — adding 'demo_password_leak' rule"
echo ""

RULE_BODY='{
  "name": "demo_password_leak",
  "description": "Block any response containing a password field with a value",
  "checks": [
    {
      "type": "regex",
      "pattern": "\"password\"\\s*:\\s*\"[^\"]+\"",
      "description": "JSON password field with non-empty value"
    }
  ],
  "mode": "enforce",
  "severity": "critical",
  "violation_message": "Response contains exposed password — blocked"
}'

ADD_RESP=$(curl -sf -X POST "${BASE_URL}/semantic/rules" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d "$RULE_BODY" 2>/dev/null || true)

echo "$ADD_RESP" | pretty
ok "Rule 'demo_password_leak' added (mode=enforce, severity=critical)"

pause

# ── Step 5: Add credit card detection rule ─────────────────────────────────
header "Step 5 — Add Rule: Block Credit Card Numbers"

step "POST /semantic/rules — adding 'demo_credit_card' rule"
echo ""

CC_BODY='{
  "name": "demo_credit_card",
  "description": "Block responses containing Visa/Mastercard numbers",
  "checks": [
    {
      "type": "regex",
      "pattern": "\\b4[0-9]{12}(?:[0-9]{3})?\\b",
      "description": "Visa card number pattern (4xxx...)"
    }
  ],
  "mode": "enforce",
  "severity": "critical",
  "violation_message": "Credit card number detected in response — blocked"
}'

CC_RESP=$(curl -sf -X POST "${BASE_URL}/semantic/rules" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d "$CC_BODY" 2>/dev/null || true)

echo "$CC_RESP" | pretty
ok "Rule 'demo_credit_card' added"

pause

# ── Step 6: Add amount threshold rule (audit mode) ─────────────────────────
header "Step 6 — Add Rule: Flag High Amounts (audit mode)"

step "POST /semantic/rules — adding 'demo_high_amount' rule (audit only)"
echo ""

AMT_BODY='{
  "name": "demo_high_amount",
  "description": "Flag responses with unusually high monetary amounts",
  "checks": [
    {
      "type": "numeric_range",
      "field_path": "amount",
      "max_value": 1000000,
      "description": "Amount exceeds 1M threshold"
    }
  ],
  "mode": "audit",
  "severity": "high",
  "violation_message": "High amount detected — flagged for review"
}'

AMT_RESP=$(curl -sf -X POST "${BASE_URL}/semantic/rules" \
  -H "X-Master-Key: ${MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d "$AMT_BODY" 2>/dev/null || true)

echo "$AMT_RESP" | pretty
ok "Rule 'demo_high_amount' added (mode=audit — logs only, does NOT block)"

pause

# ── Step 7: Show current semantic stats ────────────────────────────────────
header "Step 7 — Semantic Validation Stats"

step "GET /semantic/stats"
echo ""

STATS=$(curl -sf "${BASE_URL}/semantic/stats" \
  -H "X-Master-Key: ${MASTER_KEY}" 2>/dev/null || true)

echo "$STATS" | pretty

pause

# ── Step 8: Verify rules loaded ────────────────────────────────────────────
header "Step 8 — All Loaded Rules"

step "GET /semantic/rules (after additions)"
echo ""

RULES2=$(curl -sf "${BASE_URL}/semantic/rules" \
  -H "X-Master-Key: ${MASTER_KEY}" 2>/dev/null || true)

TOTAL=$(echo "$RULES2" | jq '.rules | length' 2>/dev/null || echo "?")
echo "$RULES2" | jq '.rules[] | {name, severity, mode, checks_count}' 2>/dev/null || echo "$RULES2"
echo ""
ok "${TOTAL} semantic rules active"

pause

# ── Step 9: Clean up demo rules ────────────────────────────────────────────
header "Step 9 — Cleanup"

step "Removing demo rules..."
curl -sf -X DELETE "${BASE_URL}/semantic/rules/demo_password_leak" \
  -H "X-Master-Key: ${MASTER_KEY}" >/dev/null 2>&1 || true
ok "Removed: demo_password_leak"

curl -sf -X DELETE "${BASE_URL}/semantic/rules/demo_credit_card" \
  -H "X-Master-Key: ${MASTER_KEY}" >/dev/null 2>&1 || true
ok "Removed: demo_credit_card"

curl -sf -X DELETE "${BASE_URL}/semantic/rules/demo_high_amount" \
  -H "X-Master-Key: ${MASTER_KEY}" >/dev/null 2>&1 || true
ok "Removed: demo_high_amount"

step "Removing demo agent..."
curl -sf -X DELETE "${BASE_URL}/agents/${AGENT_ID}" \
  -H "X-Master-Key: ${MASTER_KEY}" >/dev/null 2>&1 || true
ok "Agent removed"

# ── Summary ────────────────────────────────────────────────────────────────
header "Demo Complete — Semantic Poka-yoke"

echo -e "  ${GREEN}✔ Clean response${RESET}    →  ${GREEN}PASSED${RESET}   (no violations, delivered to agent)"
echo -e "  ${MAGENTA}⚡ Password rule${RESET}     →  ${MAGENTA}ENFORCE${RESET}  (blocks exposed credentials)"
echo -e "  ${MAGENTA}⚡ Credit card rule${RESET}  →  ${MAGENTA}ENFORCE${RESET}  (blocks PII in responses)"
echo -e "  ${YELLOW}⚠ Amount rule${RESET}       →  ${YELLOW}AUDIT${RESET}    (logs anomaly, does NOT block)"
echo ""
echo -e "  ${BOLD}Response validation runs in < 1 ms (pattern-based).${RESET}"
echo -e "  ${BOLD}Rules are YAML-declared and hot-reloadable.${RESET}"
echo ""
echo -e "  ${BOLD}Architecture:${RESET}"
echo -e "    Agent Request → Policy Gate → Upstream API"
echo -e "                                       ↓"
echo -e "                              ${MAGENTA}Semantic Poka-yoke${RESET}"
echo -e "                              ├─ Layer 1: Pattern (regex/keyword)  <1ms"
echo -e "                              └─ Layer 2: LLM (optional)          ~100ms"
echo -e "                                       ↓"
echo -e "                    ${GREEN}PASS → deliver${RESET}  │  ${RED}FAIL → HTTP 451 block${RESET}"
echo ""
echo -e "  ${DIM}Learn more:  https://github.com/yoned0609/AgentGate${RESET}"
banner
