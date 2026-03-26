# AgentGate Business Plan v1.0

> JIT Authorization Infrastructure for AI Agents
> Created: 2026-03-24

---

## 1. Executive Summary

AI agents are beginning to autonomously access enterprise SaaS platforms and data.
However, the current standard practice is to hand agents full-access API keys,
with no mechanism to audit "what data was accessed, for what purpose."

**AgentGate** is a backend proxy that analyzes AI agent requests in real time
and issues **Just-in-Time (JIT)** credentials with the minimum privileges
required for each task — valid only for that moment.

---

## 2. Problem Statement

### 2.1 Over-Privileging
Granting agents `Full Access` API keys or OAuth tokens is today's default.
Prompt injection or unexpected behavior can lead to full data exfiltration.

### 2.2 Lack of Governance
There is no standard mechanism to record and audit
"which AI accessed what data, with what intent, and what was returned."

### 2.3 Adoption Barriers
Many enterprises block AI access to internal data due to security concerns.
The absence of a platform that guarantees safe access is the biggest blocker to AI adoption.

### 2.4 The MCP Authorization Gap
Anthropic's MCP (Model Context Protocol) defines a protocol for connecting tools and resources,
but **has no explicit authorization layer**. Annotations like `readOnlyHint` are advisory
and carry no enforcement. This gap is AgentGate's primary market entry opportunity.

---

## 3. Solution (Value Proposition)

### Core Concept
AgentGate sits as a transparent proxy between AI agents and SaaS APIs,
providing **three capabilities** in real time:

```
AI Agent
    ↓ Request
 ┌──────────────────────────────┐
 │        AgentGate             │
 │                              │
 │  1. Intent Analyzer          │  ← Analyze the "intent" of the request
 │     (Pattern match + classify)│
 │                              │
 │  2. Policy Engine            │  ← Evaluate against user/org policies
 │     (RBAC / ABAC / CEL)      │
 │                              │
 │  3. Token Factory            │  ← Issue least-privilege tokens or
 │     (JIT issuance / proxy)   │     filter API calls at proxy level
 │                              │
 │  [Audit Logger]              │  ← Record all operations tamper-proof
 └──────────────────────────────┘
    ↓ Authorized request
 SaaS API (Google, Slack, etc.)
```

### Key Differentiators
- **Proxy, not SDK** — Zero code changes required for adoption
- **MCP-native** — Simply insert between MCP Server and Client
- **Multi-provider** — Cross-platform coverage: Google / Microsoft / Slack and more

---

## 4. Data Flow (Example)

```
1. Agent: "Show me Person A's schedule for today"
2. AgentGate intercepts the request
3. Intent Analyzer:
   - Pattern match: GET /calendar → "calendar:read" (<5ms)
   - Target resource: Person A's calendar
   - Operation type: Read (non-destructive)
4. Policy Engine:
   - User policy: "Allow only during business hours" → OK
   - Org policy: "Viewing others' calendars requires manager role" → Check
5. Token Factory:
   - Microsoft OBO: Issue 30-second token with Calendars.Read scope
   - (For Google: Enforce read-only at proxy level)
6. Agent retrieves data
7. Token auto-expires / Audit log recorded
```

---

## 5. Technical Challenges & Mitigations

### 5.1 The Reality of Token Downscoping

Research findings show that **downscoping support across major SaaS providers is very limited**:

| Provider | Downscoping | Mechanism | Constraints |
|----------|:-----------:|-----------|-------------|
| Google Cloud (GCS etc.) | Supported | CAB (Credential Access Boundaries) | **Not available for Workspace APIs (Calendar/Gmail/Drive)** |
| Microsoft (Entra ID) | Partial | On-Behalf-Of (OBO) flow | Scopes must be pre-declared in app registration |
| Slack | Not supported | None | Token scopes are fixed at installation time |
| Salesforce | Partial | Token Exchange | Primarily for cross-org identity, not scope reduction |

**Mitigation: Hybrid Architecture**

```
Supported providers → Native downscoping (OBO, CAB)
Unsupported providers → Proxy-level filtering (API firewall approach)
```

In proxy mode, AgentGate maintains API schemas for each SaaS provider
and makes allow/deny decisions based on HTTP method + endpoint.
**This is the realistic primary approach for MVP.**

### 5.2 Intent Analysis Latency

Adding LLM analysis to every request introduces 200ms–2,000ms latency.

**Three-tier fallback strategy:**

| Layer | Method | Latency | Coverage |
|-------|--------|:-------:|:--------:|
| L1 | Pattern matching (HTTP method + URL path) | <5ms | 80%+ |
| L2 | Lightweight classification model (fine-tuned BERT etc.) | 10-50ms | 15% |
| L3 | LLM analysis (ambiguous cases only) | 200-500ms | 5% |

Since agent workflows already take seconds due to LLM inference,
the effective added latency for L1/L2 cases is negligible.

### 5.3 Single Point of Failure (SPOF)

If the proxy goes down, all agent API calls fail.

**Mitigations:**
- **Sidecar model** — Deploy an AgentGate process alongside each agent (Envoy-style)
- **Policy cache** — When the policy engine is unreachable, enforce cached policies
- **Fail-open / Fail-closed** — Configurable per organization policy
- **Future: Edge deployment** — Global distribution via Cloudflare Workers

### 5.4 Streaming & Long-Running Tasks

When agent tasks span minutes or hours:
- **Session-based authorization** — Authorize at session start, periodically re-evaluate
- **Checkpoint authorization** — Re-authorize at each step boundary in multi-step workflows
- **Token refresh proxy** — AgentGate transparently handles token refresh

---

## 6. Target Market

### 6.1 Market Size

| Segment | Size (2028 Forecast) |
|---------|:--------------------:|
| AI TRiSM (Trust, Risk, Security Management) | $7-8B |
| AI Agent Authorization/Governance (subset) | $500M-$1.5B |
| API Security | ~$3B |
| Identity Governance (IGA) | ~$7B |

### 6.2 Target Segments

**Phase 1: Developers (Developer-first)**
- Individuals and startups building AI agents
- MCP Server developers
- Value: "No need to build security from scratch"

**Phase 2: Enterprise DX Divisions**
- Organizations seeking safe AI access to internal data
- Industries with strong audit trail requirements (finance, healthcare, manufacturing)
- Value: "Makes AI adoption approvable by security teams"

**Phase 3: AI SaaS Developers**
- SaaS vendors seeking security as a differentiator
- Value: "Enables enterprise sales"

---

## 7. Competitive Analysis

| Product | Approach | Difference from AgentGate |
|---------|----------|--------------------------|
| **Pangea** | Security API suite (SDK integration) | SDK-based = requires code changes. AgentGate is a proxy = transparent |
| **Indent** | JIT access for humans | Assumes human approval flows. Not designed for autonomous AI agent decisions |
| **ConductorOne / Opal** | ID Governance | Focused on human access management. Not AI-agent-specific |
| **Permit.io / Cerbos** | Policy engines | Authorization decision engine only. No token issuance or proxy capabilities |
| **Lakera** | AI firewall | Focused on prompt injection defense. Not API authorization |

**AgentGate's unique position:**
No existing product delivers "intent analysis + JIT token issuance + audit logging"
**transparently as a proxy**.

**Biggest risk:**
Google / Microsoft / Anthropic could build equivalent authorization layers natively.
→ **Multi-provider cross-platform support** is the answer. No single platform vendor can build this.

---

## 8. Business Model

### 8.1 Pricing

| Plan | Monthly | Includes |
|------|:-------:|----------|
| Free | $0 | 1 agent / 1,000 requests / basic logs |
| Pro | $49 | 5 agents / 50,000 requests / detailed audit logs |
| Business | $199 | 20 agents / 500,000 requests / custom policies / SSO |
| Enterprise | $999+ | Unlimited / SLA / on-premise / dedicated support |

### 8.2 Revenue Model Evolution

```
Year 1: OSS core + Cloud hosting (PLG: Product-Led Growth)
Year 2: Enterprise contracts + custom connector development
Year 3: Marketplace (third-party connectors / policy templates)
```

---

## 9. MOAT (Competitive Barriers)

### 9.1 Data Network Effects
- Accumulation of intent analysis logs → Improved classification model accuracy
- Learning data on "safe/dangerous request patterns" grows more valuable over time

### 9.2 Connector Ecosystem
- API schema + authorization specification knowledge base for each SaaS
- Accumulated best practices for privilege restriction per provider
- Third-party connector contributions (OSS model)

### 9.3 Regulatory Compliance Expertise
- Industry-specific policy templates (finance / healthcare / manufacturing)
- Standardized audit trail formats

### 9.4 Switching Costs
- Accumulated policy definitions and audit logs after adoption
- Existing integrations with MCP Servers / agents

---

## 10. MVP Development Roadmap (Solo Developer)

### Phase 1: Proxy Foundation + Google Calendar PoC ✅ Complete

**Goal:** JIT authorization proxy prototype for Google Calendar API

**Completed tasks:**
- [x] Reverse proxy server with FastAPI + httpx
- [x] L1 pattern-match authorization (HTTP method + URL path)
- [x] YAML-based policy definition format
- [x] SQLite audit log storage (aiosqlite)
- [x] Agent authentication (API key + registry)
- ~~Dashboard~~ → Deemed unnecessary; all operations available via API

**Tech Stack:**
```
Backend:  Python 3.12 FastAPI (async) + httpx (proxy)
DB:       SQLite (aiosqlite)
Lint:     ruff
CI:       GitHub Actions
Container: Docker + docker-compose
```

---

### Phase 2: Multi-Provider + Intent Analysis ✅ Complete

**Completed tasks:**
- [x] Microsoft Graph (Outlook/Calendar/Mail) connector
- [x] Slack API connector
- [x] L1 (HTTP method) + L2 (path pattern) two-stage intent analysis
- [x] Slack POST-as-read handling
- [x] Structured denial responses (intent info + alternative suggestions)
- [x] Provider-specific policy templates (5 types)
- [x] Plugin-based connector architecture

**Additional backend hardening completed:**
- [x] Rate limiting (sliding window, configurable per policy YAML)
- [x] Request validation (path traversal / header injection / body size)
- [x] Policy engine v2 (intent matching / compound conditions / hot reload / schema validation)
- [x] Agent store SQLite migration (key rotation / usage stats)
- [x] Audit log enhancements (CSV/JSON export / auto-purge / stats API)
- [x] Webhook alerts (deny notifications / threshold-based / cooldown)

---

### Phase 3: MCP Integration ✅ Complete

**Completed tasks:**
- [x] MCP Auth Proxy — JSON-RPC `tools/call` interception with authorization
- [x] MCP tool annotation (readOnlyHint, destructiveHint) → auto policy conversion
- [x] MCP Server registration API + bulk tool definition registration
- [x] E2E integration tests (20 cases, mocked upstream)
- [ ] ContextFlow integration (separate repo, future task)
- [ ] Python SDK (pip install agentgate)
- [ ] TypeScript SDK (npm install agentgate)

**Positioning:**
> "AgentGate: The authorization layer MCP doesn't have."

**Tests:** 111 cases passing

---

### Phase 4: OSS Launch + Community Building (Next)

**Tasks:**
- [ ] License selection (Apache 2.0 or BSL)
- [ ] GitHub public release + documentation site
- [ ] Product Hunt / Hacker News launch
- [ ] Custom connector development guide
- [ ] Cloud-hosted version (SaaS) launch
- [ ] Python SDK / TypeScript SDK

---

## 11. Synergy with ContextFlow

AgentGate can be integrated as the **security layer** for ContextFlow:

```
User → ContextFlow → AgentGate → Google Calendar API
                                → Supabase Storage
                                → OpenAI API
```

**Specific benefits:**
- Apply restrictions like "business hours only" and "own calendar only" to ContextFlow's calendar sync
- Centralize file access audit trails through AgentGate
- Leverage "Powered by AgentGate" as a security selling point for ContextFlow Enterprise
- Use ContextFlow as a real-world case study and dogfooding environment for AgentGate

**However, they are independent businesses:**
- Separate repositories, domains, and brands
- AgentGate is a general-purpose product not dependent on ContextFlow
- ContextFlow is AgentGate's "first customer"

---

## 12. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|:------:|------------|
| Platform vendors build equivalent features natively | High | Multi-provider cross-platform support as core differentiator. No single vendor can build this |
| Many SaaS providers don't support token downscoping | Medium | Proxy-based approach as primary, native downscoping as optimization |
| Agent market grows slower than expected | Medium | Can pivot to human-facing JIT access (Indent-like positioning) |
| Building trust as a security product takes time | Medium | Ensure transparency through OSS + demonstrate self-use track record via ContextFlow |
| Resource constraints as a solo developer | High | Focus Phase 1 on Google Calendar only. Maximize reuse of ContextFlow tech assets |

---

## 13. Success Metrics (KPIs)

### Phase 1 Complete ✅ (Actual: completed in 2 days — 2026-03-24)
- ✅ Read/write control of Google Calendar API functioning via proxy
- ✅ Authorization logs recorded and queryable via API
- ✅ Latency: L1 pattern matching <5ms

### Phase 2 Complete ✅ (Actual: completed in 2 days — 2026-03-25)
- ✅ 3 providers supported (Google / Microsoft / Slack)
- ✅ L1 + L2 two-stage intent analysis operational
- ⬜ GitHub Stars: not yet published

### Phase 3 Complete ✅ (Actual: completed in 2 days — 2026-03-25)
- ✅ MCP-compatible proxy operational (JSON-RPC `tools/call` authorization)
- ⬜ ContextFlow integration (future task)
- ⬜ SDKs (future task)
- 111 tests passing

### Phase 4 Goals
- License selection + GitHub public release
- GitHub Stars: 100+ (within 1 month of launch)
- SDKs (pip / npm) published

### Year 1 Goals
- GitHub Stars: 1,000+
- Paid users: 50+
- MRR: $5,000+
