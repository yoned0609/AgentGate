/** Configuration options for the AgentGate client. */
export interface AgentGateConfig {
  /** Base URL of the AgentGate server (e.g. "http://localhost:8000"). */
  baseUrl: string;
  /** Master API key for admin endpoints. */
  masterKey?: string;
  /** Agent API key for proxy endpoints. */
  agentKey?: string;
  /** Request timeout in milliseconds. Defaults to 30000. */
  timeout?: number;
  /** Additional default headers to include in every request. */
  headers?: Record<string, string>;
}

// ── Agent Models ────────────────────────────────────────────────────

export interface AgentCreateParams {
  name: string;
  description?: string;
  policy?: string;
  provider?: string;
}

export interface AgentResponse {
  agent_id: string;
  name: string;
  description: string;
  api_key: string;
  policy: string;
  provider: string;
  created_at: string;
  request_count: number;
  deny_count: number;
  last_request_at: string | null;
}

export interface AgentStats {
  agent_id: string;
  name: string;
  request_count: number;
  deny_count: number;
  deny_rate: number;
  last_request_at: string | null;
}

export interface AgentDeleteResponse {
  status: string;
}

// ── Audit Models ────────────────────────────────────────────────────

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  agent_id: string;
  agent_name: string;
  method: string;
  path: string;
  provider: string;
  decision: "allow" | "deny" | "error";
  deny_reason: string | null;
  intent: string;
  intent_confidence: number;
  status_code: number | null;
  latency_ms: number;
  request_id: string;
}

export interface AuditLogList {
  logs: AuditLogEntry[];
  total: number;
}

export interface AuditLogsParams {
  agent_id?: string;
  decision?: string;
  provider?: string;
  limit?: number;
  offset?: number;
}

export interface AuditStatsParams {
  agent_id?: string;
  provider?: string;
}

export interface AuditStatsResponse {
  [key: string]: unknown;
}

export interface AuditExportParams {
  agent_id?: string;
  decision?: string;
  provider?: string;
  format?: "json" | "csv";
  limit?: number;
}

export interface AuditExportJsonResponse {
  logs: Record<string, unknown>[];
  count: number;
}

export interface AuditPurgeParams {
  retention_days?: number;
}

export interface AuditPurgeResponse {
  purged: number;
  retention_days: number;
}

// ── Policy Models ───────────────────────────────────────────────────

export interface PolicyInfo {
  name: string;
  rules: Record<string, unknown>[];
}

// ── Webhook / Alert Models ──────────────────────────────────────────

export interface WebhookCreateParams {
  url: string;
  events?: string[];
  headers?: Record<string, string>;
}

export interface WebhookCreateResponse {
  status: string;
  url: string;
  events: string[];
}

export interface AlertThresholdParams {
  event?: string;
  count?: number;
  window_seconds?: number;
  agent_id?: string;
}

export interface AlertThresholdResponse {
  status: string;
  event: string;
  count: number;
  window_seconds: number;
}

// ── MCP Models ──────────────────────────────────────────────────────

export interface MCPServerRegisterParams {
  name?: string;
  url: string;
  tools?: Record<string, unknown>[];
}

export interface MCPServerRegisterResponse {
  status: string;
  name: string;
  url: string;
  tools_registered: number;
  auto_policy: string | null;
}

export interface MCPRequestParams {
  serverName: string;
  body: Record<string, unknown>;
}

// ── Proxy Models ────────────────────────────────────────────────────

export interface ProxyRequestParams {
  provider: string;
  path: string;
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
  query?: Record<string, string>;
}

// ── Discovery Models ────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  version: string;
  providers: string[];
  policy_loaded: boolean;
  agents_count: number;
  audit_db: string;
}

export interface ProvidersResponse {
  providers: string[];
}
