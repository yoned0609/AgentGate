export { AgentGateClient } from "./client.js";
export type {
  AgentsResource,
  AuditResource,
  ProxyResource,
  ConfigResource,
} from "./client.js";

export {
  AgentGateError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  ServerError,
  mapStatusToError,
} from "./errors.js";

export type {
  AgentGateConfig,
  AgentCreateParams,
  AgentResponse,
  AgentStats,
  AgentDeleteResponse,
  AuditLogEntry,
  AuditLogList,
  AuditLogsParams,
  AuditStatsParams,
  AuditStatsResponse,
  AuditExportParams,
  AuditExportJsonResponse,
  AuditPurgeParams,
  AuditPurgeResponse,
  PolicyInfo,
  WebhookCreateParams,
  WebhookCreateResponse,
  AlertThresholdParams,
  AlertThresholdResponse,
  MCPServerRegisterParams,
  MCPServerRegisterResponse,
  MCPRequestParams,
  ProxyRequestParams,
  HealthResponse,
  ProvidersResponse,
} from "./types.js";
