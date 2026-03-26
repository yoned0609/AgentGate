import { mapStatusToError } from "./errors.js";
import type {
  AgentCreateParams,
  AgentDeleteResponse,
  AgentGateConfig,
  AgentResponse,
  AgentStats,
  AlertThresholdParams,
  AlertThresholdResponse,
  AuditExportJsonResponse,
  AuditExportParams,
  AuditLogList,
  AuditLogsParams,
  AuditPurgeParams,
  AuditPurgeResponse,
  AuditStatsParams,
  AuditStatsResponse,
  HealthResponse,
  MCPRequestParams,
  MCPServerRegisterParams,
  MCPServerRegisterResponse,
  PolicyInfo,
  ProvidersResponse,
  ProxyRequestParams,
  WebhookCreateParams,
  WebhookCreateResponse,
} from "./types.js";

// ── Internal helpers ────────────────────────────────────────────────

function stripTrailingSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}

function buildQueryString(params: Record<string, unknown> | object): string {
  const entries: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      entries.push(
        `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`,
      );
    }
  }
  return entries.length > 0 ? `?${entries.join("&")}` : "";
}

// ── Resource namespaces ─────────────────────────────────────────────

export class AgentsResource {
  constructor(private readonly _request: AgentGateClient["_request"]) {}

  /** Create a new agent. Requires masterKey. */
  async create(params: AgentCreateParams): Promise<AgentResponse> {
    return this._request<AgentResponse>("POST", "/agents", {
      body: params,
      auth: "master",
    });
  }

  /** List all agents. Requires masterKey. */
  async list(): Promise<AgentResponse[]> {
    return this._request<AgentResponse[]>("GET", "/agents", {
      auth: "master",
    });
  }

  /** Delete an agent by ID. Requires masterKey. */
  async delete(agentId: string): Promise<AgentDeleteResponse> {
    return this._request<AgentDeleteResponse>("DELETE", `/agents/${agentId}`, {
      auth: "master",
    });
  }

  /** Rotate an agent's API key. Requires masterKey. */
  async rotateKey(agentId: string): Promise<AgentResponse> {
    return this._request<AgentResponse>(
      "POST",
      `/agents/${agentId}/rotate-key`,
      { auth: "master" },
    );
  }

  /** Get usage stats for an agent. Requires masterKey. */
  async stats(agentId: string): Promise<AgentStats> {
    return this._request<AgentStats>("GET", `/agents/${agentId}/stats`, {
      auth: "master",
    });
  }
}

export class AuditResource {
  constructor(private readonly _request: AgentGateClient["_request"]) {}

  /** Query audit logs. Requires masterKey. */
  async logs(params: AuditLogsParams = {}): Promise<AuditLogList> {
    const qs = buildQueryString(params);
    return this._request<AuditLogList>("GET", `/audit/logs${qs}`, {
      auth: "master",
    });
  }

  /** Get aggregated audit stats. Requires masterKey. */
  async stats(params: AuditStatsParams = {}): Promise<AuditStatsResponse> {
    const qs = buildQueryString(params);
    return this._request<AuditStatsResponse>("GET", `/audit/stats${qs}`, {
      auth: "master",
    });
  }

  /** Export audit logs as JSON. For CSV use exportCsv(). Requires masterKey. */
  async export(
    params: Omit<AuditExportParams, "format"> = {},
  ): Promise<AuditExportJsonResponse> {
    const qs = buildQueryString({ ...params, format: "json" });
    return this._request<AuditExportJsonResponse>(
      "GET",
      `/audit/export${qs}`,
      { auth: "master" },
    );
  }

  /** Export audit logs as raw CSV string. Requires masterKey. */
  async exportCsv(
    params: Omit<AuditExportParams, "format"> = {},
  ): Promise<string> {
    const qs = buildQueryString({ ...params, format: "csv" });
    return this._request<string>("GET", `/audit/export${qs}`, {
      auth: "master",
      rawText: true,
    });
  }

  /** Purge old audit logs. Requires masterKey. */
  async purge(
    params: AuditPurgeParams = {},
  ): Promise<AuditPurgeResponse> {
    const qs = buildQueryString(params);
    return this._request<AuditPurgeResponse>("POST", `/audit/purge${qs}`, {
      auth: "master",
    });
  }
}

export class ProxyResource {
  constructor(private readonly _request: AgentGateClient["_request"]) {}

  /** Send a request through the AgentGate proxy. Requires agentKey. */
  async request(params: ProxyRequestParams): Promise<unknown> {
    const { provider, path, method = "POST", body, headers, query } = params;
    const qs = query ? buildQueryString(query) : "";
    return this._request<unknown>(
      method,
      `/proxy/${provider}/${path}${qs}`,
      {
        body,
        auth: "agent",
        extraHeaders: headers,
      },
    );
  }

  /** Send a JSON-RPC request to a registered MCP server. Requires agentKey. */
  async mcp(params: MCPRequestParams): Promise<unknown> {
    return this._request<unknown>("POST", `/mcp/${params.serverName}`, {
      body: params.body,
      auth: "agent",
    });
  }
}

export class ConfigResource {
  constructor(private readonly _request: AgentGateClient["_request"]) {}

  /** List all loaded policies. Requires masterKey. */
  async policies(): Promise<PolicyInfo[]> {
    return this._request<PolicyInfo[]>("GET", "/policies", {
      auth: "master",
    });
  }

  /** Register a webhook. Requires masterKey. */
  async registerWebhook(
    params: WebhookCreateParams,
  ): Promise<WebhookCreateResponse> {
    return this._request<WebhookCreateResponse>("POST", "/webhooks", {
      body: params,
      auth: "master",
    });
  }

  /** Register an alert threshold. Requires masterKey. */
  async registerAlertThreshold(
    params: AlertThresholdParams,
  ): Promise<AlertThresholdResponse> {
    return this._request<AlertThresholdResponse>(
      "POST",
      "/alerts/thresholds",
      { body: params, auth: "master" },
    );
  }

  /** Register an MCP server. Requires masterKey. */
  async registerMCPServer(
    params: MCPServerRegisterParams,
  ): Promise<MCPServerRegisterResponse> {
    return this._request<MCPServerRegisterResponse>("POST", "/mcp/servers", {
      body: params,
      auth: "master",
    });
  }
}

// ── Main client ─────────────────────────────────────────────────────

interface RequestOptions {
  body?: unknown;
  auth?: "master" | "agent" | "none";
  extraHeaders?: Record<string, string>;
  rawText?: boolean;
}

export class AgentGateClient {
  private readonly _baseUrl: string;
  private readonly _masterKey: string | undefined;
  private readonly _agentKey: string | undefined;
  private readonly _timeout: number;
  private readonly _defaultHeaders: Record<string, string>;

  /** Agent management endpoints. */
  public readonly agents: AgentsResource;
  /** Audit log endpoints. */
  public readonly audit: AuditResource;
  /** Proxy and MCP proxy endpoints. */
  public readonly proxy: ProxyResource;
  /** Configuration endpoints (policies, webhooks, alerts, MCP servers). */
  public readonly config: ConfigResource;

  constructor(options: AgentGateConfig) {
    this._baseUrl = stripTrailingSlash(options.baseUrl);
    this._masterKey = options.masterKey;
    this._agentKey = options.agentKey;
    this._timeout = options.timeout ?? 30_000;
    this._defaultHeaders = options.headers ?? {};

    // Bind _request so resource classes can use it
    const boundRequest = this._request.bind(this);
    this.agents = new AgentsResource(boundRequest);
    this.audit = new AuditResource(boundRequest);
    this.proxy = new ProxyResource(boundRequest);
    this.config = new ConfigResource(boundRequest);
  }

  // ── Discovery (no auth) ────────────────────────────────────────────

  /** Health check. No authentication required. */
  async health(): Promise<HealthResponse> {
    return this._request<HealthResponse>("GET", "/health", { auth: "none" });
  }

  /** List available providers. No authentication required. */
  async providers(): Promise<ProvidersResponse> {
    return this._request<ProvidersResponse>("GET", "/providers", {
      auth: "none",
    });
  }

  // ── Internal request method ────────────────────────────────────────

  /** @internal */
  async _request<T>(
    method: string,
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    const { body, auth = "none", extraHeaders, rawText } = options;

    const headers: Record<string, string> = {
      ...this._defaultHeaders,
      ...extraHeaders,
    };

    if (auth === "master") {
      if (!this._masterKey) {
        throw new Error(
          "masterKey is required for this operation. Pass it in AgentGateConfig.",
        );
      }
      headers["x-master-key"] = this._masterKey;
    } else if (auth === "agent") {
      if (!this._agentKey) {
        throw new Error(
          "agentKey is required for this operation. Pass it in AgentGateConfig.",
        );
      }
      headers["x-agent-key"] = this._agentKey;
    }

    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }

    const url = `${this._baseUrl}${path}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this._timeout);

    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } catch (err: unknown) {
      clearTimeout(timeoutId);
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new Error(`Request to ${method} ${path} timed out after ${this._timeout}ms`);
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }

    if (!response.ok) {
      let responseBody: unknown;
      try {
        responseBody = await response.json();
      } catch {
        responseBody = await response.text().catch(() => null);
      }
      throw mapStatusToError(response.status, responseBody);
    }

    if (rawText) {
      return (await response.text()) as T;
    }

    return (await response.json()) as T;
  }
}
