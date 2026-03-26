import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  AgentGateClient,
  AgentGateError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  ServerError,
} from "../src/index.js";

// ── Test helpers ────────────────────────────────────────────────────

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function textResponse(text: string, status = 200): Response {
  return new Response(text, {
    status,
    headers: { "content-type": "text/csv" },
  });
}

const BASE_URL = "http://localhost:8000";
const MASTER_KEY = "test-master-key";
const AGENT_KEY = "test-agent-key";

let fetchSpy: ReturnType<typeof vi.fn>;

function createClient(
  opts?: Partial<{ masterKey: string | undefined; agentKey: string | undefined }>,
): AgentGateClient {
  const config: Record<string, unknown> = { baseUrl: BASE_URL };
  const mk = opts && "masterKey" in opts ? opts.masterKey : MASTER_KEY;
  const ak = opts && "agentKey" in opts ? opts.agentKey : AGENT_KEY;
  if (mk !== undefined) config.masterKey = mk;
  if (ak !== undefined) config.agentKey = ak;
  return new AgentGateClient(config as import("../src/types.js").AgentGateConfig);
}

beforeEach(() => {
  fetchSpy = vi.fn();
  vi.stubGlobal("fetch", fetchSpy);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Discovery ───────────────────────────────────────────────────────

describe("discovery", () => {
  it("health() calls GET /health without auth", async () => {
    const body = {
      status: "ok",
      version: "0.2.0",
      providers: ["google", "openai"],
      policy_loaded: true,
      agents_count: 2,
      audit_db: "ok",
    };
    fetchSpy.mockResolvedValueOnce(jsonResponse(body));

    const client = createClient();
    const result = await client.health();

    expect(result).toEqual(body);
    expect(fetchSpy).toHaveBeenCalledOnce();
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/health`);
    expect(init.method).toBe("GET");
    expect(init.headers).not.toHaveProperty("x-master-key");
    expect(init.headers).not.toHaveProperty("x-agent-key");
  });

  it("providers() calls GET /providers without auth", async () => {
    const body = { providers: ["google", "openai", "anthropic"] };
    fetchSpy.mockResolvedValueOnce(jsonResponse(body));

    const client = createClient();
    const result = await client.providers();

    expect(result).toEqual(body);
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/providers`);
  });
});

// ── Agents ──────────────────────────────────────────────────────────

describe("agents", () => {
  const agentData = {
    agent_id: "ag_123",
    name: "test-bot",
    description: "A test agent",
    api_key: "ak_abc",
    policy: "default",
    provider: "google",
    created_at: "2025-01-01T00:00:00Z",
    request_count: 0,
    deny_count: 0,
    last_request_at: null,
  };

  it("create() sends POST /agents with master key and body", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(agentData));

    const client = createClient();
    const result = await client.agents.create({
      name: "test-bot",
      description: "A test agent",
      policy: "default",
      provider: "google",
    });

    expect(result).toEqual(agentData);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/agents`);
    expect(init.method).toBe("POST");
    expect(init.headers["x-master-key"]).toBe(MASTER_KEY);
    expect(init.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(init.body)).toEqual({
      name: "test-bot",
      description: "A test agent",
      policy: "default",
      provider: "google",
    });
  });

  it("list() sends GET /agents with master key", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse([agentData]));

    const client = createClient();
    const result = await client.agents.list();

    expect(result).toEqual([agentData]);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/agents`);
    expect(init.method).toBe("GET");
    expect(init.headers["x-master-key"]).toBe(MASTER_KEY);
  });

  it("delete() sends DELETE /agents/{id} with master key", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ status: "deleted" }));

    const client = createClient();
    const result = await client.agents.delete("ag_123");

    expect(result).toEqual({ status: "deleted" });
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/agents/ag_123`);
    expect(init.method).toBe("DELETE");
  });

  it("rotateKey() sends POST /agents/{id}/rotate-key", async () => {
    const rotated = { ...agentData, api_key: "ak_new" };
    fetchSpy.mockResolvedValueOnce(jsonResponse(rotated));

    const client = createClient();
    const result = await client.agents.rotateKey("ag_123");

    expect(result.api_key).toBe("ak_new");
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/agents/ag_123/rotate-key`);
    expect(init.method).toBe("POST");
  });

  it("stats() sends GET /agents/{id}/stats", async () => {
    const stats = {
      agent_id: "ag_123",
      name: "test-bot",
      request_count: 100,
      deny_count: 5,
      deny_rate: 0.05,
      last_request_at: "2025-06-01T12:00:00Z",
    };
    fetchSpy.mockResolvedValueOnce(jsonResponse(stats));

    const client = createClient();
    const result = await client.agents.stats("ag_123");

    expect(result).toEqual(stats);
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/agents/ag_123/stats`);
  });

  it("throws Error when masterKey is missing", async () => {
    const client = createClient({ masterKey: undefined });
    await expect(client.agents.list()).rejects.toThrow(
      "masterKey is required",
    );
  });
});

// ── Audit ───────────────────────────────────────────────────────────

describe("audit", () => {
  it("logs() sends GET /audit/logs with query params", async () => {
    const body = { logs: [], total: 0 };
    fetchSpy.mockResolvedValueOnce(jsonResponse(body));

    const client = createClient();
    const result = await client.audit.logs({
      agent_id: "ag_1",
      decision: "deny",
      limit: 10,
      offset: 5,
    });

    expect(result).toEqual(body);
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toContain("/audit/logs?");
    expect(url).toContain("agent_id=ag_1");
    expect(url).toContain("decision=deny");
    expect(url).toContain("limit=10");
    expect(url).toContain("offset=5");
  });

  it("stats() sends GET /audit/stats", async () => {
    const body = { total: 100, deny: 10 };
    fetchSpy.mockResolvedValueOnce(jsonResponse(body));

    const client = createClient();
    const result = await client.audit.stats({ provider: "openai" });

    expect(result).toEqual(body);
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toContain("/audit/stats?provider=openai");
  });

  it("export() sends GET /audit/export with format=json", async () => {
    const body = { logs: [], count: 0 };
    fetchSpy.mockResolvedValueOnce(jsonResponse(body));

    const client = createClient();
    await client.audit.export({ limit: 500 });

    const [url] = fetchSpy.mock.calls[0];
    expect(url).toContain("format=json");
    expect(url).toContain("limit=500");
  });

  it("exportCsv() returns raw text", async () => {
    fetchSpy.mockResolvedValueOnce(textResponse("id,timestamp\n1,2025-01-01"));

    const client = createClient();
    const csv = await client.audit.exportCsv();

    expect(csv).toBe("id,timestamp\n1,2025-01-01");
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toContain("format=csv");
  });

  it("purge() sends POST /audit/purge with retention_days", async () => {
    const body = { purged: 42, retention_days: 30 };
    fetchSpy.mockResolvedValueOnce(jsonResponse(body));

    const client = createClient();
    const result = await client.audit.purge({ retention_days: 30 });

    expect(result).toEqual(body);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toContain("/audit/purge?retention_days=30");
    expect(init.method).toBe("POST");
  });
});

// ── Proxy ───────────────────────────────────────────────────────────

describe("proxy", () => {
  it("request() sends to /proxy/{provider}/{path} with agent key", async () => {
    const body = { result: "ok" };
    fetchSpy.mockResolvedValueOnce(jsonResponse(body));

    const client = createClient();
    const result = await client.proxy.request({
      provider: "openai",
      path: "v1/chat/completions",
      method: "POST",
      body: { model: "gpt-4", messages: [] },
    });

    expect(result).toEqual(body);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/proxy/openai/v1/chat/completions`);
    expect(init.method).toBe("POST");
    expect(init.headers["x-agent-key"]).toBe(AGENT_KEY);
    expect(init.headers).not.toHaveProperty("x-master-key");
  });

  it("request() defaults method to POST", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({}));

    const client = createClient();
    await client.proxy.request({ provider: "google", path: "v1/generate" });

    const [, init] = fetchSpy.mock.calls[0];
    expect(init.method).toBe("POST");
  });

  it("request() includes extra headers and query params", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({}));

    const client = createClient();
    await client.proxy.request({
      provider: "anthropic",
      path: "v1/messages",
      headers: { "anthropic-version": "2024-01-01" },
      query: { stream: "true" },
    });

    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toContain("?stream=true");
    expect(init.headers["anthropic-version"]).toBe("2024-01-01");
  });

  it("mcp() sends POST /mcp/{server_name} with agent key", async () => {
    const rpcResponse = { jsonrpc: "2.0", id: 1, result: {} };
    fetchSpy.mockResolvedValueOnce(jsonResponse(rpcResponse));

    const client = createClient();
    const result = await client.proxy.mcp({
      serverName: "filesystem",
      body: { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} },
    });

    expect(result).toEqual(rpcResponse);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/mcp/filesystem`);
    expect(init.method).toBe("POST");
    expect(init.headers["x-agent-key"]).toBe(AGENT_KEY);
  });

  it("throws Error when agentKey is missing", async () => {
    const client = createClient({ agentKey: undefined });
    await expect(
      client.proxy.request({ provider: "openai", path: "v1/models" }),
    ).rejects.toThrow("agentKey is required");
  });
});

// ── Config ──────────────────────────────────────────────────────────

describe("config", () => {
  it("policies() sends GET /policies with master key", async () => {
    const body = [{ name: "default", rules: [{ effect: "allow" }] }];
    fetchSpy.mockResolvedValueOnce(jsonResponse(body));

    const client = createClient();
    const result = await client.config.policies();

    expect(result).toEqual(body);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/policies`);
    expect(init.headers["x-master-key"]).toBe(MASTER_KEY);
  });

  it("registerWebhook() sends POST /webhooks", async () => {
    const response = {
      status: "registered",
      url: "https://hooks.example.com",
      events: ["deny"],
    };
    fetchSpy.mockResolvedValueOnce(jsonResponse(response));

    const client = createClient();
    const result = await client.config.registerWebhook({
      url: "https://hooks.example.com",
      events: ["deny"],
    });

    expect(result).toEqual(response);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/webhooks`);
    expect(init.method).toBe("POST");
  });

  it("registerAlertThreshold() sends POST /alerts/thresholds", async () => {
    const response = {
      status: "registered",
      event: "deny",
      count: 10,
      window_seconds: 300,
    };
    fetchSpy.mockResolvedValueOnce(jsonResponse(response));

    const client = createClient();
    const result = await client.config.registerAlertThreshold({
      event: "deny",
      count: 10,
      window_seconds: 300,
    });

    expect(result).toEqual(response);
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/alerts/thresholds`);
  });

  it("registerMCPServer() sends POST /mcp/servers", async () => {
    const response = {
      status: "registered",
      name: "my-mcp",
      url: "http://mcp:3000",
      tools_registered: 2,
      auto_policy: "mcp_my-mcp",
    };
    fetchSpy.mockResolvedValueOnce(jsonResponse(response));

    const client = createClient();
    const result = await client.config.registerMCPServer({
      name: "my-mcp",
      url: "http://mcp:3000",
      tools: [{ name: "read_file" }, { name: "write_file" }],
    });

    expect(result).toEqual(response);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/mcp/servers`);
    expect(init.method).toBe("POST");
    expect(init.headers["x-master-key"]).toBe(MASTER_KEY);
  });
});

// ── Error mapping ───────────────────────────────────────────────────

describe("error mapping", () => {
  it("401 -> AuthenticationError", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ detail: "Missing X-Agent-Key header" }, 401),
    );

    const client = createClient();
    try {
      await client.health();
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthenticationError);
      expect((err as AuthenticationError).status).toBe(401);
      expect((err as AuthenticationError).detail).toBe(
        "Missing X-Agent-Key header",
      );
    }
  });

  it("403 -> AuthorizationError", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ detail: "Invalid master key" }, 403),
    );

    const client = createClient();
    try {
      await client.agents.list();
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthorizationError);
      expect((err as AuthorizationError).status).toBe(403);
    }
  });

  it("404 -> NotFoundError", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ detail: "Agent not found" }, 404),
    );

    const client = createClient();
    try {
      await client.agents.delete("nonexistent");
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(NotFoundError);
      expect((err as NotFoundError).status).toBe(404);
    }
  });

  it("422 -> ValidationError", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ detail: "Invalid field" }, 422),
    );

    const client = createClient();
    try {
      await client.agents.create({ name: "" });
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ValidationError);
      expect((err as ValidationError).status).toBe(422);
    }
  });

  it("429 -> RateLimitError", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ detail: "Too many requests" }, 429),
    );

    const client = createClient();
    try {
      await client.health();
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RateLimitError);
      expect((err as RateLimitError).status).toBe(429);
    }
  });

  it("500 -> ServerError", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ detail: "Internal server error" }, 500),
    );

    const client = createClient();
    try {
      await client.health();
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ServerError);
      expect((err as ServerError).status).toBe(500);
    }
  });

  it("502 -> ServerError (any 5xx)", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ detail: "Bad gateway" }, 502),
    );

    const client = createClient();
    try {
      await client.health();
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ServerError);
      expect((err as ServerError).status).toBe(502);
    }
  });

  it("unknown 4xx -> AgentGateError", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ detail: "Conflict" }, 409),
    );

    const client = createClient();
    try {
      await client.health();
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AgentGateError);
      expect((err as AgentGateError).status).toBe(409);
      // Should NOT be a more specific subclass
      expect(err).not.toBeInstanceOf(AuthenticationError);
      expect(err).not.toBeInstanceOf(AuthorizationError);
    }
  });
});

// ── Trailing slash handling ─────────────────────────────────────────

describe("base URL handling", () => {
  it("strips trailing slash from baseUrl", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ status: "ok" }));

    const client = new AgentGateClient({
      baseUrl: "http://localhost:8000/",
    });
    await client.health();

    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe("http://localhost:8000/health");
  });
});

// ── Default headers ─────────────────────────────────────────────────

describe("default headers", () => {
  it("includes custom default headers in requests", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({}));

    const client = new AgentGateClient({
      baseUrl: BASE_URL,
      headers: { "x-custom": "hello" },
    });
    await client.health();

    const [, init] = fetchSpy.mock.calls[0];
    expect(init.headers["x-custom"]).toBe("hello");
  });
});
