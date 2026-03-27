# agentgate-sdk

TypeScript SDK for [AgentGate](https://github.com/yoned0609/AgentGate) -- JIT Authorization Proxy for AI Agents.

## Installation

```bash
npm install agentgate-sdk
```

## Quick Start

```typescript
import { AgentGateClient } from "agentgate-sdk";

const client = new AgentGateClient({
  baseUrl: "http://localhost:8000",
  masterKey: "your-master-key",
  agentKey: "your-agent-key",
});

// Health check (no auth required)
const health = await client.health();

// Create an agent (requires masterKey)
const agent = await client.agents.create({
  name: "my-bot",
  policy: "default",
  provider: "openai",
});

// List agents
const agents = await client.agents.list();

// Proxy a request through AgentGate (requires agentKey)
const response = await client.proxy.request({
  provider: "openai",
  path: "v1/chat/completions",
  method: "POST",
  body: {
    model: "gpt-4",
    messages: [{ role: "user", content: "Hello" }],
  },
});

// Query audit logs
const logs = await client.audit.logs({ decision: "deny", limit: 20 });

// MCP JSON-RPC proxy
const result = await client.proxy.mcp({
  serverName: "filesystem",
  body: { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} },
});
```

## Error Handling

All API errors are thrown as typed exceptions:

```typescript
import {
  AgentGateError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  ValidationError,
  ServerError,
} from "agentgate-sdk";

try {
  await client.agents.delete("nonexistent");
} catch (err) {
  if (err instanceof NotFoundError) {
    console.log("Agent not found:", err.detail);
  } else if (err instanceof AuthorizationError) {
    console.log("Bad master key");
  }
}
```

## API Reference

### Discovery (no auth)
- `client.health()` -- Health check
- `client.providers()` -- List available providers

### Agents (masterKey)
- `client.agents.create(params)` -- Create agent
- `client.agents.list()` -- List agents
- `client.agents.delete(id)` -- Delete agent
- `client.agents.rotateKey(id)` -- Rotate API key
- `client.agents.stats(id)` -- Usage stats

### Proxy (agentKey)
- `client.proxy.request(params)` -- Forward request through policy engine
- `client.proxy.mcp(params)` -- MCP JSON-RPC proxy

### Audit (masterKey)
- `client.audit.logs(params?)` -- Query logs
- `client.audit.stats(params?)` -- Aggregated stats
- `client.audit.export(params?)` -- Export as JSON
- `client.audit.exportCsv(params?)` -- Export as CSV
- `client.audit.purge(params?)` -- Purge old logs

### Config (masterKey)
- `client.config.policies()` -- List policies
- `client.config.registerWebhook(params)` -- Register webhook
- `client.config.registerAlertThreshold(params)` -- Register alert threshold
- `client.config.registerMCPServer(params)` -- Register MCP server

## License

MIT
