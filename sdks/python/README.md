# agentgate-sdk

Python SDK for [AgentGate](https://github.com/yoned0609/AgentGate) — JIT Authorization Proxy for AI Agents.

## Installation

```bash
pip install agentgate-sdk
```

## Quick Start

### Sync Client

```python
from agentgate_sdk import AgentGateClient

client = AgentGateClient(
    base_url="http://localhost:8000",
    master_key="your-master-key",
)

# Create an agent
agent = client.agents.create("my-agent", policy="default", provider="openai")
print(agent.agent_id, agent.api_key)

# List agents
for a in client.agents.list():
    print(a.name, a.request_count)

# Check health
health = client.health()
print(health.status, health.providers)

# Query audit logs
logs = client.audit.logs(limit=10, decision="deny")
print(f"{logs.total} deny entries")

# Proxy a request (use agent_key instead of master_key)
proxy_client = AgentGateClient(
    base_url="http://localhost:8000",
    agent_key=agent.api_key,
)
resp = proxy_client.proxy.request(
    "openai", "v1/chat/completions",
    json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
)
print(resp.json())

client.close()
```

### Async Client

```python
import asyncio
from agentgate_sdk import AsyncAgentGateClient

async def main():
    async with AsyncAgentGateClient(
        base_url="http://localhost:8000",
        master_key="your-master-key",
    ) as client:
        agent = await client.agents.create("async-agent")
        print(agent.agent_id)

        logs = await client.audit.logs(limit=5)
        print(f"{logs.total} log entries")

asyncio.run(main())
```

## Resource Namespaces

| Namespace        | Auth         | Methods                                                        |
|------------------|--------------|----------------------------------------------------------------|
| `client.agents`  | master_key   | `create()`, `list()`, `delete()`, `rotate_key()`, `stats()`   |
| `client.audit`   | master_key   | `logs()`, `stats()`, `export()`, `purge()`                    |
| `client.proxy`   | agent_key    | `request()`, `mcp()`                                          |
| `client.config`  | master_key   | `list_policies()`, `register_webhook()`, `register_alert_threshold()`, `register_mcp_server()` |
| `client.health()`| none         | Health check                                                   |
| `client.providers()`| none      | List available providers                                       |

## Exception Handling

```python
from agentgate_sdk import AgentGateClient
from agentgate_sdk.exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
)

client = AgentGateClient(base_url="http://localhost:8000", master_key="wrong")

try:
    client.agents.list()
except AuthorizationError as e:
    print(f"Auth failed: {e}")
except NotFoundError as e:
    print(f"Not found: {e}")
except RateLimitError as e:
    print(f"Rate limited: {e}")
```

| HTTP Status | Exception            |
|-------------|----------------------|
| 401         | `AuthenticationError`|
| 403         | `AuthorizationError` |
| 404         | `NotFoundError`      |
| 422         | `ValidationError`    |
| 429         | `RateLimitError`     |
| 5xx         | `ServerError`        |

## License

MIT
