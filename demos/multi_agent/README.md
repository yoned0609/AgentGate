# AgentGate Multi-Agent Security Demo

A technical demo proving that AgentGate acts as a consistent
security and governance layer across multiple AI agents.

## Architecture

```mermaid
graph TB
    User([User])

    subgraph AgentGate["AgentGate Proxy"]
        direction TB
        PolicyEngine["Policy Engine<br/>- PII detection -> masking<br/>- Forbidden words -> block<br/>- Routing permissions"]
        TraceLog["Trace Log<br/>- Source/destination tracking<br/>- Full communication log<br/>- Decision records"]
    end

    subgraph Agents["Agent Pool"]
        Orchestrator["Orchestrator<br/>Task decomposition & dispatch"]
        Executor["Executor<br/>Task execution"]
        Reviewer["Reviewer<br/>Result review"]
    end

    User -->|Submit task| Orchestrator
    Orchestrator -->|1. Execute request| AgentGate
    AgentGate -->|Inspected| Executor
    Executor -->|2. Execution result| AgentGate
    AgentGate -->|Inspected| Orchestrator
    Orchestrator -->|3. Review request| AgentGate
    AgentGate -->|Inspected| Reviewer
    Reviewer -->|4. Review result| AgentGate
    AgentGate -->|Inspected| Orchestrator

    Executor -.->|Direct communication denied| Reviewer

    style AgentGate fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#fff
    style Orchestrator fill:#16213e,stroke:#0f3460,color:#fff
    style Executor fill:#16213e,stroke:#0f3460,color:#fff
    style Reviewer fill:#16213e,stroke:#0f3460,color:#fff
```

## Communication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant O as Orchestrator
    participant G as AgentGate Proxy
    participant E as Executor
    participant R as Reviewer

    U->>O: Submit task
    O->>G: Execute request (to: Executor)
    G->>G: Policy check
    G->>E: Deliver
    E->>G: Execution result (to: Orchestrator)
    G->>G: Policy check
    G->>O: Deliver
    O->>G: Review request (to: Reviewer)
    G->>G: Policy check
    G->>R: Deliver
    R->>G: Review result (to: Orchestrator)
    G->>G: Policy check
    G->>O: Deliver
    O->>U: Final result

    Note over G: PII detected -> masked
    Note over G: Forbidden word -> blocked
    Note over G: Routing violation -> denied
```

## Demo Scenarios

| # | Scenario | Description | Expected |
|---|----------|-------------|----------|
| 1 | Normal Flow | Orchestrator -> Executor -> Reviewer collaboration | All ALLOW |
| 2 | PII Masking | Message containing email, phone, credit card | PII replaced with `***` |
| 3 | Forbidden Word | SQL injection payload | Message BLOCKED |
| 4 | Routing Violation | Executor -> Reviewer direct communication | Routing BLOCKED |

## Setup

```bash
cd demos/multi_agent
pip install -r requirements.txt
```

## Usage

### CLI Mode (recommended)

```bash
python3 main.py
```

Interactive slideshow — press Enter to advance through each scenario.
Trace log summary is displayed at the end.

### HTTP API Mode

```bash
uvicorn gate_proxy:app --port 8200
```

```bash
# Register agent
curl -X POST http://localhost:8200/agents/register \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "orchestrator", "role": "orchestrator"}'

# Relay message
curl -X POST http://localhost:8200/relay \
  -H "Content-Type: application/json" \
  -d '{
    "from_agent": "orchestrator",
    "to_agent": "executor",
    "payload": "test message"
  }'

# View trace log
curl http://localhost:8200/trace
```

### Tests

```bash
pytest test_demo.py -v
```

## File Structure

```
demos/multi_agent/
├── README.md           # This file
├── requirements.txt    # Dependencies
├── policies.yaml       # Security policy definitions
├── gate_proxy.py       # AgentGate Proxy implementation
├── agents.py           # Agent definitions (Orchestrator/Executor/Reviewer)
├── main.py             # Interactive demo script
└── test_demo.py        # Test suite
```

## Policy Configuration

`policies.yaml` controls the following:

- **PII patterns**: Email, phone number, credit card, SSN, national ID
- **Forbidden words**: SQL injection, XSS, dangerous shell commands, confidential keys
- **Masking mode**: `mask` (replace and continue) / `block` (reject message)
- **Routing permissions**: Per-agent send-to restrictions
- **Message size limits**: Per-agent maximum payload size
