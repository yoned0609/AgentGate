"""
Multi-Agent Definitions
========================
Orchestrator / Executor / Reviewer — three agents.
All communication flows through the AgentGate Proxy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gate_proxy import AgentGateProxy


# ---------------------------------------------------------------------------
# Base Agent
# ---------------------------------------------------------------------------

@dataclass
class BaseAgent:
    agent_id: str
    role: str
    proxy: AgentGateProxy
    inbox: list[dict] = field(default_factory=list)

    def __post_init__(self):
        self.proxy.register_agent(self.agent_id, self.role)
        self.proxy.set_callback(self.agent_id, self._on_message)

    def _on_message(self, from_agent: str, payload: str, metadata: dict):
        self.inbox.append({
            "from": from_agent,
            "payload": payload,
            "metadata": metadata,
        })

    def send(self, to_agent: str, payload: str, metadata: dict | None = None):
        return self.proxy.relay(self.agent_id, to_agent, payload, metadata)

    def _print(self, msg: str):
        colors = {
            "orchestrator": "\033[36m",
            "executor": "\033[35m",
            "reviewer": "\033[34m",
        }
        c = colors.get(self.role, "")
        print(f"  {c}[{self.agent_id}]\033[0m {msg}")


# ---------------------------------------------------------------------------
# Orchestrator Agent
# ---------------------------------------------------------------------------

class OrchestratorAgent(BaseAgent):
    """Decomposes user tasks and dispatches to sub-agents."""

    def process_user_task(self, task: str) -> dict:
        self._print(f"Task received: {task}")
        self._print("Decomposing task...")

        # Step 1: Send to Executor
        self._print("-> Dispatching to Executor")
        exec_result = self.send(
            "executor",
            f"Please execute the following task:\n{task}",
            {"step": "execute", "task_type": "code_generation"},
        )

        if exec_result.decision.value == "block":
            self._print("BLOCKED: Cannot send to Executor")
            return {"status": "blocked", "phase": "execution", "result": exec_result}

        exec_response = self._wait_for_response("executor")

        # Step 2: Send to Reviewer
        self._print("-> Dispatching to Reviewer")
        review_result = self.send(
            "reviewer",
            f"Please review the following result:\n{exec_response}",
            {"step": "review", "original_task": task},
        )

        if review_result.decision.value == "block":
            self._print("BLOCKED: Cannot send to Reviewer")
            return {"status": "blocked", "phase": "review", "result": review_result}

        review_response = self._wait_for_response("reviewer")

        self._print("Task completed successfully")
        return {
            "status": "completed",
            "execution": exec_response,
            "review": review_response,
        }

    def _wait_for_response(self, from_agent: str) -> str:
        for msg in reversed(self.inbox):
            if msg["from"] == from_agent:
                return msg["payload"]
        return "(no response)"


# ---------------------------------------------------------------------------
# Executor Agent
# ---------------------------------------------------------------------------

class ExecutorAgent(BaseAgent):
    """Executes tasks and returns results."""

    def __post_init__(self):
        super().__post_init__()
        original_on_message = self._on_message

        def auto_process(from_agent, payload, metadata):
            original_on_message(from_agent, payload, metadata)
            self._print(f"Task received (from {from_agent})")
            result = self.execute(payload, metadata)
            self._print("Execution done -> Replying to Orchestrator")
            self.send("orchestrator", result, {"step": "execution_result"})

        self.proxy.set_callback(self.agent_id, auto_process)

    def execute(self, task: str, metadata: dict) -> str:
        self._print("Generating code...")

        return (
            "## Execution Result\n"
            "```python\n"
            "def fibonacci(n: int) -> list[int]:\n"
            '    """Generate a Fibonacci sequence."""\n'
            "    if n <= 0:\n"
            "        return []\n"
            "    seq = [0, 1]\n"
            "    for _ in range(2, n):\n"
            "        seq.append(seq[-1] + seq[-2])\n"
            "    return seq[:n]\n"
            "```\n"
            "Execution time: 0.003ms\n"
            "Tests: 5/5 passed"
        )


# ---------------------------------------------------------------------------
# Reviewer Agent
# ---------------------------------------------------------------------------

class ReviewerAgent(BaseAgent):
    """Reviews execution results and provides feedback."""

    def __post_init__(self):
        super().__post_init__()
        original_on_message = self._on_message

        def auto_process(from_agent, payload, metadata):
            original_on_message(from_agent, payload, metadata)
            self._print(f"Review request received (from {from_agent})")
            result = self.review(payload, metadata)
            self._print("Review done -> Replying to Orchestrator")
            self.send("orchestrator", result, {"step": "review_result"})

        self.proxy.set_callback(self.agent_id, auto_process)

    def review(self, content: str, metadata: dict) -> str:
        self._print("Reviewing code...")

        return (
            "## Review Result\n"
            "Verdict: PASS\n\n"
            "### Strengths\n"
            "- Type hints improve readability\n"
            "- Edge case (n<=0) handled correctly\n"
            "- Docstring included\n\n"
            "### Suggestions\n"
            "- Consider adding memoization or a generator variant\n"
            "- Add performance tests for very large n values"
        )
