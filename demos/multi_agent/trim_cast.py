#!/usr/bin/env python3
"""Trim a .cast file: remove events before the demo output starts and after it ends."""

import json
import sys
from pathlib import Path


def trim(input_path: str, output_path: str):
    lines = Path(input_path).read_text().strip().split("\n")
    header = json.loads(lines[0])

    events = []
    for line in lines[1:]:
        try:
            ts, etype, data = json.loads(line)
            events.append((ts, etype, data))
        except (json.JSONDecodeError, ValueError):
            continue

    # Find first event containing the banner
    start_idx = None
    for i, (ts, etype, data) in enumerate(events):
        if "AgentGate Multi-Agent Security Demo" in data and "===" in data:
            start_idx = i
            break

    # Find last meaningful event (before shell prompt after demo)
    end_idx = len(events) - 1
    for i in range(len(events) - 1, -1, -1):
        ts, etype, data = events[i]
        if "uvicorn gate_proxy" in data or "Demo Complete" in data:
            end_idx = i
            break

    if start_idx is None:
        print("Could not find demo start")
        sys.exit(1)

    trimmed = events[start_idx:end_idx + 1]
    base_ts = trimmed[0][0]

    # Write output
    out_lines = [json.dumps(header)]
    for ts, etype, data in trimmed:
        out_lines.append(json.dumps([round(ts - base_ts, 6), etype, data]))

    Path(output_path).write_text("\n".join(out_lines) + "\n")
    print(f"Trimmed: {len(events)} -> {len(trimmed)} events")
    print(f"Duration: {trimmed[-1][0] - base_ts:.1f}s")
    print(f"Saved: {output_path}")


if __name__ == "__main__":
    inp = sys.argv[1] if len(sys.argv) >= 2 else "/tmp/multi_agent.cast"
    out = sys.argv[2] if len(sys.argv) >= 3 else "/tmp/multi_agent_trimmed.cast"
    trim(inp, out)
