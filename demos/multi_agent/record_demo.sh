#!/usr/bin/env bash
# Asciinema auto-recording script
# Usage: bash record_demo.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$SCRIPT_DIR/../../demo_multi_agent.cast"

echo "=== AgentGate Multi-Agent Demo Recording ==="
echo "Output: $OUTPUT"
echo ""

asciinema rec "$OUTPUT" \
  --title "AgentGate Multi-Agent Security Demo" \
  --cols 100 \
  --rows 40 \
  --command "python3 $SCRIPT_DIR/main.py" \
  --overwrite

echo ""
echo "Recording saved: $OUTPUT"
echo "Playback: asciinema play $OUTPUT"
