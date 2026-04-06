#!/usr/bin/env bash
# Record asciinema demo with typewriter-style line-by-line output
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CAST_OUT="$SCRIPT_DIR/../../demo_multi_agent.cast"

# Capture main.py output
OUTPUT=$(python3 "$SCRIPT_DIR/main.py" 2>&1)

# Write a temp script that outputs line by line with delay
TMPSCRIPT=$(mktemp /tmp/agdemo_XXXX.sh)
cat > "$TMPSCRIPT" << 'INNEREOF'
#!/usr/bin/env bash
IFS=''
while read -r line; do
    echo "$line"
    sleep 0.08
done < /tmp/agdemo_output.txt
sleep 2
INNEREOF
chmod +x "$TMPSCRIPT"

echo "$OUTPUT" > /tmp/agdemo_output.txt

asciinema rec "$CAST_OUT" \
  --title "AgentGate Multi-Agent Security Demo" \
  --cols 100 \
  --rows 45 \
  --command "bash $TMPSCRIPT" \
  --overwrite

rm -f "$TMPSCRIPT" /tmp/agdemo_output.txt
echo "Recording saved: $CAST_OUT"
