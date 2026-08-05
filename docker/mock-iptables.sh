#!/bin/sh
# Mock iptables for testing the iptables fallback backend
# Simulates FORWARD chain rule management with a state file

STATE_FILE="/tmp/mock-state/iptables_state"
LOG_FILE="/tmp/mock-state/iptables.log"

mkdir -p /tmp/mock-state
touch "$STATE_FILE" "$LOG_FILE"

echo "$@" >> "$LOG_FILE"

if echo "$@" | grep -q -- "-C FORWARD"; then
    mac=$(echo "$@" | sed -n 's/.*--mac-source \([0-9a-fA-F:]*\).*/\1/p')
    if grep -q "^DROP $mac$" "$STATE_FILE" 2>/dev/null; then
        exit 0
    else
        exit 1
    fi
elif echo "$@" | grep -q -- "-I FORWARD"; then
    mac=$(echo "$@" | sed -n 's/.*--mac-source \([0-9a-fA-F:]*\).*/\1/p')
    if [ -n "$mac" ]; then
        echo "DROP $mac" >> "$STATE_FILE"
    fi
    exit 0
elif echo "$@" | grep -q -- "-D FORWARD"; then
    mac=$(echo "$@" | sed -n 's/.*--mac-source \([0-9a-fA-F:]*\).*/\1/p')
    line=$(grep -n "^DROP $mac$" "$STATE_FILE" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -n "$line" ]; then
        sed -i "${line}d" "$STATE_FILE"
        exit 0
    else
        exit 1
    fi
elif echo "$@" | grep -q -- "-L FORWARD"; then
    cat "$STATE_FILE"
    exit 0
fi
exit 0