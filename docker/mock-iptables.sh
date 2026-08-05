#!/bin/sh
# Mock iptables for testing - simulates FORWARD chain rule management
# Manages a simple state file at /tmp/mock-state/iptables_state

STATE_FILE="/tmp/mock-state/iptables_state"
LOG_FILE="/tmp/mock-state/iptables.log"

mkdir -p /tmp/mock-state
touch "$STATE_FILE" "$LOG_FILE"

# Log the call
echo "$@" >> "$LOG_FILE"

if echo "$@" | grep -q -- "-C FORWARD"; then
    # Check if rule exists
    mac=$(echo "$@" | sed -n 's/.*--mac-source \([0-9a-fA-F:]*\).*/\1/p')
    if grep -q "^DROP $mac$" "$STATE_FILE" 2>/dev/null; then
        exit 0
    else
        exit 1
    fi

elif echo "$@" | grep -q -- "-I FORWARD"; then
    # Insert rule
    mac=$(echo "$@" | sed -n 's/.*--mac-source \([0-9a-fA-F:]*\).*/\1/p')
    if [ -n "$mac" ]; then
        echo "DROP $mac" >> "$STATE_FILE"
    fi
    exit 0

elif echo "$@" | grep -q -- "-D FORWARD"; then
    # Delete rule - return 1 if not found (so while loops terminate)
    mac=$(echo "$@" | sed -n 's/.*--mac-source \([0-9a-fA-F:]*\).*/\1/p')
    line=$(grep -n "^DROP $mac$" "$STATE_FILE" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -n "$line" ]; then
        sed -i "${line}d" "$STATE_FILE"
        exit 0
    else
        exit 1
    fi

elif echo "$@" | grep -q -- "-L FORWARD"; then
    # List rules
    cat "$STATE_FILE"
    exit 0
fi

# Unknown command, succeed silently
exit 0