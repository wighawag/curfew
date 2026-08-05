#!/bin/sh
# Mock nft (nftables) for testing
# Simulates a table with a MAC address set using a simple state file

STATE_FILE="/tmp/mock-state/nft_state"
LOG_FILE="/tmp/mock-state/nft.log"

mkdir -p /tmp/mock-state
touch "$STATE_FILE" "$LOG_FILE"

# Log the call
echo "$@" >> "$LOG_FILE"

# Parse the nft command
# We handle: add table, add chain, add set, add rule, add element, delete element, get element, list set, list table, list tables

args="$*"

# list tables - always report our table exists
if echo "$args" | grep -q "list tables"; then
    echo "table inet parental_control"
    exit 0
fi

# list table - report table exists
if echo "$args" | grep -q "list table"; then
    exit 0
fi

# add table - succeed
if echo "$args" | grep -q "add table"; then
    exit 0
fi

# add chain - succeed
if echo "$args" | grep -q "add chain"; then
    exit 0
fi

# add set - succeed
if echo "$args" | grep -q "add set"; then
    exit 0
fi

# add rule - succeed
if echo "$args" | grep -q "add rule"; then
    exit 0
fi

# add element - add MAC to the set state
if echo "$args" | grep -q "add element"; then
    mac=$(echo "$args" | sed -n 's/.*{\s*\([0-9a-fA-F:]*\)\s*}.*/\1/p')
    if [ -n "$mac" ]; then
        # Don't add duplicates
        grep -q "^$mac$" "$STATE_FILE" 2>/dev/null || echo "$mac" >> "$STATE_FILE"
    fi
    exit 0
fi

# delete element - remove MAC from the set state
if echo "$args" | grep -q "delete element"; then
    mac=$(echo "$args" | sed -n 's/.*{\s*\([0-9a-fA-F:]*\)\s*}.*/\1/p')
    if [ -n "$mac" ]; then
        # Remove the MAC (may not exist - that's ok)
        grep -v "^$mac$" "$STATE_FILE" > "$STATE_FILE.tmp" 2>/dev/null
        mv "$STATE_FILE.tmp" "$STATE_FILE" 2>/dev/null || true
    fi
    exit 0
fi

# get element - check if MAC is in the set
if echo "$args" | grep -q "get element"; then
    mac=$(echo "$args" | sed -n 's/.*{\s*\([0-9a-fA-F:]*\)\s*}.*/\1/p')
    if grep -q "^$mac$" "$STATE_FILE" 2>/dev/null; then
        echo "ether saddr $mac"
        exit 0
    else
        exit 1
    fi
fi

# list set - output the set contents
if echo "$args" | grep -q "list set"; then
    while read -r mac; do
        [ -n "$mac" ] && echo "    $mac"
    done < "$STATE_FILE"
    exit 0
fi

# Unknown command, succeed silently
exit 0