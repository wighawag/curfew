#!/usr/bin/env bats
# Tests for blocklists.sh (global content filtering)

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"

setup() {
    export BLOCKLISTS_CONFIG="${BATS_TMPDIR}/parental_blocklists"
    export BLOCKLIST_DIR="${BATS_TMPDIR}/dnsmasq-blocklists"
    export DNSMASQ_CONF="${BATS_TMPDIR}/blocklists.conf"
    export WGET="${BATS_TMPDIR}/mock-wget"
    export MOCK_LOG_DIR="/tmp/mock-state"

    # Create mock wget that generates fake dnsmasq-format content
    cat > "$WGET" << 'WGET'
#!/bin/sh
# Mock wget - generates fake dnsmasq blocklist content
# Parse the -O flag to get output file
outfile=""
url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -O) outfile="$2"; shift 2 ;;
        -q) shift ;;
        *) url="$1"; shift ;;
    esac
done

# Generate fake content based on URL
if echo "$url" | grep -q "gambling"; then
    echo "server=/casino.com/" > "$outfile"
    echo "server=/betting.com/" >> "$outfile"
    echo "server=/poker.com/" >> "$outfile"
elif echo "$url" | grep -q "porn"; then
    echo "server=/porn.com/" > "$outfile"
    echo "server=/xxx.com/" >> "$outfile"
elif echo "$url" | grep -q "malware"; then
    echo "server=/malware.com/" > "$outfile"
    echo "server=/virus.com/" >> "$outfile"
elif echo "$url" | grep -q "phishing"; then
    echo "server=/phish.com/" > "$outfile"
else
    echo "server=/blocked.com/" > "$outfile"
fi
exit 0
WGET
    chmod +x "$WGET"

    # Create test config
    cat > "$BLOCKLISTS_CONFIG" << 'EOF'
# Test blocklists
https://blocklistproject.github.io/Lists/dnsmasq-version/gambling-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/porn-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/malware-dnsmasq.txt
EOF

    mkdir -p "$BLOCKLIST_DIR" "$MOCK_LOG_DIR"
}

teardown() {
    rm -rf "$BLOCKLIST_DIR" 2>/dev/null || true
}

@test "update downloads all configured lists" {
    run sh "$SCRIPT_DIR/scripts/blocklists.sh" update
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "gambling"
    echo "$output" | grep -q "porn"
    echo "$output" | grep -q "malware"
}

@test "update creates blocklist files in blocklist dir" {
    sh "$SCRIPT_DIR/scripts/blocklists.sh" update
    [ -f "$BLOCKLIST_DIR/gambling-dnsmasq.txt" ]
    [ -f "$BLOCKLIST_DIR/porn-dnsmasq.txt" ]
    [ -f "$BLOCKLIST_DIR/malware-dnsmasq.txt" ]
}

@test "downloaded files contain dnsmasq format entries" {
    sh "$SCRIPT_DIR/scripts/blocklists.sh" update
    grep -q "server=/" "$BLOCKLIST_DIR/gambling-dnsmasq.txt"
}

@test "status shows loaded lists and domain counts" {
    sh "$SCRIPT_DIR/scripts/blocklists.sh" update
    run sh "$SCRIPT_DIR/scripts/blocklists.sh" status
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "gambling"
    echo "$output" | grep -q "domains"
}

@test "list shows configured URLs" {
    run sh "$SCRIPT_DIR/scripts/blocklists.sh" list
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "gambling"
    echo "$output" | grep -q "blocklistproject"
}

@test "add appends URL to config" {
    run sh "$SCRIPT_DIR/scripts/blocklists.sh" add "https://example.com/list.txt"
    [ "$status" -eq 0 ]
    grep -q "example.com" "$BLOCKLISTS_CONFIG"
}

@test "remove removes URL from config" {
    sh "$SCRIPT_DIR/scripts/blocklists.sh" add "https://example.com/list.txt"
    run sh "$SCRIPT_DIR/scripts/blocklists.sh" remove "https://example.com/list.txt"
    [ "$status" -eq 0 ]
    ! grep -q "example.com" "$BLOCKLISTS_CONFIG"
}

@test "add without URL fails" {
    run sh "$SCRIPT_DIR/scripts/blocklists.sh" add
    [ "$status" -ne 0 ]
}

@test "no command shows usage" {
    run sh "$SCRIPT_DIR/scripts/blocklists.sh"
    [ "$status" -eq 0 ]
    echo "$output" | grep -qi "usage"
}

@test "update skips comment lines" {
    echo "# this is a comment" >> "$BLOCKLISTS_CONFIG"
    echo "" >> "$BLOCKLISTS_CONFIG"
    run sh "$SCRIPT_DIR/scripts/blocklists.sh" update
    [ "$status" -eq 0 ]
}

@test "create default config when none exists" {
    rm -f "$BLOCKLISTS_CONFIG"
    sh "$SCRIPT_DIR/scripts/blocklists.sh" update
    [ -f "$BLOCKLISTS_CONFIG" ]
    grep -q "gambling" "$BLOCKLISTS_CONFIG"
    grep -q "porn" "$BLOCKLISTS_CONFIG"
    grep -q "malware" "$BLOCKLISTS_CONFIG"
}