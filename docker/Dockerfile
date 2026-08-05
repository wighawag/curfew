# Test environment for parental control scripts
# Uses Alpine Linux with REAL nftables (same nft binary as OpenWrt)
#
# We can't run the mediatek ARM firmware on x86, but nftables behaves
# identically regardless of distro. We use real nft + mock uci only.
#
# Usage:
#   docker compose -f docker/docker-compose.yml run --rm test
#   docker compose -f docker/docker-compose.yml run --rm shell

FROM alpine:3.20

# Install:
# - BusyBox (OpenWrt uses BusyBox)
# - bats-core for testing
# - nftables (REAL nft binary, same as OpenWrt uses)
# - bind-tools (nslookup for website-blocking.sh DNS resolution)
# - coreutils, grep, sed for script dependencies
RUN apk add --no-cache \
    busybox \
    busybox-extras \
    bash \
    bats \
    nftables \
    bind-tools \
    coreutils \
    grep \
    sed \
    curl

# nft is installed at /usr/sbin/nft, create symlink to /usr/bin for PATH
RUN ln -sf /usr/sbin/nft /usr/bin/nft

# Copy project files
COPY . /opt/my-router/
WORKDIR /opt/my-router

# Make scripts executable
RUN chmod +x scripts/*.sh web/cgi-bin/ticket

# Create state directory
RUN mkdir -p /tmp/mock-state

# Mock uci - OpenWrt-specific, not available in Alpine
RUN printf '#!/bin/sh\nif echo "$@" | grep -q "get network.wan.device"; then\n  echo "eth1"\n  exit 0\nfi\nexit 0\n' > /usr/local/bin/mock-uci && chmod +x /usr/local/bin/mock-uci
RUN ln -sf /usr/local/bin/mock-uci /usr/bin/uci

# Mock logger - logs to file instead of syslog
RUN printf '#!/bin/sh\necho "$@" >> /tmp/mock-state/logger.log\n' > /usr/local/bin/mock-logger && chmod +x /usr/local/bin/mock-logger
RUN ln -sf /usr/local/bin/mock-logger /usr/bin/logger

# Mock iptables for iptables fallback tests (real nft is used for nft tests)
COPY docker/mock-iptables.sh /usr/local/bin/mock-iptables
RUN chmod +x /usr/local/bin/mock-iptables

# Default: run all tests
CMD ["bats", "test/"]