# Test environment for parental control scripts
# Mimics OpenWrt's BusyBox-based environment using Alpine Linux
#
# Usage:
#   docker build -t my-router-test .
#   docker run --rm my-router-test
#   # Or for interactive testing:
#   docker run --rm -it my-router-test sh

FROM alpine:3.20

# Install BusyBox (OpenWrt uses BusyBox), bats-core for testing, and basic tools
RUN apk add --no-cache \
    busybox \
    busybox-extras \
    bash \
    bats \
    coreutils \
    grep \
    sed \
    curl

# Copy project files
COPY . /opt/my-router/
WORKDIR /opt/my-router

# Make scripts executable
RUN chmod +x scripts/*.sh web/cgi-bin/ticket

# Create mock binaries for OpenWrt-specific commands
RUN mkdir -p /usr/local/bin /tmp/mock-state

# Mock iptables - simulates FORWARD chain rule management
# -C: check if rule exists (exit 0=yes, 1=no)
# -I: insert rule (always succeeds)
# -D: delete rule (exit 0=deleted, 1=not found)
# -L: list rules
COPY docker/mock-iptables.sh /usr/local/bin/mock-iptables
RUN chmod +x /usr/local/bin/mock-iptables

# Mock uci - returns expected values for known queries
RUN printf '#!/bin/sh\nif echo "$@" | grep -q "get network.wan.device"; then\n  echo "eth1"\n  exit 0\nfi\nexit 0\n' > /usr/local/bin/mock-uci && chmod +x /usr/local/bin/mock-uci

# Mock ip - returns empty ARP table
RUN printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/mock-ip && chmod +x /usr/local/bin/mock-ip

# Mock logger - logs to file
RUN printf '#!/bin/sh\necho "$@" >> /tmp/mock-state/logger.log\n' > /usr/local/bin/mock-logger && chmod +x /usr/local/bin/mock-logger

# Symlink mocks to standard paths (overriding real binaries)
RUN ln -sf /usr/local/bin/mock-iptables /usr/bin/iptables && \
    ln -sf /usr/local/bin/mock-uci /usr/bin/uci && \
    ln -sf /usr/local/bin/mock-logger /usr/bin/logger

# Default: run all tests
CMD ["bats", "test/"]