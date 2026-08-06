# Test environment for the parental control scripts.
#
# Real OpenWrt userland, matching the router's release line, with NO mocked
# system tools: uci, logger, nft, uhttpd and busybox behaviour are the real
# things. See docs/adr/0005-test-environment-is-a-real-openwrt-image.md for
# why, and work/notes/findings/rootless-container-netns-nftables-requirements.md
# for the measurements behind each step below.
#
# Usage:
#   podman compose -f docker/docker-compose.yml run --build --rm test
#   podman compose -f docker/docker-compose.yml run --build --rm shell

FROM openwrt/rootfs:x86-64-25.12.4

# OpenWrt package names differ from Alpine's, and busybox is missing pieces
# the test tooling needs. Each of these has a measured failure behind it:
#   bash             bats is a bash program; OpenWrt ships only ash
#   ip-full          busybox `ip` has no `link add` and no `netns`
#   coreutils-nl     bats calls `nl`; without it it runs 0 of N tests silently
#   coreutils-cksum  test/setup-adguard.bats derives filter IDs with `cksum`
#   nsenter          `ip netns exec` cannot work here (it remounts /sys)
RUN apk add --no-cache bash ip-full coreutils-nl coreutils-cksum nsenter

# bats is not packaged for OpenWrt at all, so fetch it pinned and verified.
# The digest is a literal on purpose: an upstream change must not be able to
# alter the gate without a commit in this repo. Note bats' own install.sh
# cannot be used (OpenWrt has no coreutils `install`), and busybox tar has no
# --strip-components, so extract as-is and symlink the versioned path.
ARG BATS_VERSION=1.11.0
ARG BATS_SHA256=aeff09fdc8b0c88b3087c99de00cf549356d7a2f6a69e3fcec5e0e861d2f9063
RUN wget -q -O /tmp/bats.tar.gz \
      "https://github.com/bats-core/bats-core/archive/refs/tags/v${BATS_VERSION}.tar.gz" \
 && echo "${BATS_SHA256}  /tmp/bats.tar.gz" | sha256sum -c - \
 && mkdir -p /opt \
 && tar -xzf /tmp/bats.tar.gz -C /opt \
 && ln -sf "/opt/bats-core-${BATS_VERSION}/bin/bats" /usr/bin/bats \
 && rm -f /tmp/bats.tar.gz

# /var is a symlink to /tmp on OpenWrt and /var/run is created at boot by
# procd, which never runs in a container. Without this `ip netns add` fails.
RUN mkdir -p /var/run

COPY . /opt/my-router/
WORKDIR /opt/my-router

RUN chmod +x scripts/*.sh web/cgi-bin/ticket

# State directory used by the test helpers.
RUN mkdir -p /tmp/mock-state

CMD ["bats", "test/"]
