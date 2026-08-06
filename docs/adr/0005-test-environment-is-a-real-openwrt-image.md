# The test environment is a real OpenWrt image, not a lookalike

**Status:** accepted

Tests are to run on `openwrt/rootfs` from the router's release line, with no mocked system tools, rather than on Alpine with shims for `uci` and `logger`. Reasoning about the target from a lookalike distribution and from upstream source trees produced confident, wrong answers repeatedly during the investigation that led here: a conclusion that `nft -j` was unavailable on the router (drawn from the nftables Makefile's default variant, and false because firewall4 depends on the JSON build), and an assumption that the test tooling would install cleanly (false in several distinct ways, each found only by running it: the package names differ, bats is not packaged at all, two separate coreutils packages are needed, and a directory the tooling depends on does not exist). Each was disproved by a real image in seconds. The mocks compounded it by making OpenWrt-specific behaviour unobservable rather than merely unknown.

## Considered Options

- **Real `openwrt/rootfs` image (chosen).** `uci`, `logger`, `nft`, busybox applet behaviour and `uhttpd` are the real things. Costs a handful of setup steps that Alpine did not need.
- **Alpine with mocks (rejected; the status quo at the time).** Faster and simpler, and every mock is a place where the test environment can silently disagree with the router. The `uci` shim in particular was a universal no-op, so any script path touching `uci` was untested rather than tested.

(Those two were the real alternatives. No third option is listed, because none was genuinely weighed.)

## Consequences

- The x86-64 image differs in architecture from the aarch64 router, and its patch version trails it slightly (the router runs 25.12.5, the image tag used is 25.12.4). Same release line, and irrelevant for nftables semantics, shell behaviour and HTTP, which is everything currently tested; it would matter for a compiled binary, which is an argument for testing any future Go tool in this same image. An ADR whose thesis is "do not reason from a lookalike" should be precise about the remaining gap rather than claim an exact match.
- Setup is fiddlier and the details are non-obvious, so they are recorded in `work/notes/findings/rootless-container-netns-nftables-requirements.md` rather than rediscovered: `iproute2` is `ip-full`, bats is not packaged at all and must be fetched and pinned, `nl` and `cksum` come from separate coreutils packages, `/var/run` does not exist without procd, and `ip netns exec` does not work.
- Deleting the mocks costs the iptables backend its only test coverage. Accepted knowingly, because that backend is dead code scheduled for removal. Note this is a CHOICE and not a consequence of the image: the iptables mock is plain POSIX shell and would run perfectly well on OpenWrt. It goes because keeping a mock alive for a backend nobody runs is not worth the weight, and the honest framing matters because a "forced by the swap" story would hide a decision someone might want to revisit.
- Any future claim about how the router behaves should be settled by running it in this image rather than by reading upstream source.
- **State at the time of writing:** the container is still Alpine with the shims in place. The swap ships from `openwrt-test-image`. Read this ADR as the ratified direction, not as a description of the current container.
