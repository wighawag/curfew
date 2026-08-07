#!/bin/sh
# my-router installer: download the latest release and put the LAPTOP binary
# on your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/wighawag/my-router/main/install.sh | sh
#
# Options (environment variables):
#   MYROUTER_VERSION  version tag to install (default: latest, e.g. v0.1.0)
#   PREFIX            install dir (default: $HOME/.local/bin)
#
# This installs `my-router`, which runs on your LAPTOP and only does
# install/push/pull over ssh. It deliberately does NOT install
# my-router-daemon: that one belongs on the router and is put there by
# `my-router install`, which fetches the right architecture for your device.
# Keeping the enforcement binary off your laptop is the point of the split.
set -eu

REPO="wighawag/my-router"
BIN="my-router"

info() { printf '%s\n' "my-router-install: $*" >&2; }
err() {
	printf '%s\n' "my-router-install: error: $*" >&2
	exit 1
}

os="$(uname -s)"
case "$os" in
Linux) goos=linux ;;
Darwin) goos=darwin ;;
*) err "unsupported OS $os (Linux and macOS are supported)" ;;
esac

arch="$(uname -m)"
case "$arch" in
x86_64 | amd64) goarch=amd64 ;;
aarch64 | arm64) goarch=arm64 ;;
*) err "unsupported architecture $arch" ;;
esac

version="${MYROUTER_VERSION:-}"
if [ -z "$version" ]; then
	version="$(
		wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null ||
			curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest"
	)" || err "cannot reach the GitHub API to find the latest release"
	version="$(printf '%s' "$version" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
	[ -n "$version" ] || err "could not determine the latest version; set MYROUTER_VERSION"
fi

archive="my-router_${goos}_${goarch}.tar.gz"
url="https://github.com/${REPO}/releases/download/${version}/${archive}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "downloading $version for ${goos}/${goarch}"
if command -v curl >/dev/null 2>&1; then
	curl -fsSL -o "$tmp/$archive" "$url" || err "download failed: $url"
	curl -fsSL -o "$tmp/checksums.txt" "https://github.com/${REPO}/releases/download/${version}/checksums.txt" ||
		err "could not download checksums"
else
	wget -qO "$tmp/$archive" "$url" || err "download failed: $url"
	wget -qO "$tmp/checksums.txt" "https://github.com/${REPO}/releases/download/${version}/checksums.txt" ||
		err "could not download checksums"
fi

# Verify before unpacking, not after. An unverified archive that has already
# been extracted has already had its chance.
if command -v sha256sum >/dev/null 2>&1; then
	(cd "$tmp" && grep " ${archive}\$" checksums.txt | sha256sum -c -) >/dev/null 2>&1 ||
		err "checksum mismatch for $archive"
elif command -v shasum >/dev/null 2>&1; then
	want="$(grep " ${archive}\$" "$tmp/checksums.txt" | awk '{print $1}')"
	got="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
	[ "$want" = "$got" ] || err "checksum mismatch for $archive"
else
	err "no sha256sum or shasum available to verify the download"
fi

tar -xzf "$tmp/$archive" -C "$tmp"

prefix="${PREFIX:-$HOME/.local/bin}"
mkdir -p "$prefix"
mv "$tmp/$BIN" "$prefix/$BIN"
chmod +x "$prefix/$BIN"

info "installed $prefix/$BIN"
case ":$PATH:" in
*":$prefix:"*) ;;
*) info "note: $prefix is not on your PATH" ;;
esac
"$prefix/$BIN" version
