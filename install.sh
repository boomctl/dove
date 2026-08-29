#!/bin/sh
# dove installer for macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/boomctl/dove/main/install.sh | sh
#
# Downloads the latest release binary for your OS/arch, verifies its SHA-256
# against the release's SHA256SUMS, and installs it.
#
# Env:
#   DOVE_BINDIR    install directory (default: $HOME/.local/bin)
#   DOVE_VERSION   release to install: "latest" (default), "v0.1.0", or "0.1.0"
#
# The whole script is wrapped in main() and only invoked on the last line, so a
# truncated download (the classic `curl | sh` hazard) never runs a half-script.
set -eu

say() { printf '%s\n' "$*"; }
die() { printf 'dove install: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

dl() { # url dest
  if have curl; then curl -fsSL --proto '=https' "$1" -o "$2"
  elif have wget; then wget -qO "$2" "$1"
  else die "need curl or wget"; fi
}

main() {
  REPO="boomctl/dove"
  BINDIR="${DOVE_BINDIR:-$HOME/.local/bin}"
  VERSION="${DOVE_VERSION:-latest}"
  # Accept "0.1.0" as well as "v0.1.0" — release tags are v-prefixed.
  case "$VERSION" in
    latest | v*) ;;
    *) VERSION="v$VERSION" ;;
  esac

  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Linux) plat="unknown-linux-musl" ;;
    Darwin) plat="apple-darwin" ;;
    *) die "unsupported OS '$os' — on Windows use install.ps1" ;;
  esac
  case "$arch" in
    x86_64 | amd64) cpu="x86_64" ;;
    aarch64 | arm64) cpu="aarch64" ;;
    *) die "unsupported architecture '$arch'" ;;
  esac
  asset="dove-${cpu}-${plat}"

  if [ "$VERSION" = "latest" ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$VERSION"
  fi

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT INT TERM

  say "downloading $asset ($VERSION)…"
  dl "$base/$asset" "$tmp/dove" || die "download failed — is there a release for $asset?"
  dl "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not fetch SHA256SUMS"

  want=$(grep " ${asset}\$" "$tmp/SHA256SUMS" | awk '{print $1}')
  [ -n "$want" ] || die "no checksum for $asset in SHA256SUMS"
  if have sha256sum; then got=$(sha256sum "$tmp/dove" | awk '{print $1}')
  elif have shasum; then got=$(shasum -a 256 "$tmp/dove" | awk '{print $1}')
  else die "need sha256sum or shasum to verify the download"; fi
  [ "$want" = "$got" ] || die "checksum mismatch (expected $want, got $got)"

  mkdir -p "$BINDIR"
  chmod 755 "$tmp/dove"
  mv "$tmp/dove" "$BINDIR/dove"
  say "installed dove → $BINDIR/dove"

  case ":${PATH}:" in
    *":$BINDIR:"*) ;;
    *) say "note: $BINDIR is not on your PATH — add it, e.g.  export PATH=\"$BINDIR:\$PATH\"" ;;
  esac
  "$BINDIR/dove" --version 2>/dev/null || true
}

main "$@"
