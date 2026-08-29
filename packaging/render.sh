#!/usr/bin/env bash
#
# Render the Homebrew formula and Scoop manifest for a dove release, filling in
# the version and the per-artifact SHA-256s from the release's SHA256SUMS file.
# The release workflow calls this after publishing; you can also run it locally
# against a downloaded SHA256SUMS to preview or hand-publish a formula.
#
#   packaging/render.sh <version> <SHA256SUMS path> <out dir>
#
# It writes <out>/homebrew/dove.rb and <out>/scoop/dove.json.
set -euo pipefail

version="${1:?usage: render.sh <version> <SHA256SUMS> <out-dir>}"
sums="${2:?usage: render.sh <version> <SHA256SUMS> <out-dir>}"
out="${3:?usage: render.sh <version> <SHA256SUMS> <out-dir>}"

repo="boomctl/dove"
base="https://github.com/${repo}/releases/download/v${version}"

# The checksum for one artifact, by exact filename, from a `sha256sum` manifest
# (`<hash>␠␠<name>` per line). Fails loudly if the artifact is missing.
sha() {
  local name="$1" line
  line=$(grep -E "  ${name}\$" "$sums") || {
    echo "render.sh: no checksum for '${name}' in ${sums}" >&2
    exit 1
  }
  printf '%s' "${line%% *}"
}

d_arm=$(sha "dove-aarch64-apple-darwin.tar.gz")
d_x64=$(sha "dove-x86_64-apple-darwin.tar.gz")
l_arm=$(sha "dove-aarch64-unknown-linux-musl.tar.gz")
l_x64=$(sha "dove-x86_64-unknown-linux-musl.tar.gz")
w_x64=$(sha "dove-x86_64-pc-windows-msvc.zip")

mkdir -p "${out}/homebrew" "${out}/scoop"

# ── Homebrew formula ─────────────────────────────────────────────────────────
# Binary formula: download the prebuilt archive for the running platform, install
# the single `dove` inside it. macOS (arm/intel) + Linux (arm/intel via musl).
cat > "${out}/homebrew/dove.rb" <<RB
class Dove < Formula
  desc "Send a file out of your own cloud — encrypted, expiring, one command"
  homepage "https://dove.sh"
  version "${version}"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "${base}/dove-aarch64-apple-darwin.tar.gz"
      sha256 "${d_arm}"
    else
      url "${base}/dove-x86_64-apple-darwin.tar.gz"
      sha256 "${d_x64}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "${base}/dove-aarch64-unknown-linux-musl.tar.gz"
      sha256 "${l_arm}"
    else
      url "${base}/dove-x86_64-unknown-linux-musl.tar.gz"
      sha256 "${l_x64}"
    end
  end

  def install
    bin.install "dove"
  end

  test do
    assert_match "dove", shell_output("#{bin}/dove --version")
  end
end
RB

# ── Scoop manifest ───────────────────────────────────────────────────────────
# Windows x64. \$version in the autoupdate url is a Scoop template variable (kept
# literal), so its excavator can also bump the manifest between our pushes.
cat > "${out}/scoop/dove.json" <<JSON
{
    "version": "${version}",
    "description": "Send a file out of your own cloud — encrypted, expiring, one command.",
    "homepage": "https://dove.sh",
    "license": "Apache-2.0",
    "architecture": {
        "64bit": {
            "url": "${base}/dove-x86_64-pc-windows-msvc.zip",
            "hash": "${w_x64}",
            "bin": "dove.exe"
        }
    },
    "checkver": "github",
    "autoupdate": {
        "architecture": {
            "64bit": {
                "url": "https://github.com/${repo}/releases/download/v\$version/dove-x86_64-pc-windows-msvc.zip"
            }
        }
    }
}
JSON

echo "render.sh: wrote ${out}/homebrew/dove.rb + ${out}/scoop/dove.json for v${version}"
