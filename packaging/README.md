# Packaging

How dove ships to Homebrew and Scoop. End users don't need this — see the root
README's **Install** section. This is the maintainer runbook.

## How a release flows

`.github/workflows/release.yml` runs on a `v*` tag (or a manual
`workflow_dispatch`):

1. **build** — cross-compiles five targets and stages the bare binary for each:
   `dove-<target>` (macOS arm64/x64, Linux arm64/x64 musl) and
   `dove-x86_64-pc-windows-msvc.exe`. Homebrew installs a bare binary directly;
   Scoop fetches the `.exe` with a `#/dove.exe` rename fragment — the same shape
   the sibling `git-ark` formula uses, so the shared tap/bucket stay uniform.
2. **sign + publish** — writes `SHA256SUMS`, signs every binary and the manifest
   with Sigstore (keyless cosign), and creates the GitHub Release.
3. **Homebrew + Scoop** — `render.sh` turns `SHA256SUMS` into a formula and a
   manifest, and pushes each to its repo.

`render.sh <version> <SHA256SUMS> <out-dir>` is a plain script — run it locally
against a downloaded `SHA256SUMS` to preview a formula, or to hand-publish one.

## The shared tap + bucket

Both already exist and hold the whole `boomctl` family (git-ark today, dove
alongside):

- **`boomctl/homebrew-tap`** — dove's formula lands at `Formula/dove.rb`, so
  `brew install boomctl/tap/dove` works.
- **`boomctl/scoop-bucket`** — dove's manifest lands at `bucket/dove.json`, so
  `scoop bucket add boomctl https://github.com/boomctl/scoop-bucket` then
  `scoop install dove` works.

## Going live

1. **Add a `PACKAGES_TOKEN` secret** to the `boomctl/dove` repo — a fine-grained
   PAT (or GitHub App token) with **contents: write** on those two repos, nothing
   else. Without it the publish step is a logged no-op, so a release still
   succeeds; the manifests just aren't updated.
2. **Tag a release**: `git tag v0.1.0 && git push origin v0.1.0`.

The formula and manifest are regenerated from checksums on every tag, so
subsequent releases need no manual manifest edits.
