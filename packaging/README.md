# Packaging

How dove ships to Homebrew and Scoop. End users don't need this — see the root
README's **Install** section. This is the maintainer runbook.

## How a release flows

`.github/workflows/release.yml` runs on a `v*` tag (or a manual
`workflow_dispatch`):

1. **build** — cross-compiles five targets and packages each as an archive
   holding a single `dove` / `dove.exe`:
   `dove-<target>.tar.gz` (macOS arm64/x64, Linux arm64/x64 musl) and
   `dove-x86_64-pc-windows-msvc.zip`.
2. **sign + publish** — writes `SHA256SUMS`, signs every archive and the manifest
   with Sigstore (keyless cosign), and creates the GitHub Release.
3. **Homebrew + Scoop** — `render.sh` turns `SHA256SUMS` into a formula and a
   manifest, and pushes each to its repo.

`render.sh <version> <SHA256SUMS> <out-dir>` is a plain script — run it locally
against a downloaded `SHA256SUMS` to preview a formula, or to hand-publish one.

## One-time setup (before the first release)

1. **Create two repos** in the `boomctl` org:
   - `boomctl/homebrew-tap` — the formula lands at `Formula/dove.rb`, so
     `brew install boomctl/tap/dove` works.
   - `boomctl/scoop-bucket` — the manifest lands at `bucket/dove.json`, so
     `scoop bucket add boomctl https://github.com/boomctl/scoop-bucket` then
     `scoop install dove` works.
2. **Add a `PACKAGES_TOKEN` secret** to the `boomctl/dove` repo — a
   fine-grained PAT (or GitHub App token) with **contents: write** on those two
   repos, nothing else. Without it the publish step is a logged no-op, so the
   release still succeeds; the manifests just aren't updated.
3. **Tag a release**: `git tag v0.1.0 && git push origin v0.1.0`.

The formula and manifest are regenerated from checksums on every tag, so
subsequent releases need no manual manifest edits.
