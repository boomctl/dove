# Releasing dove

dove releases itself. The GitHub mirror pushes `--follow-tags`, so an annotated
release tag pushed *through git-ark* lands on the mirror repo and triggers the
release workflow — no `workflow_dispatch`, no manual upload.

## Steps

1. **Bump the version** in `Cargo.toml`, run a build so `Cargo.lock` updates, and
   add a `CHANGELOG.md` entry for the new version.

2. **Commit** the bump (this commit is what the tag will point at).

3. **Tag it, annotated:**

   ```sh
   git tag -a vX.Y.Z -m "dove X.Y.Z — <summary>"
   ```

4. **Push the branch and the tag in ONE push:**

   ```sh
   git push git-ark:dove main vX.Y.Z
   ```

   The mirror only runs when a **branch** ref is in the push, and `--follow-tags`
   only carries tags alongside a branch push. If you push `main` first and the
   tag second, the tag never reaches the release repo. Always push them together,
   and make sure this push *advances* `main`.

5. **Watch the release build:**

   ```sh
   gh run list -R boomctl/dove --workflow Release --limit 1
   ```

   It builds the five-platform matrix and attaches the binaries + `SHA256SUMS`,
   each signed with Sigstore.

## After the release

- **Publish the tap files** — one command, never a hand-pasted checksum:

  ```sh
  scripts/render-tap-files.sh X.Y.Z
  ```

  It fetches the release's `SHA256SUMS`, rewrites `Formula/dove.rb` (Homebrew) and
  `bucket/dove.json` (Scoop) in the sibling tap repos (`../homebrew-tap`,
  `../scoop-bucket`), then commits and pushes each through the git-ark vault,
  which mirrors both to GitHub. Add `--dry-run` to write the files and print the
  push commands without pushing. The tap files are generated — regenerate for a
  new release rather than editing checksums in place.

  This is the shared `boomctl` tap/bucket, so `brew install boomctl/tap/dove` and
  `scoop install dove` work the moment the push lands.

## Publishing to crates.io

The binary release above (GitHub Releases + Homebrew/Scoop taps) is independent
of crates.io and doesn't require these steps. Do this only when publishing the
library or making `cargo install dove-cli` work.

`dove-cli` (this repo) depends on `dove-core` (`/Users/phil/Code/dove-core`,
its own repo). While the two are co-developed, that's a `path` dependency —
`cargo publish` refuses to publish a crate whose dependency has no version
requirement, and crates.io won't accept a path in a published `Cargo.toml` at
all. `dove-cli`'s `Cargo.toml` therefore carries **both**:

```toml
dove-core = { path = "../dove-core", version = "0.1.0" }
```

`cargo build` resolves the `path` locally; `cargo publish` strips the `path`
key and ships only the `version` requirement, provided that requirement is
satisfied by a version of `dove-core` that's actually on crates.io. Publish
order matters:

1. **Publish `dove-core` first**, on its own version line (`cargo publish` from
   `../dove-core`).
2. **Bump the version requirement** in `dove-cli`'s `Cargo.toml` if `dove-core`
   crossed a semver boundary the existing requirement doesn't cover (a patch
   release under the same `0.y` line usually needs no change; a `0.y` minor
   bump does, per Cargo's `0.y.z` semver rules).
3. **Publish `dove-cli`** (`cargo publish` from this repo). Cargo will fail
   loudly at publish time if the `dove-core` version on crates.io doesn't
   satisfy the requirement — that's the signal to go back to step 2.

`cargo deny check` (`bans.wildcards = "deny"`) enforces that the dependency
always carries a version requirement, not just a bare path, so this ordering
constraint can't silently regress.
