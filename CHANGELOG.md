# Changelog

All notable changes to `dove` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-08-29

Request files from other people, and a library split.

### Added — request a file
- `dove request "<what you need>" [--from --message --pin --expires --uploads]`
  mints a PIN-gated link you send to someone else. They open it, see who's
  asking and why, pick a file, and it is **encrypted on their device** before a
  single byte is uploaded — the gate never sees the key, the filename, or the
  content. Only you can decrypt what arrives. It is `share` run backwards.
- `dove requests` lists your open requests and their live state
  (waiting / received / failed with a reason); `dove requests get <id>`
  downloads the upload and decrypts it under its real filename.

### Changed
- The CLI is now a thin shim over the new [`dove-core`](https://crates.io/crates/dove-core)
  library, which holds the crypto, the S3/gate transfer, provisioning, and the
  backend registry. Behavior is unchanged; the split lets other front-ends
  (a desktop app) drive the same audited core. `cargo install dove-cli` still
  installs the `dove` binary.

## [0.1.0] - 2026-08-28

The first working version — both tiers, end to end.

### Added — simple tier
- `dove provision simple` stands up a private, all-public-access-blocked S3
  bucket in your own account, with a lifecycle rule that auto-deletes objects
  after a ceiling of days. It mints a **least-privilege IAM user** scoped to just
  that bucket, so share links are signed with a long-term scoped key (never your
  account credentials, and never capped by an SSO session's lifetime).
- `dove share <file> [--expires 3d]` uploads and prints a presigned link;
  directories are zipped first. `--encrypt` encrypts client-side even on the
  simple tier, with the key in the URL `#fragment`.

### Added — full tier
- `dove provision full` adds the access-policy **gate**: a DynamoDB table (TTL on
  expiry), a Python gate Lambda, an API Gateway HTTP API, and a CloudFront
  distribution — reachable via `lambda:InvokeFunction` so it works even where
  public Function URLs are disallowed.
- End-to-end encryption by default: chunked **AES-256-GCM**, the key only ever in
  the link fragment. The gate holds ciphertext and enforces policy; it is
  structurally unable to read a byte.
- Download policy: `--downloads N` (atomically decremented at the gate) and
  `--expires` enforced server-side, not just by the presign window.
- `--pin` PIN-locks a share: verified at the gate (rate-limited, lockout after 5
  wrong guesses) **and** folded into the decryption key. `--from` / `--message`
  ride an encrypted metadata blob the server can't read — shown to the recipient
  as a trust signal before they enter the PIN.
- **Unforgeable share ids**: `hex(nonce ‖ HMAC-SHA256(secret, nonce))`, verified
  at the gate before any DynamoDB/S3 touch — a forged or random id is rejected
  for the cost of a hash.
- A cached browser **decryptor page** served from the edge (one CloudFront cache
  entry for every share via a rewrite function, so page loads never invoke the
  Lambda), plus a branded link-preview card.
- `dove get <url> [--pin]` fetches and decrypts from the CLI. `dove domain add`
  puts your own subdomain (ACM + CloudFront) in front of the gate.

### Added — operating the gate
- **Cost circuit-breaker**, on by default: a CloudWatch alarm on gate invocation
  volume trips an SNS topic that fires a kill-switch Lambda, setting the gate's
  reserved concurrency to 0 before a flood can run up a bill.
- An API Gateway stage throttle (the first, free line of defense) and
  `dove gate disable | enable | status` — the manual panic switch.
- The gate's HMAC secret lives in **SSM as a SecureString** (encrypted, not
  readable from the function config); the Lambda reads it at cold start.

### Added — housekeeping
- `dove ls` / `dove revoke <id>` / `dove status`, and a local ledger mapping
  share ids to filenames for `ls`.
- OSS hygiene: Apache-2.0 license, `NOTICE`, contributing guide, code of conduct,
  security policy, CI (fmt / clippy / test / `cargo-deny` across Linux, macOS,
  Windows), a release workflow with Sigstore keyless signing, Dependabot, and
  issue/PR templates.
- [`docs/designs/dove-v1.md`](docs/designs/dove-v1.md) — the full v1 design:
  architecture, encryption, and threat model.

### Added — distribution
- Prebuilt release binaries for macOS, Linux, and Windows — built by the
  tag-triggered workflow, each checksummed and Sigstore-signed.
- **Homebrew** (`brew install boomctl/tap/dove`) and **Scoop**
  (`scoop install dove`): `scripts/render-tap-files.sh` renders both manifests
  from the release checksums and publishes them to the shared `boomctl`
  tap/bucket through the git-ark vault, in one command. See
  [`docs/RELEASING.md`](docs/RELEASING.md).
