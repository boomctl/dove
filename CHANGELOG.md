# Changelog

All notable changes to `dove` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project scaffold and OSS hygiene: Apache-2.0 license, `NOTICE`, contributing
  guide, code of conduct, security policy, CI (fmt / clippy / test /
  `cargo-deny`), a release workflow with Sigstore keyless signing, Dependabot,
  and issue/PR templates.
- [`docs/designs/dove-v1.md`](docs/designs/dove-v1.md) — the v1 design, worked
  out in the open: two tiers (simple presigned vs. full end-to-end), chunked
  AES-256-GCM with the key in the URL fragment, an access-policy gate, a browser
  page that hands large files to a symmetric CLI, and the dove.sh trust anchor.

_No release yet — dove is being designed in the open before it's built._
