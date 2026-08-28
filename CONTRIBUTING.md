# Contributing to dove

Thanks for your interest in improving `dove`.

## AI contributions are welcome

This project is built with AI in the loop, and **AI-assisted and AI-authored
contributions are explicitly welcome.** How a change was written makes no
difference to how it's evaluated — the bar is the same for everyone:

- The change is correct and does what it claims.
- It's covered by tests where that makes sense.
- It doesn't weaken the security model (see below and
  [docs/designs/dove-v1.md](docs/designs/dove-v1.md)).
- You understand and stand behind what you're submitting. If an AI wrote it,
  you're still the one vouching for it — review it as if you'd written it by
  hand.

You don't need to disclose that AI was involved. Please **don't** open
low-effort, unreviewed, machine-generated PRs in bulk — that wastes maintainer
time regardless of who or what authored them.

## Security-sensitive by nature

dove is a cryptographic tool. Changes to the encryption/chunking scheme, key
handling, the URL-fragment boundary, the access-policy gate, provisioned IAM, or
the install/trust chain deserve **extra care and a clear explanation in the PR**
of why they're safe. When in doubt, open an issue first. Never report a
vulnerability in a public PR or issue — see [SECURITY.md](SECURITY.md).

## Ground rules

- **Never commit secrets.** No credentials, tokens, private keys, or real
  `config.toml` / `secrets.toml`. The `.gitignore` guards the common cases, but
  check your diff.
- **Keep it generic.** No personal hostnames, account IDs, bucket names, or
  domains in source — those belong in config.
- **Tests:** add or update tests for behavior changes; make sure the suite
  passes.

## Before you open a PR

The CI gate mirrors what you should run locally:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check         # supply-chain: licenses + advisories
```

## Getting started

1. Read [docs/designs/dove-v1.md](docs/designs/dove-v1.md) for the architecture,
   the encryption design, and the threat model.
2. Open an issue to discuss anything non-trivial before you build it.
3. Fork, branch, and open a PR with a clear description of the change and how you
   verified it.

By contributing, you agree that your contributions are licensed under the
project's [Apache-2.0](LICENSE) license.
