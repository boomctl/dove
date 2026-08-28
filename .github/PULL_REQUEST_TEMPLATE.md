<!-- Thanks for contributing to dove! -->

## What this changes

<!-- A clear description of the change and why. -->

## How I verified it

<!-- Tests added/updated, manual steps, output. -->

## Checklist

- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` pass
- [ ] `cargo deny check` passes (no new advisories / disallowed licenses)
- [ ] No secrets, credentials, or personal hostnames/domains in the diff
- [ ] If this touches the security model (encryption, key handling, the URL-fragment boundary, the access-policy gate, IAM, or the install/trust chain), I explained why it's safe

<!-- Security vulnerability? Do NOT file it here — see SECURITY.md. -->
