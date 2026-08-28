# Security Policy

`dove` encrypts files and hands out time- and count-limited access to them. Its
security properties are the product, so we take reports seriously and want to
make them easy to file.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through **GitHub's private vulnerability reporting** on this
repository (the *Security* tab → *Report a vulnerability*). If you can't use
that, note it in a minimal, non-public way and we'll arrange a private channel.

Please include, as best you can:

- what the issue is and the impact you think it has,
- steps or a proof-of-concept to reproduce it,
- the version / commit affected.

We aim to acknowledge a report within a few days, agree on a disclosure timeline
with you, and credit you when the fix ships (unless you'd rather stay anonymous).
Please give us a reasonable window to fix before any public disclosure.

## Supported versions

dove is pre-1.0 and moving fast. Security fixes land on the latest release and
`main`; older releases are not maintained. Once dove reaches 1.0 this section
will list a support window.

## Scope and the security model

dove's core guarantee: **the infrastructure that stores and gates access to a
file can never read it.** Files are encrypted client-side; the decryption key
travels only in the URL *fragment*, which is never sent to any server, so S3,
CloudFront, and the access-policy Lambda hold ciphertext and enforce
*how many times / how long* — never *what*. See
[docs/designs/dove-v1.md](docs/designs/dove-v1.md) for the full model and threat
analysis.

Things we consider **in scope** for a report:

- key material leaking to the server (e.g. the fragment reaching a request),
- weaknesses in the encryption or chunking scheme (nonce reuse, missing
  authentication, truncation/reorder attacks),
- the access policy being bypassable (downloads consumed by link-unfurlers,
  count/expiry not enforced),
- provisioned infrastructure that is more permissive than documented (public
  read, over-broad IAM),
- the install/trust chain (an operator-served page able to redirect the
  canonical install; unsigned or unverifiable release artifacts).

Out of scope: issues in AWS/Cloudflare themselves, and misuse of a correctly
functioning feature (e.g. a user choosing a very long expiry).

## Release integrity

Release binaries are checksummed and signed. Verify what you install; never run
an artifact you can't verify against this project's published checksums and
signatures. Distribution and install trust are documented in the README and the
design doc.
