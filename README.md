# dove

**Send a file out of your own cloud — encrypted, expiring, one command.**

Sharing a largeish file is still annoying: stand up a bucket, mint a presigned
URL, and *remember to delete the thing* afterward. dove makes it one command
against infrastructure **you own**, and cleans up after itself.

```sh
dove share report.pdf --expires 3d          # → a link that dies in 3 days
dove share build.zip --downloads 1          # → a one-time download link
```

If git-ark is a **write-only vault** — encrypt *to you*, lock everything down —
dove is git-ark turned inside out: encrypt *to a link*, hand out exactly as much
access as you allow, then forget.

> **Status: designed in the open, not yet built.** The full v1 design —
> architecture, encryption, threat model — is written up first, in
> [docs/designs/dove-v1.md](docs/designs/dove-v1.md). This repo is the scaffold;
> implementation follows that spec.

## Two tiers

- **Simple** — just a bucket. `dove share f --expires 5d` uploads, prints a
  presigned URL, and a lifecycle rule auto-deletes it. Seconds to set up; no
  servers. (Presigned URLs cap at 7 days — that's an AWS limit, and the clean
  line into the full tier.)
- **Full** — the works: files are **encrypted client-side** in chunks, the
  decryption key travels only in the URL *fragment* (never sent to any server),
  and an access-policy gate enforces **one-time / N-time / expiry** downloads —
  while being structurally unable to read a byte of your file. Optional custom
  domain.

## Security model (short version)

The core guarantee: **the infrastructure that stores and gates access to a file
can never read it.** Files are encrypted with AES-256-GCM before upload; the key
lives in the URL fragment (`…#key`), which browsers and HTTP clients never send
to a server. So S3, CloudFront, and the policy Lambda hold ciphertext and
enforce *how many times / how long* — never *what*. See
[docs/designs/dove-v1.md](docs/designs/dove-v1.md) for the full model.

## Install

dove installs from **[dove.sh](https://dove.sh)** — the canonical, project-owned
source. Release binaries are checksummed and **signed with Sigstore** (keyless,
publicly verifiable). Always install from dove.sh or
[github.com/boomctl/dove](https://github.com/boomctl/dove/releases); never run an
artifact you can't verify.

_(Install commands land with the first release.)_

## Acknowledgments

`dove` is co-built with [Claude](https://www.anthropic.com/claude) (Anthropic's
Claude Code) working alongside its author. It's a sibling to
[git-ark](https://github.com/boomctl/git-ark) and shares its "your own cloud,
one command, get out of the way" spirit.

## License

[Apache-2.0](LICENSE).
