# Design: dove v1

> **Status: proposal.** The first dove — send a file out of your own cloud,
> encrypted and expiring, in one command. Written up before it's built, so the
> shape can be poked at on paper. Sibling to
> [git-ark](https://github.com/boomctl/git-ark): same "your own cloud, one
> command, get out of the way" spirit, opposite access semantics.

## Motivation

Sharing a largeish file with someone is still a chore. The honest workflow today
is: stand up (or find) an S3 bucket, upload, mint a presigned URL, send it — and
then *remember to delete the file* so it doesn't linger forever. It's fiddly,
and the cleanup is the part everyone forgets.

The tooling landscape doesn't fill this exact gap:

- **P2P / code-phrase tools** (magic-wormhole, croc, LocalSend) are lovely but
  need both parties online *at the same time*, and there's no durable link to
  drop in an email.
- **Relay services** (transfer.sh, bashupload, WeTransfer) give a link — but
  it's *their* server holding your file.
- **Raw presigned URLs** are the native S3 answer and exactly the "ugh": manual,
  no auto-cleanup, no download limit, you babysit them.
- The closest fit, web apps like Nubbo, prove the demand but aren't a CLI and
  aren't infrastructure you own as code.

dove fills the gap: **a small CLI that fronts *your* S3 for ephemeral sharing**,
with real cleanup, and — in its full tier — end-to-end encryption where your own
infrastructure can't read what it's serving.

## Relationship to git-ark, and non-goals

dove is **not** git-ark, and deliberately so. git-ark is defined by four
guarantees: write-only, encrypted-to-you, durable/immutable, zero public access.
Sharing needs the inverse of every one: read access (they download),
decryptable-by-the-recipient (not your key), ephemeral (delete, not immutable),
and a presigned-ish URL (not zero-access). Bolting sharing onto git-ark would
mean a second bucket with opposite IAM and a decrypt model that undoes git-ark's
whole privacy promise, living in the same binary. So dove is a separate tool
with its own bucket and its own semantics — it just shares the family's
provisioning ethos.

**Non-goals for v1:**

- Not a backup tool, not sync, not a P2P transfer. One direction: you publish a
  file, someone fetches it, it expires.
- Not a general object host or a CDN for your website.
- Not a multi-tenant service. dove provisions infrastructure *you* own; each
  operator runs their own.

## Two tiers

dove has two provisioning tiers, chosen at `provision` time. The `share` / `get`
command surface is the same on both; the tool knows which mode it's in.

### Simple — just a bucket

`dove provision` (simple) stands up a private bucket with a lifecycle rule.
`dove share f --expires 5d` uploads the file, prints a **presigned URL**, and the
lifecycle rule deletes the object after the window. No encryption, no servers,
seconds to set up. This alone kills the original "ugh."

**Constraint that shapes the tier:** a SigV4 presigned URL maxes out at **7
days** (it can't outlive the signing credential). So simple mode means *expiry ≤
7 days*. The moment you want a longer-lived link, download counts, or
encryption, that's the fault line into the full tier — a clean, honest boundary,
not a wart.

### Full — end-to-end, policy-gated

`dove provision --full` stands up the whole stack (below). `dove share` then
encrypts client-side, uploads ciphertext, records an access policy, and prints a
link whose fragment carries the key. Downloads are **one-time / N-time / expiry**
and can outlive 7 days, because the file is served through a gate that
re-authorizes rather than a single fixed signature.

## Full-tier architecture

```
             dove share                         recipient
                 │                                  │
        encrypt (chunked)                    open link / dove get
                 │                                  │
                 ▼                                  ▼
   ┌── S3 (ciphertext) ──┐            ┌─ CloudFront (CDN + domain) ─┐
   │   multipart upload  │            │   static decryptor page     │
   └─────────────────────┘            │   + /d/<id> gate route      │
                 │                    └──────────────┬──────────────┘
                 ▼                                   ▼
        DynamoDB (policy:                    Lambda (the gate):
        downloads_remaining,          check policy → decrement →
        expires_at, s3_key)           stream ciphertext / short presign / 410
```

- **S3** holds ciphertext (multipart, so large files stream).
- **DynamoDB** holds the per-share policy: `{id, s3_key, downloads_remaining,
  expires_at, created_at}`.
- **Lambda** is the gate: on a fetch for `<id>`, it checks the policy, atomically
  decrements the count, and returns the ciphertext (streamed, or a
  few-second presigned URL) — or `410 Gone` when exhausted/expired.
- **CloudFront** fronts it: the CDN, the custom-domain endpoint, and the host for
  the static **decryptor page**.

The Lambda enforces *access*; it never touches the key (which is in the
fragment), so it can't read *content*. Access-control and confidentiality are
cleanly separated — the property nothing else in the landscape has.

## Encryption

**Cipher: AES-256-GCM.** Not age (which git-ark uses), because the receiver may
be a *browser*, and AES-GCM is the one authenticated cipher both Rust
(`aes-gcm`) and the browser (`crypto.subtle` / WebCrypto) speak natively — same
bytes, both ends, no WASM. GCM authenticates, so tampering is detected.

**The key lives in the URL fragment.**

```
https://dove.sh-instance/d/aX9k2#<base64url key>
                            ^^^^^ ^^^^^^^^^^^^^^^^
                            id    key — never sent to a server
```

Everything after `#` is the fragment; browsers and HTTP clients never transmit
it. So the infrastructure holds ciphertext and gates access while being
*structurally incapable* of decrypting. That's the whole design.

**Chunked, for largeish files** (required, not optional):

- Split the plaintext into fixed blocks (~1–4 MB). Encrypt each block with
  AES-256-GCM; the nonce is derived from a random base nonce + the block index
  (a counter — never reused).
- Put the **block index and an is-last flag in the GCM AAD**, so a tampered
  stream can't reorder blocks *or* silently truncate the tail (dropping the last
  chunk is a real attack otherwise).
- Sender streams: encrypt block → S3 multipart part. Receiver streams: fetch
  block → decrypt → write. Neither side holds the whole file in memory.

Key derivation can start simple (one random 256-bit key per share); HKDF-splitting
into separate encryption/metadata keys is a refinement, not a v1 requirement.

## Decryption — two paths, each doing what it's good at

**Browser (the "share with anyone" path).** The recipient opens the link and
gets a small static **decryptor page** — the request carries `/d/<id>` but *not*
`#key`. The page's JS reads `location.hash` locally, fetches the ciphertext
through the gate, decrypts in-browser with WebCrypto, and offers "Save file."
The key is never in any network request.

But a browser can't stream-decrypt a huge file cleanly (no buffering 2 GB in
memory; service workers / File System Access API are fiddly and Safari-flaky). So
the page **checks the size first**:

- Under a threshold → decrypt in-browser (buffer + save). Simple, no service
  worker.
- Over the threshold (or unsupported browser) → show a card: *"This file is 2.3
  GB — too big for the browser. Install dove and run `dove get <url>`,"* with the
  **complete command pre-filled** (the page has the fragment, so it can build the
  exact `dove get …#key` line). Showing the command does **not** consume a
  download — the decrement only fires on the real ciphertext fetch.

This deletes the hardest engineering from v1: the browser only does what browsers
do well, and hands the heavy files to the CLI.

**CLI (`dove get <url>`) — the symmetric path.** Split the URL into id + key,
fetch the ciphertext through the gate, AES-GCM decrypt locally, stream to disk.
No page, no browser limits — the reliable path for the biggest files, and the
pure end-to-end path for anyone who wants it. `dove` sending *and* receiving is
a nice symmetry, but it's also load-bearing: it's the large-file escape hatch.

## Access policy

The DynamoDB record per share carries `downloads_remaining` and `expires_at`;
the Lambda enforces both and decrements atomically. This yields one-time,
N-time, or time-limited shares from one mechanism, none of which the key ever
passes through.

**Sharp edge — link unfurlers eat one-time downloads.** Slack, iMessage, and
WhatsApp fetch a URL to build a preview, and a naive one-time link gets
*consumed by the preview bot* before the human clicks. Firefox Send got burned by
exactly this. The fix: don't decrement on page load. The decryptor page loads
freely (static, no secret); the **ciphertext fetch that decrements** requires an
explicit user action (a click) and a nonce/POST an unfurler won't replay.

## Custom domain (post-provision, opt-in)

`dove provision --full` hands back a working `*.cloudfront.net` URL immediately —
zero domain required, shares work out of the box. Then, as a **separate later
step**, `dove domain add share.you.com` wires a custom domain. The one honest
fork inside that:

- The ACM certificate (must live in **us-east-1** for CloudFront) needs DNS
  validation. **If the domain is in Route53, dove does it all** — mints the
  cert, drops the validation record, waits, attaches it, adds the alias.
- **If the DNS is elsewhere** (Cloudflare, Namecheap, …), dove can't touch it, so
  it *prints the two records to add* (the validation CNAME + the CNAME to
  CloudFront) and waits.

Both `provision` and `domain add` end with "…propagating, live in ~10–15 min" —
CloudFront + cert propagation is minutes, not instant. Say so; never hang.

## Install and trust

dove has a trust wrinkle no other tool in the family has: the person told to
install is the **recipient**, and they land on a page that may be served from the
*operator's* domain, which they have no reason to trust.

The model:

- **dove.sh is the anchor.** A project-owned domain turns the install source from
  a raw URL into a recognizable *brand* (the `bun.sh` / `astral.sh` idiom), and
  recognition becomes a security signal: once "dove comes from dove.sh" is known,
  a page pointing elsewhere reads as a red flag. dove.sh hosts the one canonical
  `## Install` (brew / scoop / cargo / `curl -fsSL https://dove.sh/install | sh`),
  and every share page and README just *links* to it.
- **Binaries are signed + notarized + checksummed** — Sigstore keyless (the
  release workflow's OIDC identity is the signer; the signature goes in the
  public transparency log), plus macOS notarization and `SHA256SUMS`. A tampered
  artifact is caught regardless of the link followed.
- **The share page is a signpost, not a source.** It only ever links to dove.sh;
  it never inlines an operator-spoofable install command as the primary path.

**Honest residual:** an operator controls their own share page's HTML and could
point it at `evil.sh`. dove.sh can't prevent that — it makes the *canonical/
default* page point somewhere recognizable, and signing makes a bad artifact
detectable. Recognition + verifiability, not page-tamper-prevention, is the
defense. In practice it's a one-time hurdle per recipient: once they have dove
from the canonical source, `dove get` is the trusted path for every future share.

## Command surface (sketch — to be refined during planning)

```
dove provision [--full] [--bucket <name>] [--region <r>]   # stand up the infra
dove domain add <domain>                                   # opt-in custom domain
dove share <file> [--expires <dur>] [--downloads <n>]      # → a link
dove get <url> [-o <path>]                                 # fetch + decrypt
dove ls | dove revoke <id>                                 # list / kill a share
dove status                                                # what's provisioned
```

## Open questions / follow-ups

- **Tiers: provision-time choice vs. progressive `dove upgrade`.** The upgrade
  path (simple → bolt on encryption + Lambda + CloudFront) is lovelier but
  trickier (plaintext-bucket → encrypted-path is closer to a re-provision).
  Leaning provision-time choice for v1, upgrade as a someday.
- **Chunk size and the size threshold** for the browser's decrypt-vs-punt
  decision — pick defaults from real WebCrypto memory behavior.
- **Metadata (original filename, content-type)** — encrypt it into the payload
  (so the server never learns it) vs. store it in the policy record. Leaning
  encrypt-it.
- **S3-compatible backends** (MinIO, R2) — the simple tier is portable; the full
  tier leans on CloudFront + Lambda + DynamoDB, which are AWS-specific. Document
  the boundary the way git-ark documents its per-backend guarantees.
- **Backport to git-ark:** the Sigstore signing + notarization added here is
  worth bringing back to git-ark's release workflow.
