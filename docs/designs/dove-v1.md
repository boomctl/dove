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

## PIN-locked shares (out-of-band second factor)

For genuinely sensitive payloads — credentials, banking details — a share can be
locked with a short **PIN that the sender delivers out of band** (a text, a phone
call), separate from the link. Then intercepting the link alone isn't enough:
you need the link *and* the PIN, over two channels.

It binds cleanly to the full tier's encryption. The real decryption key is
derived, not carried: `key = KDF(fragment_secret, PIN)` (a slow KDF —
Argon2/PBKDF2 — over the fragment secret salted/peppered with the PIN). The URL
fragment carries only `fragment_secret`; the recipient must also enter the PIN
(received out of band) for the browser page or `dove get` to derive the real key
and decrypt. **The server still never sees the key or the PIN** — both are used
only client-side — so the "infrastructure can't read the file" guarantee holds,
now with a second factor on top.

**The PIN is checked at the gate — which is what makes a short PIN safe.** A
KDF-only PIN is offline-brute-forceable: once the ciphertext is fetched, a
4-digit PIN is 10,000 guesses against the GCM tag, and a slow KDF buys minutes,
not safety. So the PIN is verified **server-side at the access gate**, which
stores a salted hash of it, rate-limits, and **locks after N wrong attempts**.
The attacker can't obtain the ciphertext to attack offline, and can't keep
guessing online — brute force is *prevented*, not merely slowed. This is the
clean separation:

- **PIN → rate-limited access.** The gate verifies it and locks out abuse. The
  gate sees the PIN, but it never holds the fragment key, so it still **cannot
  decrypt** — a compromised gate with the PIN reads nothing.
- **Fragment key → confidentiality.** Never leaves the client. E2E is intact.

Strongest form does both: the PIN gates the fetch (the primary, brute-force-proof
defense) **and** is folded into the KDF (`key = KDF(fragment_secret, PIN)`), so
if a ciphertext ever leaks past the gate it's still PIN-locked — the slow KDF as
the second line, not the only line.

This is a **full-tier** feature — the simple tier has no gate and no client-side
key to bind a PIN to. `dove share <file> --pin` prompts for the PIN (never
echoed), prints the link, and reminds you to send the PIN over a separate
channel.

## The trust dimension: sender name + message

A recipient who lands on a share link has no built-in way to know it's genuinely
from who they think. So the sender can attach a **name** and a **message**:
`dove share <file> --from "Alice" --message "the Q3 numbers we discussed"`.

**The name shows *before* PIN entry** — it's the trust signal that lets the
recipient corroborate the out-of-band context ("yes, Alice said she'd send
this") *before* they type the PIN. The message shows on unlock.

Keeping this E2E (the server learns neither the name nor the message) is the
elegant part, and it works because the browser already holds the fragment key on
page load:

- Name + message are encrypted client-side with the **fragment key** into a
  small **metadata blob**, stored alongside the share (a DynamoDB field or a
  tiny S3 object).
- The gate serves that blob **freely** — no PIN, no download decrement (so a
  link-unfurler fetching it costs nothing). The browser decrypts it with the
  fragment key and shows the **name immediately, pre-PIN**. The server only ever
  held ciphertext.

**One decision to make** on the message:

- **UI-gated (simpler):** the message travels in the same free metadata blob and
  is merely *displayed* after unlock. Anyone with the link could technically
  decrypt it pre-PIN — fine for a friendly note, not for a secret.
- **PIN-gated (stronger):** the message is bound to the PIN (only decryptable
  once the PIN is known/verified), so it's protected the same as the file.
  Right when the message itself is sensitive.

Leaning: name is always the free, pre-PIN, E2E trust signal; the message is
UI-gated by default with a `--secret-message` style opt-in for PIN-gating.
(`--from`/`--message` are full-tier; the simple tier has no page to show them on.)

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
