# dove full-tier gate v2 — the abuse-resistant, BYOA-safe gate

**Status:** proposed (supersedes the function-URL gate in `dove-v1.md`)
**Context:** dove asks the public to stand up a *public, unauthenticated* endpoint
in *their own* AWS account, on *their own* bill. Two things forced this redesign:

1. **BYOA reality.** dove runs in an account it does not control and cannot see
   the guardrails of. A real account (the account) was found to block *every*
   non-IAM-identity path to a Lambda Function URL — anonymous **and** the
   CloudFront-OAC service principal. Function URLs are the newest, most-restricted
   way to expose a Lambda and therefore the worst default for BYOA.
2. **Abuse is the defining constraint.** The payload is already end-to-end
   encrypted, so the real exposure is not data disclosure — it is
   **denial-of-wallet**: a public URL anyone can flood, on the user's bill, with
   the worst case being a surprise five-figure charge and an AWS abuse ticket.

The design goal: a gate that is **cheap to run, expensive to abuse, portable
across BYOA accounts, and honest when an account won't allow it.**

---

## 1. Threat model

**Primary threat — denial-of-wallet.** A public share link (or just the gate's
base host) is hit at high volume to run up per-request charges: Lambda invokes,
DynamoDB reads, S3 requests, API-Gateway/CloudFront requests.

**Secondary threats.**
- *Budget griefing* — a link-holder burns a share's download budget so the real
  recipient can't fetch it. (Mitigated today by the PIN.)
- *Egress amplification* — one `/dl` yields a presigned URL reusable until it
  expires; a large file can be re-pulled many times inside that window.

**Already defended (do not re-solve).**
- **Confidentiality** — chunked AES-256-GCM, key in the URL fragment, never sent
  to a server. The gate holds ciphertext it cannot read.
- **Enumeration** — share ids are random; there is no listing endpoint and the
  bucket blocks public `ListBucket`. One leaked link never reveals another.
- **Public write** — uploads require the scoped IAM key; the public cannot store
  content in the user's bucket.

**The core insight this design turns on:** *most* abuse is lazy — loop one URL,
spray garbage. The clever move is to make everything except a tiny, metered,
rate-limited path either free-to-reject or served-from-cache, so the expensive
backend is only ever reachable by requests the attacker **cannot manufacture**.

---

## 2. Architecture overview

```
                         ┌──────────── CloudFront (custom domain, WAF-ready) ───────────┐
recipient ── HTTPS ──►   │  /d/*   → S3 origin      (static page, long-TTL cache)         │
                         │  /meta/*→ API Gateway    (HTTP API, throttled; short-TTL cache)│
                         │  /dl/*  → API Gateway    (HTTP API, throttled; NEVER cached)   │
                         └───────────────────────────────┬──────────────────────────────┘
                                                          │
                                              gate Lambda (Python)
                                                 │        │
                                     DynamoDB (policy)   S3 (presign only; 302)
```

- **CloudFront** is the front door: caching, custom domain, a place to attach
  WAF, and the always-free 10M-requests / 1TB tier.
- **The page is static.** `/d/<id>/<name>` serves a single, share-agnostic
  `share.html` from S3 (the id is read client-side; the page then calls `/meta`).
  A CloudFront Function rewrites `/d/*` → the one object. **Page loads never
  invoke a Lambda** — this is the highest-volume, most unfurl-/flood-prone path,
  and it costs a CloudFront request and nothing else.
- **API Gateway HTTP API** fronts the gate Lambda for `/meta` and `/dl`. It is
  the portable primitive (reaches Lambda via `lambda:InvokeFunction`, the
  universally-allowed action, not `lambda:InvokeFunctionUrl`) and it hands us a
  **free native throttle** (rate + burst) — the abuse control function URLs lack.
- **The gate Lambda** verifies the request cryptographically *before* it touches
  DynamoDB or S3 (§3), then reads/decrements the policy and 302s to a presigned
  S3 URL. File bytes stream **S3 → client directly**; they never cross the gate.

Why not CloudFront → Lambda function URL (the v1 shape)? Because a real BYOA
account blocks it, and API Gateway is both more portable and gives us the
throttle. Why keep CloudFront at all (API Gateway is already public)? For the
static-page cache, the custom domain, WAF, and the free tier.

---

## 3. MAC'd share ids — the unforgeable shape (centerpiece)

**Problem.** A structural shape (`/meta/{id}` where `id` is `[0-9a-f]{16}`) is
*forgeable* — an attacker generates unlimited unique, correctly-shaped ids, each
a cache miss that reaches DynamoDB. Structure only forces *rotation*, and
rotation is free.

**Fix.** Make the shape *unforgeable*. The id carries a MAC that proves dove
minted it, verifiable without a database lookup:

```
nonce = 8 random bytes                         (the DynamoDB partition key)
mac   = HMAC-SHA256(gate_secret, nonce)[:8]    (64-bit tag, truncated)
id    = hex(nonce ‖ mac)                        (32 hex chars, in the URL)
```

- **Minting** (`dove share`, full tier): draw `nonce`, compute `mac` with the
  gate secret (§5), hand out `…/d/<id>/<name>#<fragment>`. DynamoDB is keyed on
  `nonce` alone; `mac` is verification-only, not stored.
- **Verifying** (gate Lambda, *first thing*, cheapest-first order):
  1. length == 32 and charset is hex — else reject (constant work).
  2. split into `nonce`/`mac`; recompute `HMAC(secret, nonce)[:8]`;
     **constant-time compare**. Mismatch → `403`, **before any DynamoDB or S3**.
  3. only now: `GetItem`/`UpdateItem` by `nonce`.

**What this buys.** An attacker without the gate secret cannot produce valid
`(nonce, mac)` pairs. The set of ids that can reach the backend collapses from
2⁶⁴ (any 16-byte string) to **exactly the links the attacker actually holds**.
And those are already:
- **cached on repeat** (§4) — replaying one link is free after the first hit,
- **budget-bound on `/dl`** — a held link can't be pulled past its download count,
- **rate-limited** and **metered** by the breaker.

"Rotate the right shape" stops being *free and infinite* and becomes *forge an
HMAC*, which is infeasible. Random-id floods die at the MAC check — a compute-only
comparison, no DynamoDB read, no S3 request.

**MAC length.** 64 bits. Forgery requires an *online* attack (the attacker must
query the gate to test a guess), so 2⁶⁴ is flatly infeasible; the throttle makes
even a dented fraction of that pointless. HMAC truncated to 64 bits is not
weakened against forgery at any realistic query volume. Cheap to keep at 64.

**Where the MAC is verified.** In the origin Lambda, before DynamoDB/S3. This
kills the *DynamoDB + S3* cost of forged floods and shrinks the reaching set to
real links. It does not, by itself, save the API-Gateway-hop + Lambda-invoke for a
forged request — that residual is what the throttle + breaker cap. Pushing the
verify to the edge (Lambda@Edge) would reject one hop earlier but adds its own
per-request cost, and CloudFront Functions can't HMAC (no crypto runtime). **We
verify in the Lambda; edge-verify is a documented future lever, not v2.**

---

## 4. Layered abuse defense (each layer as cheap as the one before)

Ordered from cheapest-to-reject outward-in. A flood must survive *every* layer to
cost real money, and the survivors are a bounded, metered set.

| Layer | Rejects | Cost of a rejected request |
|---|---|---|
| **Structural** (Lambda length+charset, optionally API Gateway regex) | malformed junk | ~an API Gateway request |
| **MAC verify** (Lambda, pre-DynamoDB) | well-formed **forged** ids (the whole 2⁶⁴ space) | + one Lambda invoke, **no DynamoDB/S3** |
| **Cache** (CloudFront: `/d` long-TTL, `/meta` short-TTL incl. 404s) | **repeats** of any id | served from edge, **no origin** |
| **Throttle** (API Gateway stage rate + burst) | volume above the rate | `429`, no Lambda |
| **Breaker** (CloudWatch alarm → disable gate) | sustained abuse | gate goes dark; user is told |

- `/dl` is **never cached** (it decrements) but is **budget-bound**, so it caps
  itself.
- The **breaker** is the blast-radius backstop: a CloudWatch alarm on gate request
  volume trips an SNS → kill-switch Lambda that disables the API stage (and pings
  the user). Metric alarms fire in minutes, so it bounds damage to *hours of a
  capped rate*, not an open-ended bill. This is the one control that turns
  "unbounded surprise" into "bounded, and I get told" — **it ships on by default;
  a gate handed to the public should never exist without it.**
- **Log discipline is a cost control, not just hygiene.** Under a flood,
  CloudWatch Logs ingestion ($0.50/GB) scales with invocations and can rival the
  compute bill (a per-request stack trace makes it far worse). So the hot path
  logs **nothing** — MAC-rejects, throttles, and normal serves are silent; only
  genuine unexpected errors log, minimally. Retention is set at provision (§7 bans
  infinite retention). Reject/flood visibility comes from **free default metrics**,
  not per-request logs. The breaker doubles as the backstop: killing the gate shuts
  off the log firehose too.
- **WAF** (per-IP rate rules, bot control) is the heavyweight opt-in (~$5/mo +
  $0.60/M) for users who expect to be targeted. Off by default.

---

## 5. The gate secret

A per-gate 32-byte random secret, generated once at provision.

- **Source of truth:** SSM Parameter Store **SecureString** (`/dove/<bucket>/gate-secret`).
  Not a plain Lambda env var — env vars are readable by anyone with
  `lambda:GetFunctionConfiguration`; the whole point is that the secret is hard to
  read.
- **Lambda** reads it at cold start (its role gets `ssm:GetParameter` on that one
  parameter, `kms:Decrypt` on the default key) and caches it in memory.
- **CLI** (`dove share`) needs it to mint ids. dove reads it once at provision and
  caches it locally in `~/.config/dove/secrets.toml` (already `0600`) next to the
  scoped key, so sharing doesn't hit SSM every time. Rotating the secret
  invalidates outstanding links by design (a revoke-all lever).

---

## 6. Cheap-by-design endpoints

- **`/d` (page):** static object in S3, `/d/*` rewritten to it by a CloudFront
  Function, long-TTL cached. Zero Lambda, zero DynamoDB.
- **`/meta`:** MAC-verify → **one DynamoDB GetItem**. The v1 S3 `HeadObject` is
  gone — `dove share` writes `size` into the policy item at upload time (dove
  already knows it). Cacheable short-TTL, **negative-cached** (404s cached) so a
  repeated bad id is free after the first.
- **`/dl`:** MAC-verify → DynamoDB conditional decrement → 302 to a presigned S3
  GET. Uncached, budget-bound. Egress-amplification note: keep the presign window
  as tight as large-file resume needs (a knob), since the URL is reusable until it
  expires.

---

## 7. Cost floor — $0 to operate

The target: **free to keep provisioned, free to run lightly.** Outside S3 egress on
actual downloads (unavoidable, and the user's regardless of architecture), an idle
or lightly-used gate costs approximately nothing. One rule makes this true:
**provision nothing always-on.** Every component is either perpetual-free-tier or
pay-per-use with no hourly/fixed charge.

**Standing cost of an idle instance:**

| Component | Fixed cost at idle | Why |
|---|---|---|
| S3 (bucket, page, ciphertext) | $0 | pay per storage/request; tiny |
| DynamoDB (on-demand) | $0 | no provisioned capacity = no hourly charge |
| Lambda (gate) | $0 | perpetual free tier (1M req + 400k GB-s/mo) |
| API Gateway (HTTP API) | $0 | no hourly charge; $1/M requests only |
| CloudFront | $0 | perpetual free tier (1TB + 10M req/mo) |
| CloudWatch alarm (breaker) | $0 | within the 10-alarm perpetual free tier |
| CloudWatch Logs | $0 | 5GB/mo free, with retention set (§4, §6) |
| SNS (breaker fan-out) | $0 | 1M publishes free |
| ACM certificate | $0 | public certs are free |
| SSM SecureString (standard) | $0 | standard params + aws-managed KMS are free |
| DNS | $0 | Cloudflare, not a Route 53 hosted zone |

At light use, requests fall inside those tiers or cost pennies; even after the
12-month tiers lapse, a few hundred `/meta` + `/dl` a month is fractions of a cent.
The only two costs not covered by a *perpetual* free tier — API Gateway ($1/M after
12 months) and CloudWatch alarms beyond 10 ($0.10 each) — are effectively $0 at
light use, and the caching + MAC-reject design (§3, §4) drives the API-Gateway
per-request count toward zero anyway.

### Banned components (anything with an always-on charge)

"Near-free" is a rule about what may be provisioned. The implementation MUST NOT
introduce any always-on resource; each of these has a cheaper serverless
substitute already in the design:

| Banned | Fixed cost it adds | Use instead |
|---|---|---|
| **ALB** in front of Lambda | ~$16/mo just to exist | API Gateway HTTP API |
| **Provisioned-capacity DynamoDB** | hourly RCU/WCU | on-demand (PAY_PER_REQUEST) |
| **Route 53 hosted zone** | $0.50/mo | Cloudflare (or the user's existing DNS) |
| **Customer-managed KMS key** | $1/mo | aws-managed key for SSM/S3 |
| **Advanced SSM parameters** | $0.05 each/mo | standard SecureString |
| **NAT Gateway / VPC endpoints** | ~$32/mo+ | none — the gate needs no VPC |
| **Infinite log retention** | storage creep past the 5GB free tier | 14-day retention set at provision |
| **Provisioned-concurrency Lambda** | hourly per unit | on-demand (cold start is fine here) |

The promise this earns: **free to keep provisioned, free to run lightly; you pay
S3 egress only when someone actually downloads, and abuse is capped so it stays
that way.**

---

## 8. BYOA articulation — state it, probe it, name the gap

dove runs in someone else's account; it owes them a clear contract and an honest
verdict, not a link that silently 403s.

1. **Stated requirements.** Provision declares, up front, exactly what the account
   must permit: create the bucket / DynamoDB / Lambda / API Gateway / CloudFront,
   **and** allow a publicly-reachable gate. A short preflight checks the create
   permissions and fails fast in plain language.
2. **Reachability probe (the step v1 was missing).** The *last* provisioning step
   is a real **anonymous** HTTPS GET against the deployed gate:
   - `GET /d/probe/x` must be `200` (proves CloudFront + S3 page).
   - `GET /meta/<a freshly-minted probe id>` must be a valid `200`/`404` JSON
     (proves CloudFront → API Gateway → Lambda → DynamoDB is publicly reachable).
   If either is not reachable anonymously, dove **does not report success**. It
   articulates: *"Everything was created, but your account is blocking anonymous
   access to the gate — dove needs the gate reachable without credentials, and
   this account won't allow it. This is an account guardrail, not a dove error.
   Options: …"* — the message that would have saved the entire the account detour.
3. **Actionable failures throughout** — every gate-provisioning error names the
   permission or guardrail involved, never a bare AWS error code.

---

## 9. Migration from v1

The v1 full tier (Lambda Function URL, optional CloudFront-OAC) is replaced, not
extended. dove is unreleased, so there is no link/format compatibility to keep;
v2 is the full tier. Concretely:

- `provision full` stands up: bucket + DynamoDB + gate Lambda + **API Gateway HTTP
  API** + **CloudFront** (S3 page origin + API Gateway origin) + the **SSM secret**
  + the **breaker** (CloudWatch alarm + kill-switch Lambda) + the reachability
  probe. It hands back a working `*.cloudfront.net` gate immediately.
- `domain add` attaches a custom domain (ACM + alias) to that distribution.
- `share` mints **MAC'd ids** and writes `size` into the policy item.
- The gate Lambda gains **MAC verification before every lookup** and drops the
  `HeadObject`.
- Retire: the function URL, the OAC, the `dynamodb:GetItem`-only role gap (already
  fixed), and the function-URL public permission.

---

## 10. Open decisions for review

1. **Breaker default threshold.** Conservative (protects the naive user, but could
   dark a legitimately-popular share) vs generous (fewer false trips, bigger
   worst-case bill). Proposed: a modest default with a clear `--max-requests/day`
   knob, erring toward *tripping and telling* over silent spend.
2. **Throttle values.** API Gateway stage rate/burst defaults — proposed low
   (e.g. a few req/s sustained, small burst), raisable per gate.
3. **Structural check at API Gateway vs Lambda.** HTTP APIs have thin request
   validation; REST APIs can regex the path param for free but cost more and add
   complexity. Proposed: structural check in the Lambda (cheap), keep the HTTP API.
4. **Edge MAC verify (Lambda@Edge).** Deferred — rejects forged floods one hop
   earlier at its own per-request cost. Revisit only if a real threat model wants
   randoms rejected before the origin.
5. **WAF default.** Off (cost); documented as the opt-in for targeted users.

---

## 11. Why this is defensible

The through-line: the account restriction and the abuse model pushed us to the
same architecture. Public things get abused — so we made the only thing an
attacker can *manufacture* (a URL shape) **unforgeable**, made everything they can
*replay* **cached or budget-bound**, made the residual **throttled**, and made the
worst case **bounded and announced**. What's left that costs real money is a
narrow, metered lane guarding a set of ids the attacker had to be *given*. That is
what makes "a public, unauthenticated endpoint on someone else's bill" a
responsible thing to hand the public.
