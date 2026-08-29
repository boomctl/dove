# OSS build list: dove CLI

**Status:** planning queue, not a release promise.
**Scope:** the open-source `dove` CLI and its operator workflows only.
**Core dependencies:** [dove-core build list](https://github.com/boomctl/dove-core/blob/main/docs/BUILD_LIST.md).

## Hard boundary

This list does not include a desktop application, hosted Dove service, accounts, billing or credits, OIDC, organization policy, scanning, or enterprise controls. Those products have separate plans and must not be inferred from this queue.

## How a planning or build agent should use this file

1. Take one work-item ID at a time. Do not turn the whole list into one change.
2. Read current source, tests, and `--help` before treating any design document or website as shipped truth.
3. Produce a file-level implementation plan and identify cross-repository dependencies before editing.
4. Preserve the security invariants in `docs/designs/dove-v1.md`: secrets after `#` never enter requests or logs; page loads never spend access; cryptography stays local.
5. Keep human output as the default unless a work item explicitly changes the output contract.
6. Update tests, CLI help, README examples, and dove.sh documentation with the implementation.
7. Do not mark an item complete without the acceptance evidence listed under it.

## Recommended order

| Order | ID | Outcome | Depends on |
|---:|---|---|---|
| 1 | DOVE-001 | Honest, interoperable v1 request and PIN arguments | CORE-001 |
| 2 | DOVE-002 | Stable machine-readable output | — |
| 3 | DOVE-003 | Complete request lifecycle commands | CORE-003 |
| 4 | DOVE-004 | Safe unattended provisioning | CORE-004 |
| 5 | DOVE-005 | Standard-input sharing | CORE-005 |
| 6 | DOVE-006 | Batch sharing | DOVE-002, DOVE-005 |
| 7 | DOVE-007 | Inspectable teardown | CORE-004 |
| 8 | DOVE-008 | External backend helpers | CORE-006 |

## DOVE-001 — Make v1 request and PIN arguments honest

**Priority:** P0

**Problem:** `dove request --uploads N` implies a multi-file inbox, but the current request becomes terminal after one confirmed object. Supplied share/request PINs are accepted without CLI validation even though the browser input supports 4–6 numeric digits.

**Recommendation:**

- Treat one completed file as the only supported v1 request contract.
- Reject `--uploads` values other than `1` with an actionable message, then deprecate or remove the flag in the next compatible release.
- Validate supplied share and request PINs as 4–6 numeric digits at the CLI boundary and again in dove-core.
- Keep bare `--pin` generation at six zero-padded digits.
- Make help and error text distinguish outgoing-share PIN key derivation from request PIN upload authorization.

**Likely files:** `src/main.rs`, `src/share.rs`, `src/requestcmd.rs`, CLI tests and docs.

**Acceptance evidence:**

- Invalid PINs and `--uploads 0` / `--uploads 2` fail before any AWS or gate call.
- Bare `--pin` still produces a six-digit value.
- Help snapshots and docs describe one requested file and the two different PIN semantics.
- Existing one-file request round trips still pass.

## DOVE-002 — Add a stable machine-readable output contract

**Priority:** P1

**Problem:** automation must currently parse decorative human output. That is brittle for `share`, `request`, `requests`, `ls`, `status`, and provisioning.

**Recommendation:** add a global output mode, preferably `--output human|json` with human as the default. Define a versioned JSON envelope and command-specific payloads. Keep progress and diagnostics on stderr; write exactly one JSON document to stdout. Secret-bearing results such as links and generated PINs may be returned only because the caller explicitly requested the operation, and must never be echoed in errors or progress.

**Likely files:** `src/main.rs`, `src/ui.rs`, `src/cli_progress.rs`, command renderers, snapshot/integration tests.

**Acceptance evidence:**

- JSON is valid with color both enabled and disabled.
- stdout contains no progress text; stderr contains no fragment, content key, plaintext metadata, or PIN.
- Every supported command has a documented schema version and fixtures.
- Exit codes and error envelopes are stable and tested.

## DOVE-003 — Complete the request lifecycle

**Priority:** P1

**Problem:** requesters can create, list, and collect requests, but cannot explicitly close one or cleanly remove local request records.

**Recommendation:** add `dove requests revoke <id>` and `dove requests forget <id>`. Revoke must make a waiting request terminal at the gate and remove any request object if present. Forget is local-only, must warn that it deletes the durable decryption secret, and should refuse a live/received request without an explicit force flag. Consider `dove requests clean` only after revoke/forget semantics are stable.

**Depends on:** CORE-003.

**Acceptance evidence:**

- Revoked links cannot obtain an upload grant.
- Forget never mutates AWS state.
- Secret-loss warnings are explicit and tested.
- Unknown, waiting, received, failed, and unreachable states have deterministic behavior.

## DOVE-004 — Support safe unattended provisioning

**Priority:** P1

**Problem:** provisioning always prompts, preventing repeatable CI/bootstrap use. A generic `--yes` would be too easy to aim at the wrong AWS account.

**Recommendation:** add a non-interactive mode bound to an expected AWS account ID. Require an explicit profile/credential source plus `--confirm-account <12-digit-id>`. Print or return the same provision plan used interactively and refuse any identity mismatch before creating resources.

**Depends on:** CORE-004 typed provision plan.

**Acceptance evidence:**

- No prompt occurs in non-interactive mode.
- Missing or mismatched account confirmation fails before a mutating AWS call.
- Human and JSON modes expose the exact planned resources and region.
- Re-running remains idempotent.

## DOVE-005 — Share from standard input with an explicit name

**Priority:** P2

**Problem:** pipelines must write a temporary source file before sharing generated content.

**Recommendation:** accept `dove share - --name <filename>`. Require a name because stdin has none. Stream stdin to a mode-`0600` temporary file, then reuse the existing encrypt/upload path so memory use and container bytes do not diverge. Delete temporary plaintext on success and ordinary failure.

**Depends on:** CORE-005 input abstraction.

**Acceptance evidence:**

- Empty, interrupted, and large stdin inputs have deterministic errors and cleanup.
- The plaintext name is not exposed in a full-tier object key.
- Directory-only behaviors are rejected for stdin.
- A stdin share decrypts byte-for-byte through browser and CLI paths.

## DOVE-006 — Add batch sharing after JSON exists

**Priority:** P2

**Problem:** sending several independent files requires repeated manual commands, but silently zipping everything changes access and expiry semantics.

**Recommendation:** add a batch mode that creates independent shares from repeated paths or a manifest. Do not overload one link with multiple files. Define partial-failure, retry, ordering, and output semantics in JSON first; human output can summarize the same result.

**Depends on:** DOVE-002 and DOVE-005.

**Acceptance evidence:**

- Each input receives its own ID, key, expiry, and access budget.
- Partial failure never hides successful secret-bearing links.
- Retries do not duplicate already-completed entries without an explicit choice.
- Directory behavior remains the existing zip-one-directory contract.

## DOVE-007 — Add inspectable, conservative teardown

**Priority:** P2

**Problem:** there is no `dove destroy`, leaving operators to reverse the provisioner manually.

**Recommendation:** expose `dove destroy --plan` first. Actual teardown must require exact account and backend confirmation, enumerate retained objects/outstanding shares, and default to preserving user data. Separate disabling the gate, deleting control-plane resources, deleting scoped credentials, and deleting the bucket.

**Depends on:** CORE-004 typed destroy plan and operations.

**Acceptance evidence:**

- Plan mode is read-only and lists exact resource identifiers.
- Default execution cannot delete a non-empty bucket.
- Partial teardown is resumable and reports retained resources.
- Wrong account/region/backend confirmation fails before mutation.

## DOVE-008 — Finish the external backend helper contract

**Priority:** P3

**Problem:** config and discovery mention `dove-<kind>` helpers, but no wire protocol exists, so third-party backends cannot interoperate safely.

**Recommendation:** after CORE-006 defines and tests the protocol, make the CLI dispatch every relevant command through it with version negotiation, bounded subprocess I/O, signature/trust guidance, timeout/cancellation, and secret-safe error handling.

**Depends on:** CORE-006.

**Acceptance evidence:**

- A conformance helper passes share/get/list/revoke/status tests.
- Version mismatch and missing helper errors are actionable.
- Malformed or oversized helper output is bounded.
- The CLI does not imply that discovery alone means a helper is trusted.

## Explicitly deferred

- Multi-file request inboxes. They require per-file key and object semantics; `--uploads N` is not enough.
- Push notifications or background request polling.
- Runtime share-page plugins or themes. See CORE-007, which is on hold by product decision.
- Any hosted-service, account, billing, organization, or desktop work.
