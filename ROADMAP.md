# Roadmap

The roadmap is ordered by safety prerequisites rather than feature count.

## 0.1 — planning foundation

- [x] secret-free authority graph validation
- [x] least-cost revocation cut with parallel-edge support
- [x] witness path for unclosable graphs
- [x] deterministic plan digests
- [x] Ed25519-signed closure receipts
- [x] explicit partial and indeterminate states
- [x] self-contained offline demonstration
- [x] bounded, read-only GitHub repository inventory
- [x] bounded, read-only npm publication inventory
- [x] versioned JSON Schema documents
- [x] Windows and Linux release binaries
- [ ] publish native macOS arm64/x86-64 binaries from the implemented matrix

## 0.2.0a1 — independently observed live revocation

- [x] exact preview and mandatory digest confirmation
- [x] hash-chained execution journal and crash-safe reconciliation
- [x] exact GitHub workflow disable and active-run cancellation
- [x] exact npm token-ID revocation with a separate recovery config
- [x] GitHub Actions state observation
- [x] npm token-list observation with a one-hour propagation window
- [x] provider-specific evidence v2 and signing-key fingerprints
- [x] schema compatibility fixtures for v0.1 artifacts
- [x] protected destructive provider-lab workflow
- [x] successful disposable GitHub and npm drill on the release commit
- [x] remove the legacy `--experimental` gate through reviewed v0.3 changes

Mutation and observation remain separate commands and credentials. No accepted
provider request is used as closure evidence.

## 0.3 — guided incident response and AWS containment

- [x] provider inventory → human-confirmed incident draft
- [x] interactive incident wizard and exact non-interactive candidate selection
- [x] deterministic offline HTML report and execution timeline
- [x] allow-listed AWS IAM role and GitHub OIDC trust inventory
- [x] unique preview-bound AWS role-session deny with independent observation
- [x] protected disposable AWS/OIDC provider-lab workflow
- [x] Linux arm64 and native macOS arm64/x86-64 release matrices
- [ ] successful disposable GitHub/npm drill on the 1.0.0 release commit
- [ ] successful disposable AWS role-session drill on the release commit
- [ ] independent 1.0.0 review from `test2GM`
- [ ] containment SLO measurement
- [x] clean-machine recovery readiness checks
- [x] retain exact preview/confirm controls without a hidden feature flag

## Additional mutation adapters: gated

Live mutations are not assigned a release until the project has:

- an exact preview and mandatory confirmation format;
- independent break-glass identity validation;
- timeout reconciliation and idempotency tests;
- explicit lockout prevention;
- provider sandboxes in CI or reproducible integration labs;
- a reviewed rollback story;
- two-person review for every destructive provider operation.

The GitHub Actions, npm token, and AWS role-session adapters remain attended
and exact-target only. AWS writes one unique
`ClosureCtlRevokeOlderSessions-*` inline policy bound to the exact role ID and
confirmed preview, and release publication remains gated until its disposable
live drill passes.

No generic “revoke everything” command is planned.

## Non-goals

- malware removal;
- endpoint detection and response;
- universal credential discovery;
- vulnerability scanning;
- unattended automated incident response;
- claims of global attacker eviction.
