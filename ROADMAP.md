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
- [ ] macOS release binary when a reliable runner is available

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
- [ ] successful disposable GitHub and npm drill on the release commit
- [ ] two-person review before removing the `--experimental` gate

Mutation and observation remain separate commands and credentials. No accepted
provider request is used as closure evidence.

## 0.3 — tabletop drills

- [ ] disposable GitHub organization drill
- [ ] disposable npm package drill
- [ ] synthetic AWS OIDC and role-session lab
- [ ] containment SLO measurement
- [ ] clean-machine recovery readiness checks
- [ ] HTML report generated from signed artifacts

## Additional mutation adapters: gated

Live mutations are not assigned a release until the project has:

- an exact preview and mandatory confirmation format;
- independent break-glass identity validation;
- timeout reconciliation and idempotency tests;
- explicit lockout prevention;
- provider sandboxes in CI or reproducible integration labs;
- a reviewed rollback story;
- two-person review for every destructive provider operation.

The GitHub Actions and npm token candidates are implemented experimentally.
The next candidate, only after those adapters graduate, is an AWS role-session
invalidation policy with a declared cutoff.

No generic “revoke everything” command is planned.

## Non-goals

- malware removal;
- endpoint detection and response;
- universal credential discovery;
- vulnerability scanning;
- unattended automated incident response;
- claims of global attacker eviction.
