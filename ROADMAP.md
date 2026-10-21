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
- [x] cross-platform CI and release binaries

## 0.2 — evidence adapters

- [ ] controlled GitHub authorization-denial probe
- [ ] GitHub queued-run reconciliation
- [ ] npm publication-rights denial probe
- [ ] provider-specific observation schemas
- [ ] receipt key fingerprints and key-rotation guidance
- [ ] schema compatibility fixtures across released versions

Evidence adapters remain read-only. They verify outcomes but do not request
revocation.

## 0.3 — tabletop drills

- [ ] disposable GitHub organization drill
- [ ] disposable npm package drill
- [ ] synthetic AWS OIDC and role-session lab
- [ ] containment SLO measurement
- [ ] clean-machine recovery readiness checks
- [ ] HTML report generated from signed artifacts

## Mutation adapters: gated

Live mutations are not assigned a release until the project has:

- an exact preview and mandatory confirmation format;
- independent break-glass identity validation;
- timeout reconciliation and idempotency tests;
- explicit lockout prevention;
- provider sandboxes in CI or reproducible integration labs;
- a reviewed rollback story;
- two-person review for every destructive provider operation.

Candidate operations, after those gates:

- cancel a specific GitHub Actions run;
- disable a specific workflow;
- revoke a specific npm publication credential;
- apply an AWS role-session invalidation policy with a declared cutoff.

No generic “revoke everything” command is planned.

## Non-goals

- malware removal;
- endpoint detection and response;
- universal credential discovery;
- vulnerability scanning;
- unattended automated incident response;
- claims of global attacker eviction.
