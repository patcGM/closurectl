# Changelog

All notable changes are documented here. The project follows Semantic
Versioning after the first public release.

## 1.0.0 — 2026-10-21

### Security and correctness

- strict JSON, timestamp, target URI, provider-output, pagination, and process
  output bounds with cross-platform Unicode handling;
- unique preview-bound AWS role-session containment policies protected by IAM
  `RoleId`, exact observer reconciliation, and old/new session canaries;
- strict inventory runtime schemas, source-digest/JSON-path provenance,
  freshness enforcement, conflict rejection, and an overwrite-safe TTY wizard;
- evidence-bound HTML reporting with full journal validation, restrictive CSP,
  control-character neutralization, collision refusal, and output SHA-256.

### Release engineering

- exact-SHA full CI, independent review, disposable GitHub/npm/AWS drills,
  signed tags, checked-in release notes, and protected-environment approval are
  mandatory for stable publication;
- stable compatibility, provider requirements, support routing, checksum, and
  GitHub attestation verification are documented.

## 0.3.0 — 2026-10-21

### Added

- human-confirmed incident drafts built from bounded GitHub, npm, and AWS
  inventories, with an interactive wizard and exact non-interactive selection;
- deterministic, self-contained HTML reports and timelines generated only
  after receipt-signature verification;
- allow-listed AWS IAM role inventory and unique preview-bound
  `ClosureCtlRevokeOlderSessions-*` execution through independent mutation and
  observer profiles without overwriting `AWSRevokeOlderSessions`;
- protected disposable AWS/OIDC provider-lab workflow;
- Linux arm64 and native macOS arm64/x86-64 binary build matrices.

### Changed

- release publication now verifies a successful destructive provider-lab run
  for GitHub/npm and AWS on the exact tagged commit instead of trusting mutable
  repository metadata;
- GitHub Actions dependencies are updated and remain pinned to full commit
  SHAs;
- exact live operations retain preview/digest/recovery controls without
  requiring the legacy `--experimental` feature flag;
- internal planner invariants remain enforced when Python assertions are
  disabled.

### Repository security

- `main` requires a current pull request, passing cross-platform checks, and an
  independent code-owner review;
- release and provider-lab deployments prevent self-review and administrator
  bypass;
- Actions SHA pinning, Dependabot security updates, secret scanning, and push
  protection are enabled.

## 0.2.0a1 — 2026-10-21

Experimental live-revocation alpha.

### Added

- immutable 15-minute execution previews bound to graph and plan digests;
- exact GitHub workflow disable and workflow-run cancellation;
- exact npm token-ID revocation using separate mutation and recovery configs;
- append-only, hash-chained execution journals with safe resume/reconciliation;
- independent provider evidence v2 and Ed25519 key fingerprints;
- v0.1 compatibility fixtures and new preview/journal/evidence schemas;
- coverage, pinned release constraints, SBOM generation, artifact attestations,
  and a protected destructive provider-lab workflow.

### Safety constraints

- live mutations require `--experimental` and exact preview confirmation;
- GitHub mutation/observation use different accounts;
- npm mutation/recovery configs must contain different credential material;
- timeout and crash recovery reconcile before retrying;
- failed or indeterminate actions stop later phases;
- npm closure remains indeterminate during its one-hour propagation window;
- no generic revoke-all operation and no automatic rollback.

## 0.1.0 — 2026-10-21

Initial alpha release.

### Added

- validated, secret-free authority graph format;
- minimum-cut closure planner with explicit unclosable witness paths;
- ordered containment phases;
- deterministic SHA-256 plan digests;
- Ed25519-signed evidence receipts;
- `CLOSED`, `PARTIAL`, `OPEN`, `INDETERMINATE`, and `BLOCKED` states;
- offline compromised-maintainer demonstration;
- read-only GitHub and npm inventory adapters;
- English and Russian user documentation;
- unit tests, CI, and Windows/Linux release binaries.

### Safety constraints

- no live credential revocation or provider mutation;
- no global containment claims;
- missing evidence never passes silently;
- provider output is allow-listed before persistence.
