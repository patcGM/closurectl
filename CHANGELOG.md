# Changelog

All notable changes are documented here. The project follows Semantic
Versioning after the first public release.

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
