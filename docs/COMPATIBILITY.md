# Compatibility policy

This policy applies beginning with the stable 1.0.0 tag. closurectl follows
Semantic Versioning for its public CLI and persisted artifact formats.

## CLI

During the 1.x line:

- documented command names, required argument meanings, JSON result fields,
  and exit-code meanings remain compatible;
- new optional arguments, commands, providers, and JSON fields may be added in
  a minor release only where the containing format permits them;
- removals or incompatible meaning changes require 2.0;
- deprecations are documented for at least one minor release and 90 days.

An urgent security release may disable unsafe behavior sooner. It will fail
closed and document the exception rather than silently changing a containment
claim.

## Schemas and receipts

Published files under `schemas/` are immutable contracts. Existing schema
versions are not edited to reinterpret a previously valid artifact. A breaking
format gets a new schema version and, where applicable, a new schema filename.

The 1.x verifier continues to read authority graph, plan, and evidence v1
artifacts covered by the checked-in compatibility fixtures. Receipt v1 and v2
signature verification remains available throughout 1.x. New receipt versions
do not weaken verification of older Ed25519 signatures, canonical JSON,
digests, plan binding, or scope statements.

## Python and operating systems

The Python package supports CPython 3.11, 3.12, 3.13, and 3.14. CI covers all
four versions on Ubuntu 24.04 and Python 3.13 on Windows Server 2025, macOS 15
x86-64/arm64, and Ubuntu 24.04 arm64.

Release executables are built and smoke-tested for:

- Linux x86-64 and arm64;
- Windows x86-64;
- macOS x86-64 and arm64.

Dropping a Python minor or binary platform requires a major release unless the
upstream platform has reached end of life and continued support would create a
security risk.

## Provider tools

Provider APIs are external dependencies. Supported permissions and CLI
requirements are pinned in
[`PROVIDER_REQUIREMENTS.md`](PROVIDER_REQUIREMENTS.md). Provider behavior that
can no longer be verified fails closed until a tested release restores support.
