# Threat model

## Security objective

For a declared authority epoch, roots, sinks, and provider enforcement points,
`closurectl` helps an operator identify and verify a cut that intersects every
declared path from compromised authority to a consequential effect.

The objective is intentionally scoped. The tool must prefer an explicit
unknown or blocked result over an unsupported claim of containment.

## Example incident

A developer workstation executes an infostealer or malicious package with
user-level access. The attacker may copy:

- GitHub sessions, personal access credentials, SSH-agent access, and OAuth
  grants;
- npm publication credentials;
- cloud configuration and environment variables;
- credentials exposed to CI jobs;
- the ability to edit a workflow that mints short-lived cloud sessions.

The attacker may act concurrently with the responder. Derived credentials and
queued effects may survive revocation of the credential from which they
originated.

## Trust assumptions

Version 0.1 assumes:

- planning and signing happen on a known-clean machine;
- the operator has an independent recovery identity;
- provider control planes and documented read-only APIs are honest;
- graph authors correctly declare relevant roots, paths, sinks, and
  enforcement points;
- Ed25519 private keys remain secret;
- observation authors accurately report what an independent check saw.

## Protected outcomes

The model can represent authority to:

- administer source repositories;
- modify CI/CD workflows or secrets;
- mint workload identities;
- publish packages;
- use already-issued cloud sessions;
- commit queued deployments;
- change recovery methods.

The model is provider-neutral. Provider names and operations are opaque
metadata until a separately reviewed adapter implements them.

## Out of scope

`closurectl` does not claim to:

- detect the original malware or prove compromise;
- enumerate unknown credentials or attacker infrastructure;
- establish forensic chain of custody for the affected host;
- remediate kernel, firmware, identity-provider, or email compromise;
- reverse already committed effects;
- prove that a provider propagated revocation globally;
- infer causal relationships solely from timestamps;
- replace legal, regulatory, or provider reporting obligations.

## Safety invariants

1. **Credential-minimizing artifacts.** Artifacts reject common
   plaintext-secret field names and provider adapters allow-list returned
   metadata. This is a guardrail, not proof that arbitrary text is secret-free.
2. **Read-only adapters in v0.1.** Inventory operations do not revoke, rotate,
   delete, cancel, or disable resources.
3. **No silent success.** Missing checks yield `PARTIAL` or `INDETERMINATE`.
4. **No cut through an unenforceable edge.** Non-revocable edges have
   effectively infinite cut cost.
5. **Parallel paths remain distinct.** The planner does not merge parallel
   authority edges.
6. **Scope is carried into the receipt.** Every receipt states that it covers
   only its declared graph and observations. Signing and verification recompute
   the plan from that graph instead of trusting a supplied action list.
7. **Signing is not provider attestation.** An Ed25519 signature establishes
   artifact integrity and signer possession, not the truth of an observation.
8. **Existing keys are never overwritten.** Key generation fails closed when
   either destination already exists.

## Closure states

- `CLOSED`: every planned action has a `VERIFIED_CLOSED` observation.
- `PARTIAL`: at least one action is verified closed and at least one remains
  open, unknown, or missing.
- `OPEN`: no action is verified closed and at least one is confirmed open.
- `INDETERMINATE`: no action is confirmed open, but required evidence is
  unknown or missing.
- `BLOCKED`: the declared graph contains a root-to-sink path without any
  enforceable cut.

These states must not be broadened beyond the receipt's declared scope.

## Future mutation-adapter requirements

Before any live containment adapter can graduate from experimental status it
must provide:

- exact target preview and operator confirmation;
- independent recovery/lockout checks;
- idempotency semantics;
- timeout reconciliation before retry;
- a distinct observation operation;
- an explicit provider-specific definition of denial;
- rollback guidance where rollback is possible;
- bounded permissions and audit logging;
- tests against a disposable provider tenant.

An accepted API request is not sufficient evidence of closure.
