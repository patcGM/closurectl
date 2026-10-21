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

Version 0.2.0a1 assumes:

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

The graph remains provider-neutral. Live execution recognizes only three
reviewed provider/operation pairs and exact resource URI formats; all other
plan actions remain descriptive metadata.

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
2. **Read-only commands stay read-only.** `inventory`, `plan`, `observe`, and
   `verify` never request a provider mutation.
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
9. **Mutation requires a bound preview.** Live execution requires a fresh
   preview digest that binds the graph, plan, immutable target, provider state,
   mutation identity, and independent observer identity.
10. **Unknown mutation outcome is not retried.** The append-only hash-chained
    journal records `REQUESTED` before the provider call. Resume reconciles
    provider state and does not blindly repeat a request.
11. **Phases fail closed.** A failed or indeterminate action prevents later
    containment phases from starting.
12. **Mutation is not observation.** Only the separate observer identity can
    produce provider evidence v2. An accepted mutation never becomes
    `VERIFIED_CLOSED` directly.

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

## Experimental mutation envelope

The alpha permits only:

- disabling one exact GitHub Actions workflow;
- cancelling one exact GitHub Actions run;
- revoking one exact npm token ID at `registry.npmjs.org`.

GitHub mutation and observation must use different GitHub accounts. npm
mutation and recovery must use different userconfig files for the same account,
with different credential material. The target token must be visible through
the recovery config before mutation.

GitHub workflow disable can be rolled back manually with the exact workflow
enable API after the incident is understood. Run cancellation and npm token
revocation are irreversible; the operator creates a new run or token instead.
`closurectl` never performs automatic rollback because concurrent attacker
activity may make it unsafe.

Before these adapters graduate from experimental status they still require a
successful protected disposable-provider drill on each release commit,
two-person review, and maintained provider-specific fault tests.

An accepted API request is not sufficient evidence of closure.
