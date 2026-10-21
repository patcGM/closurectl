# closurectl

[Русская версия](README.ru.md)

[![CI](https://github.com/patcGM/closurectl/actions/workflows/ci.yml/badge.svg)](https://github.com/patcGM/closurectl/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Know when credential revocation actually closes the incident.**

`closurectl` is a local, open-source CLI for planning and verifying revocation
closure after a developer identity compromise. It models copied credentials,
derived cloud sessions, queued CI jobs, publication rights, and consequential
effects as an authority graph. It then finds a least-cost set of enforceable
cuts and signs the resulting observations.

> [!IMPORTANT]
> `closurectl` is alpha software. Version 0.2.0a1 adds opt-in, experimental
> mutations for exact GitHub Actions workflows/runs and exact npm token IDs.
> They require a short-lived preview, digest confirmation, a separate recovery
> identity, and independent observation. Never interpret `CLOSED` as proof of
> global attacker eviction.

## The problem

An API returning `204 Revoked` proves that one request was accepted. It does not
prove that:

- an already-issued cloud session is invalid;
- a queued deployment cannot still commit;
- another OAuth grant or deploy key is gone;
- a compromised workflow can no longer mint new authority;
- every consequential access path was declared.

`closurectl` deliberately separates **requesting revocation** from **observing
the security outcome**.

```text
compromised workstation
├── GitHub session ────────────────> repository administration
│   └── Actions OIDC ─────────────> production
├── queued deployment ────────────> production
├── already-issued AWS session ───> production
└── npm publication credential ───> package registry
```

## What it does

- validates secret-free authority graph artifacts;
- computes a minimum revocation cut without collapsing parallel paths;
- orders actions as stop minting → cancel pending work → revoke descendants →
  revoke roots;
- refuses to claim closure when an unclosable path remains;
- creates deterministic plan digests;
- signs evidence receipts with Ed25519;
- reports `CLOSED`, `PARTIAL`, `OPEN`, `INDETERMINATE`, or `BLOCKED`;
- collects bounded, read-only GitHub and npm metadata through explicit
  allow-lists;
- experimentally disables one exact GitHub workflow, cancels one exact Actions
  run, or revokes one exact npm token with reconciliation and an append-only
  hash-chained journal.

## 60-second demo

Python 3.11 or newer is required when running from source.

```bash
git clone https://github.com/patcGM/closurectl.git
cd closurectl
python -m venv .venv
```

Activate the environment and install:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

python -m pip install .
closurectl demo --dir closurectl-demo
```

Expected result:

```text
status: PLANNED
actions: 5
  1. [stop_minting] github:disable_workflow -> release.yml
  2. [cancel_pending] github:cancel_workflow_run -> queued-production-deploy
  3. [revoke_descendants] aws:invalidate_role_sessions -> production-deployer
  4. [revoke_roots] npm:revoke_publication_credential -> affected-maintainer
  5. [revoke_roots] github:revoke_session -> maintainer-session
receipt: CLOSED
```

The demo is offline. Its private key is disposable and must never be reused.

## Installation

### Prebuilt binary

Download the executable for your operating system from
[GitHub Releases](https://github.com/patcGM/closurectl/releases). Releases
currently provide Windows x86-64 and Linux x86-64. macOS users should use
`pipx` or build from the tagged source until a reliable macOS release runner is
available.

Verify it against `SHA256SUMS.txt`:

```powershell
# Windows PowerShell
Get-FileHash .\closurectl-windows-x86_64.exe -Algorithm SHA256
.\closurectl-windows-x86_64.exe --version
```

```bash
# Linux
sha256sum closurectl-linux-x86_64
chmod +x closurectl-linux-x86_64
./closurectl-linux-x86_64 --version
```

The binaries are not yet code-signed or notarized. Build from the tagged
source if your environment requires a trusted publisher identity.

### pipx

```bash
pipx install "git+https://github.com/patcGM/closurectl.git@v0.2.0a1"
closurectl --version
```

### Source checkout

```bash
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

## Basic workflow

### 1. Validate a declared authority graph

```bash
closurectl validate authority-graph.json
```

Artifacts containing fields such as `access_token`, `password`, `private_key`,
or `secret` are rejected. Store opaque handles, never credential values.

### 2. Build a closure plan

```bash
closurectl plan authority-graph.json --out closure-plan.json
```

If a root-to-sink path contains no enforceable edge, the result is `BLOCKED`
and includes one witness path. The command prints the exact `plan:` digest;
copy that value into `evidence.json`.

### 3. Record independently checked outcomes

Create `evidence.json`:

```json
{
  "schema_version": "1",
  "plan_digest": "PLAN_DIGEST",
  "observations": [
    {
      "action_id": "close:queued-deploy-can-commit",
      "status": "VERIFIED_CLOSED",
      "checked_at": "2026-10-21T12:00:00Z",
      "summary": "The queued run is cancelled and cannot be re-dispatched",
      "reference": "incident://INC-42/checks/7"
    }
  ]
}
```

Valid observation states are `VERIFIED_CLOSED`, `STILL_OPEN`, and
`INDETERMINATE`. Missing observations never silently pass.

### 4. Sign and verify the receipt

Generate the keypair on a clean machine:

```bash
closurectl keygen \
  --private-key incident-signing.pem \
  --public-key incident-signing.pub.pem

closurectl receipt authority-graph.json closure-plan.json evidence.json \
  --private-key incident-signing.pem \
  --out closure-receipt.json

closurectl verify closure-receipt.json \
  --public-key incident-signing.pub.pem \
  --graph authority-graph.json \
  --plan closure-plan.json
```

Keep the private key outside the affected host and out of the repository.

## Read-only provider inventory

### GitHub

Provide the credential through the environment so it does not enter shell
history:

```bash
export GITHUB_TOKEN="$(gh auth token)"
closurectl inventory github \
  --repo OWNER/REPOSITORY \
  --out github-inventory.json
unset GITHUB_TOKEN
```

PowerShell:

```powershell
$env:GITHUB_TOKEN = gh auth token
closurectl inventory github `
  --repo OWNER/REPOSITORY `
  --out github-inventory.json
Remove-Item Env:GITHUB_TOKEN
```

The adapter collects allow-listed repository, workflow, active-run, deploy-key,
permission, and OAuth-scope metadata. Collections are capped at 500 objects
with an explicit truncation flag; absence is not treated as proof.

### npm

The adapter uses the currently authenticated npm CLI and discards credential
values and partial keys:

```bash
closurectl inventory npm \
  --package your-package \
  --out npm-inventory.json
```

Inventory accepts at most 50 packages and 1,000 items per collection.

## Experimental live revocation

Do not use this flow until you have a known-good recovery identity on a clean
machine. Only these exact contracts are executable:

- `github:disable_workflow` with
  `github://OWNER/REPO/actions/workflows/NUMERIC_ID`;
- `github:cancel_run` with
  `github://OWNER/REPO/actions/runs/NUMERIC_ID`;
- `npm:revoke_token` with
  `npm://registry.npmjs.org/tokens/FULL_TOKEN_ID`.

GitHub requires credentials for two different accounts:

```bash
export GITHUB_TOKEN="mutation-identity-token"
export CLOSURECTL_GITHUB_OBSERVER_TOKEN="independent-observer-token"
```

npm requires two different npm userconfig files for the same npm account. The
recovery config must remain valid if the target token authenticates the
mutation config:

```bash
export CLOSURECTL_NPM_MUTATION_USERCONFIG="$HOME/.npmrc-mutation"
export CLOSURECTL_NPM_RECOVERY_USERCONFIG="$HOME/.npmrc-recovery"
```

Never pass an OTP in command-line arguments. If npm requires one, provide it
through npm's protected environment/config mechanism and remove it
immediately.

Create and inspect the short-lived preview:

```bash
closurectl execute preview authority-graph.json closure-plan.json \
  --out execution-preview.json --experimental
```

Copy `preview_digest` only after checking every immutable target and identity,
then apply it exactly once:

```bash
closurectl execute apply authority-graph.json closure-plan.json \
  execution-preview.json --confirm PREVIEW_DIGEST \
  --journal execution.jsonl --experimental
```

After an interruption, use `execute resume` with the same arguments. Resume
only reconciles actions already recorded as requested; it never blindly
repeats one or starts a later unrequested action from an expired preview. After
reconciliation, create a fresh preview and a new journal to continue remaining
actions. Generate evidence with the independent identities:

```bash
closurectl observe authority-graph.json closure-plan.json \
  execution-preview.json --journal execution.jsonl --out evidence.json
```

The npm observer will not return `VERIFIED_CLOSED` until the token remains
absent after a one-hour propagation window. Mutation success is never accepted
as closure evidence.

Exit codes are `0` for the requested closed/success state, `2` for validation
or provider errors, `3` for a blocked plan, `4` for a valid but non-closed
receipt, `5` for incomplete execution/evidence, and `130` for interruption.
Use global `--json` before the command for machine-readable command summaries.

## Security model

Run incident planning from a known-clean machine with an independent
break-glass identity. Provider control planes are assumed honest. Local
artifacts describe only declared scope.

`closurectl` does not:

- discover every credential an attacker may have copied;
- clean malware or preserve a forensic disk image;
- undo effects that already committed;
- prove global revocation propagation;
- replace provider incident-response procedures or professional responders.

Read the full [threat model](docs/THREAT_MODEL.md) and
[graph format](docs/GRAPH_FORMAT.md), and follow the
[receipt key guidance](docs/RECEIPT_KEYS.md) before using real incident data.
Machine-readable formats are published in [`schemas/`](schemas/).

## Project status

Version 0.2.0a1 keeps the v0.1 planning foundation and adds gated live
revocation:

- authority graph validation;
- minimum-cut planner;
- signed receipts;
- offline demonstration;
- bounded GitHub/npm inventories;
- exact preview/confirm and resumable provider execution;
- independent provider evidence v2 and signing-key fingerprints.

Live adapters remain `--experimental` until the protected disposable GitHub
and npm lab passes on the release commit. Planned work is tracked in
[ROADMAP.md](ROADMAP.md).

## Contributing and security reports

See [CONTRIBUTING.md](CONTRIBUTING.md). Do not open a public issue for a
security vulnerability; follow [SECURITY.md](SECURITY.md).

## License

MIT
