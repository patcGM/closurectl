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
> `closurectl` performs real, high-impact mutations on exact GitHub Actions,
> and npm token targets. Every mutation requires a short-lived
> preview, exact digest confirmation, a separate recovery identity, a
> hash-chained journal, and independent observation. Never interpret `CLOSED`
> as proof of global attacker eviction.

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
├── already-issued cloud session ─> production
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
- checks clean-machine mutation and recovery identities before an incident,
  without reading or changing a target;
- refuses output paths that resolve to an input artifact or active provider
  config, including hard-link and symlink aliases;
- collects bounded, read-only GitHub and npm metadata through explicit
  allow-lists;
- turns GitHub and npm inventories into a reviewable incident draft and
  requires explicit candidate selection plus digest confirmation before a
  graph exists;
- renders a deterministic, offline HTML timeline from a verified signed
  receipt and optional execution journal;
- disables one exact GitHub workflow, cancels one exact Actions
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
  3. [revoke_descendants] manual:invalidate_cloud_sessions -> production-deployer
  4. [revoke_roots] npm:revoke_publication_credential -> affected-maintainer
  5. [revoke_roots] github:revoke_session -> maintainer-session
receipt: CLOSED
```

The demo is offline. Its private key is disposable and must never be reused.

## Installation

### Prebuilt binary

Download the executable for your operating system from
[GitHub Releases](https://github.com/patcGM/closurectl/releases). Releases
provide Windows x86-64, Linux x86-64/arm64, and native macOS arm64/x86-64
artifacts. Published binaries remain unsigned and unnotarized.

Verify it against `SHA256SUMS.txt`:

```powershell
# Windows PowerShell
$expected = ((Select-String ' closurectl-windows-x86_64.exe$' .\SHA256SUMS.txt).Line -split '\s+')[0]
$actual = (Get-FileHash .\closurectl-windows-x86_64.exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 mismatch" }
gh attestation verify .\closurectl-windows-x86_64.exe --repo patcGM/closurectl `
  --signer-workflow patcGM/closurectl/.github/workflows/release.yml
.\closurectl-windows-x86_64.exe --version
```

```bash
# Linux: download every release asset first
sha256sum -c SHA256SUMS.txt
gh attestation verify closurectl-linux-x86_64 --repo patcGM/closurectl \
  --signer-workflow patcGM/closurectl/.github/workflows/release.yml
chmod +x closurectl-linux-x86_64
./closurectl-linux-x86_64 --version
```

On macOS, use `shasum -a 256 -c SHA256SUMS.txt` and the same
`gh attestation verify` command for the selected binary.

The binaries are not yet code-signed or notarized. Build from the tagged
source if your environment requires a trusted publisher identity.

### pipx

```bash
pipx install "git+https://github.com/patcGM/closurectl.git@v1.0.0"
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

closurectl report authority-graph.json closure-plan.json closure-receipt.json \
  evidence.json \
  --public-key incident-signing.pub.pem \
  --out closure-report.html
```

The report command verifies the separate evidence artifact against the signed
receipt and prints the SHA-256 of the generated HTML. See
[`docs/INCIDENT_REPORTS.md`](docs/INCIDENT_REPORTS.md).

Keep the private key outside the affected host and out of the repository.

## Clean-machine recovery readiness

Before an incident, configure the mutation and observer/recovery credentials
described below on a known-clean machine, then authenticate only the providers
you expect to use:

```bash
closurectl readiness \
  --provider github \
  --provider npm
```

The command is read-only. It verifies that GitHub uses two accounts, npm uses
different credential material for the same account with npm 11.18.0 and a
working recovery token listing.
It emits only provider identities and credential fingerprints, never credential
values. A failed provider is `NOT_READY`, all selected providers are still
reported, and the command exits with code `5`. Put global `--json` before
`readiness` for machine-readable output.

Readiness does not inspect an incident target or prove target permissions.
`execute preview` still checks exact resources, current state, and provider
permissions before any mutation.

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

## Inventory-to-graph incident wizard

Provider metadata never becomes an authority claim automatically. First create
a review draft:

```bash
closurectl incident draft \
  --title "Compromised release identity" \
  --github-inventory github-inventory.json \
  --npm-inventory npm-inventory.json \
  --out incident-draft.json
```

Then either review every proposed path interactively:

```bash
closurectl incident wizard incident-draft.json --out authority-graph.json
```

or select exact candidate IDs non-interactively and confirm the printed
`draft_digest`:

```bash
closurectl incident build incident-draft.json \
  --select github:OWNER/REPO:disable-workflow:WORKFLOW_ID \
  --confirm DRAFT_DIGEST \
  --out authority-graph.json
```

Truncated inventories add a mandatory unclosable path, so the resulting plan is
`BLOCKED` instead of silently claiming completeness.

## Attended live containment

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
  --out execution-preview.json
```

Copy `preview_digest` only after checking every immutable target and identity,
then apply it exactly once:

```bash
closurectl execute apply authority-graph.json closure-plan.json \
  execution-preview.json --confirm PREVIEW_DIGEST \
  --journal execution.jsonl
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
receipt, `5` for incomplete readiness/execution/evidence, and `130` for
interruption. Use global `--json` before the command for machine-readable
command summaries.

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
[receipt key guidance](docs/RECEIPT_KEYS.md), review the
[provider requirements](docs/PROVIDER_REQUIREMENTS.md), and understand the
[compatibility policy](docs/COMPATIBILITY.md) before using real incident data.
Machine-readable formats are published in [`schemas/`](schemas/).

## Project status

Version 1.0.0 combines planning, guided incident modelling, independently
observed live containment, and signed reporting:

- authority graph validation;
- minimum-cut planner;
- signed receipts;
- offline demonstration;
- bounded GitHub and npm inventories;
- human-confirmed inventory-to-graph drafts and an incident wizard;
- clean-machine checks for independent recovery identities;
- deterministic offline HTML reports and execution timelines;
- exact preview/confirm and resumable provider execution;
- independent provider evidence v2 and signing-key fingerprints.

GitHub/npm publication is release-gated by a protected disposable lab on the
exact tagged commit. The 1.0.0 tag and release remain blocked until the final
metadata commit passes that drill, full CI, and independent review.
Planned work is tracked in [ROADMAP.md](ROADMAP.md).

## Contributing and security reports

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SUPPORT.md](SUPPORT.md). Do not open
a public issue for a security vulnerability; follow [SECURITY.md](SECURITY.md).

## License

MIT
