# Release checklist

## Repository controls

- Protect the `release` and `provider-lab` GitHub environments.
- Disable administrator bypass, enable `Prevent self-review`, and require an
  approver other than the workflow initiator on both environments. The
  initiator plus that distinct approver form the required two-person control.
- Require full-commit-SHA pinning for every GitHub Action.
- Register the human release signer's GPG or SSH signing key with GitHub and
  configure Git so GitHub reports the annotated tag signature as `Verified`.
  The release gate also requires tagger `patcGM
  <patcGM@users.noreply.github.com>`.
- Configure separate `LAB_GITHUB_MUTATION_TOKEN` and
  `LAB_GITHUB_OBSERVER_TOKEN` secrets for different GitHub accounts.
- Configure `LAB_GITHUB_REPOSITORY`, `LAB_GITHUB_WORKFLOW_ID`,
  `LAB_GITHUB_RUN_ID`, `LAB_NPM_TOKEN_ID`, and `LAB_NPM_ACCOUNT`. Both
  destructive jobs require exact equality with these registered disposable
  targets; the repository must match `patcGM/closurectl-lab-*`, and the preview
  must bind the npm action to that disposable account.
- Configure base64-encoded `LAB_NPM_MUTATION_NPMRC_B64` and
  `LAB_NPM_RECOVERY_NPMRC_B64` secrets with different credentials for one
  disposable npm account.
- Configure `LAB_NPM_OTP` only for the destructive run and remove it
  immediately afterward.
- Configure `LAB_AWS_MUTATION_ROLE_ARN` and `LAB_AWS_OBSERVER_ROLE_ARN` as
  different disposable IAM principals trusted only through GitHub OIDC. The
  mutation role may put/get one unique preview-bound containment policy on one
  lab role; the observer role is read-only.
- Configure `LAB_AWS_ACCOUNT_ID` and `LAB_AWS_TARGET_ROLE_NAME`; the destructive
  job requires exact equality and a `closurectl-lab-*` role name.

## Candidate validation

- Finalize `1.0.0`, the Production/Stable classifier, release notes, and every
  tracked file first. All following checks must run on that unchanged commit.
- Run Ruff, actionlint, cfn-lint, Bandit, pip-audit, coverage, schemas, package
  builds, wheel/sdist clean-install smoke tests, and every PyInstaller smoke.
- Confirm the full `ci.yml` workflow is successful on the exact candidate SHA.
- Obtain an independent approval from `test2GM` on the associated pull request;
  release automation checks that the latest review remains approved.
- Confirm each provider lab reports `READY` for its independent mutation and
  recovery identities before it creates an exact-target preview.
- Review every operation and immutable target in the provider-lab preview.
- Merge the reviewed candidate to `main`, then run
  `.github/workflows/provider-lab.yml` on that exact merge commit against a
  disposable GitHub repository and npm package/token.
- Run `.github/workflows/aws-provider-lab.yml` on the same commit against one
  exact disposable standard-partition IAM role. Review the account, immutable
  `RoleId`, unique policy name, policy digest, both STS identities, and
  role-wide cutoff effect. Require the real old-session canary to receive
  `AccessDenied` and the post-cutoff session to retain access.
- For GitHub/npm, download and inspect the preview artifact while the
  destructive job waits for `provider-lab` approval; approve within the
  15-minute TTL or rerun. For AWS, inspect the exact preview before approval;
  the old canary is created after approval but before the preview-bound cutoff,
  and the unchanged preview is retained with the final evidence.
- Confirm both provider-lab receipts are `CLOSED`, every break-glass identity
  still works, and uploaded artifacts contain no credential material.
- Confirm npm CLI 11.18.0 was installed by the drill and compare provider
  grants with `docs/PROVIDER_REQUIREMENTS.md`.

## Publish

- Create an annotated, human-signed tag:

  ```bash
  git tag -s vVERSION -m "closurectl vVERSION"
  git push origin vVERSION
  ```

- Check in `.github/releases/vVERSION.md`; the release workflow uses this exact
  file through `body_path` and does not generate mutable release notes.
- Approve the protected `release` environment only after the workflow confirms
  the tag, version, `main` ancestry, full CI, independent `test2GM` approval,
  and successful GitHub/npm and AWS provider-lab runs on the exact tagged
  commit.
- Verify wheel, sdist, Windows/Linux/macOS binaries, SBOM, checksums, and GitHub
  artifact attestations from a clean machine.
- Use a stable `vX.Y.Z` tag only when every provider drill and review above is
  complete. Tags containing a prerelease suffix are marked prerelease
  automatically.

On a clean machine, verify downloaded files:

```bash
sha256sum -c SHA256SUMS.txt
gh attestation verify closurectl-linux-x86_64 --repo patcGM/closurectl \
  --signer-workflow patcGM/closurectl/.github/workflows/release.yml
gh attestation verify closurectl-1.0.0-py3-none-any.whl --repo patcGM/closurectl \
  --signer-workflow patcGM/closurectl/.github/workflows/release.yml
```

Repeat attestation verification for every artifact being distributed. Do not
amend the checked commit after its exact-commit checks; any change requires full
CI, independent review, and all provider drills again.
