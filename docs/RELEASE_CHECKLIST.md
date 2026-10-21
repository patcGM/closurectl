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
- Configure base64-encoded `LAB_NPM_MUTATION_NPMRC_B64` and
  `LAB_NPM_RECOVERY_NPMRC_B64` secrets with different credentials for one
  disposable npm account.
- Configure `LAB_NPM_OTP` only for the destructive run and remove it
  immediately afterward.
- Configure `LAB_AWS_MUTATION_ROLE_ARN` and `LAB_AWS_OBSERVER_ROLE_ARN` as
  different disposable IAM principals trusted only through GitHub OIDC. The
  mutation role may put/get the standard revoke policy on one lab role; the
  observer role is read-only.

## Candidate validation

- Run Ruff, coverage, schemas, package builds, and wheel/sdist clean-install
  smoke tests.
- Review every operation and immutable target in the provider-lab preview.
- Merge the reviewed candidate to `main`, then run
  `.github/workflows/provider-lab.yml` on that exact merge commit against a
  disposable GitHub repository and npm package/token.
- Run `.github/workflows/aws-provider-lab.yml` on the same commit against one
  exact disposable standard-partition IAM role. Review the account, role,
  existing policy digest, both STS identities, and role-wide cutoff effect.
- Download and inspect the preview artifact while the destructive job waits
  for `provider-lab` environment approval. Approve within the 15-minute
  preview TTL or rerun the workflow.
- Confirm both provider-lab receipts are `CLOSED`, every break-glass identity
  still works, and uploaded artifacts contain no credential material.

## Publish

- Create an annotated, human-signed tag:

  ```bash
  git tag -s vVERSION -m "closurectl vVERSION"
  git push origin vVERSION
  ```

- Approve the protected `release` environment only after the workflow confirms
  the tag, version, `main` ancestry, and successful GitHub/npm and AWS
  provider-lab runs on the exact tagged commit.
- Verify wheel, sdist, Windows/Linux/macOS binaries, SBOM, checksums, and GitHub
  artifact attestations from a clean machine.
- Use a stable `vX.Y.Z` tag only when every provider drill and review above is
  complete. Tags containing a prerelease suffix are marked prerelease
  automatically.
