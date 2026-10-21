# Release checklist

## Repository controls

- Protect the `release` and `provider-lab` GitHub environments.
- Enable `Prevent self-review` on `provider-lab` and require an approver other
  than the workflow initiator. The initiator plus that distinct approver form
  the required two-person control.
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

## Candidate validation

- Run Ruff, coverage, schemas, package builds, and wheel/sdist clean-install
  smoke tests.
- Review every operation and immutable target in the provider-lab preview.
- Merge the reviewed candidate to `main`, then run
  `.github/workflows/provider-lab.yml` on that exact merge commit against a
  disposable GitHub repository and npm package/token.
- Download and inspect the preview artifact while the destructive job waits
  for `provider-lab` environment approval. Approve within the 15-minute
  preview TTL or rerun the workflow.
- Confirm the receipt is `CLOSED`, the break-glass identities still work, and
  uploaded artifacts contain no credential material.
- Set repository variable `LIVE_DRILL_SHA` to that exact tested `main` commit
  SHA.

## Publish

- Create an annotated, human-signed tag:

  ```bash
  git tag -s v0.2.0a1 -m "closurectl v0.2.0a1"
  git push origin v0.2.0a1
  ```

- Approve the protected `release` environment only after the workflow confirms
  the tag, version, `main` ancestry, and `LIVE_DRILL_SHA`.
- Verify wheel, sdist, binaries, SBOM, checksums, and GitHub artifact
  attestations from a clean machine.
- Keep the GitHub release marked prerelease while live adapters require
  `--experimental`.
