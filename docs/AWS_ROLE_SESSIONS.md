# AWS IAM role-session containment

`closurectl` implements the AWS role-session deny mechanism without touching
AWS's shared `AWSRevokeOlderSessions` name. Each confirmed preview derives one
new inline policy named `ClosureCtlRevokeOlderSessions-<32 hex characters>` on
one exact IAM role. The name includes a random 128-bit operation ID; that ID,
cutoff, policy-document digest, target URI, action ID, and immutable IAM
`RoleId` are bound together in the preview. The policy
denies all actions and resources when `aws:TokenIssueTime` is earlier than that
exact cutoff.

This is a broad containment action. It affects every user and workload session
for the role that was issued before the cutoff. It is not an individual-session
logout.

## Supported target

```text
aws://123456789012/iam/roles/ProductionDeployer
```

Only the standard `aws` partition and ordinary IAM roles are executable.
Service-linked roles, IAM Identity Center managed roles, arbitrary inline
policies, trust-policy edits, and `aws-cn`/`aws-us-gov` partitions fail closed.

## Independent profiles

Use two AWS CLI profiles that resolve through `sts get-caller-identity` to
different principals in the target account:

```bash
export CLOSURECTL_AWS_MUTATION_PROFILE=incident-mutation
export CLOSURECTL_AWS_OBSERVER_PROFILE=incident-observer
```

The mutation principal needs these permissions on the exact target role:

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:PutRolePolicy"
  ],
  "Resource": "arn:aws:iam::123456789012:role/ProductionDeployer"
}
```

The observer needs only `iam:GetRole` and `iam:GetRolePolicy` on that role.
Neither profile should use the target role itself as its recovery identity.
The disposable lab mutation role additionally needs `sts:AssumeRole` on the
target only to create its old/new canary sessions; closurectl does not call
that API.

For the disposable provider lab only, the target role trusts the mutation role
and grants its own sessions `iam:GetRole` on itself. After independent review
of the exact preview, the workflow assumes a real target-role session before
the bound cutoff, proves its baseline access, applies the preview-bound policy,
waits past the cutoff and propagation interval, and
requires that old session's `iam:GetRole` probe to fail specifically with
`AccessDenied`. It then assumes a new post-cutoff session and requires the same
probe to succeed. This tests both data-plane denial and preservation of new
recovery access.

`closurectl` invokes AWS CLI with `--profile`, strips access-key/session-token
environment variables, disables pagers and auto-prompt, and persists only STS
identity ARNs plus allow-listed role metadata.

## Preview, apply, and observation

Preview confirms:

- both profiles use the target account and different STS principals;
- both see the same exact role ARN, path, `RoleId`, and session duration;
- the role is not service-linked;
- the derived `ClosureCtlRevokeOlderSessions-*` name is absent through both
  profiles;
- the exact future cutoff and deny-policy digest are recorded in the confirmed
  preview.

Apply uses the cutoff already recorded by preview (30 seconds after the
15-minute preview expiry); it never computes a replacement cutoff and refuses
to mutate after that cutoff. Before mutation it requires the same `RoleId`,
then invokes `PutRolePolicy` with `AWS_MAX_ATTEMPTS=1` so the AWS CLI cannot
retry the mutation internally. A timeout never
causes a blind second call: resume is read-only and reconciles the exact policy
name, cutoff, and document digest. A deleted and recreated role is rejected
even if its name and ARN are reused.

Independent evidence remains `INDETERMINATE` until the exact preview-bound
policy is still visible through the observer profile five minutes after both
the mutation request and cutoff. A different
`ClosureCtlRevokeOlderSessions-*` policy does not satisfy the observation.

## What this does not close

- A workflow or external identity that can assume the role again after the
  cutoff remains a minting path. Stop it separately.
- Long-term IAM user access keys do not carry `aws:TokenIssueTime` and are not
  affected.
- Some resource-based policies may require a separate explicit deny.
- IAM is eventually consistent; a control-plane read is not proof of global
  propagation.

## Rollback

Do not automatically remove any containment policy. Doing so can restore
authority to attacker sessions that have not expired. `closurectl` contains no
automatic delete or rollback path. After the incident is contained, review the
role and manually delete the exact `ClosureCtlRevokeOlderSessions-*` policy
named in the signed artifacts using an approved recovery procedure. Existing
`AWSRevokeOlderSessions` policies are never overwritten or removed.

The protected
[`aws-provider-lab.yml`](../.github/workflows/aws-provider-lab.yml) workflow
uses short-lived GitHub OIDC profiles and a disposable target role to exercise
the complete preview → apply → propagation → observe → signed receipt flow.
[`labs/aws/cloudformation.yml`](../labs/aws/cloudformation.yml) creates the
three narrowly scoped disposable roles when an account already has GitHub's
OIDC provider configured.
