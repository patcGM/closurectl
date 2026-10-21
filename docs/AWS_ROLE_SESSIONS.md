# AWS IAM role-session containment

`closurectl` implements the AWS-documented role-session revocation mechanism:
it replaces one inline policy named `AWSRevokeOlderSessions` on one exact IAM
role. The policy explicitly denies all actions and resources when
`aws:TokenIssueTime` is earlier than the recorded cutoff.

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
    "iam:PutRolePolicy",
    "sts:AssumeRole"
  ],
  "Resource": "arn:aws:iam::123456789012:role/ProductionDeployer"
}
```

The observer needs only `iam:GetRole` and `iam:GetRolePolicy` on that role.
Neither profile should use the target role itself as its recovery identity.

For the disposable provider lab only, the target role trusts the mutation role
and grants its own sessions `iam:GetRole` on itself. The workflow assumes a
real pre-cutoff target-role session before mutation, waits for propagation, and
requires that session's `iam:GetRole` probe to fail with `AccessDenied`. This
tests data-plane denial in addition to observing the IAM policy.

`closurectl` invokes AWS CLI with `--profile`, strips access-key/session-token
environment variables, disables pagers and auto-prompt, and persists only STS
identity ARNs plus allow-listed role metadata.

## Preview, apply, and observation

Preview confirms:

- both profiles use the target account and different STS principals;
- both see the same exact role ARN and current revoke-policy digest;
- the role is not service-linked;
- any existing `AWSRevokeOlderSessions` document has the standard shape.

Apply writes a cutoff 30 seconds after the mutation request to account for IAM
propagation. A timeout never causes a blind second `PutRolePolicy`; resume
compares the current policy digest and cutoff with the confirmed preview and
recorded `REQUESTED` event.

Independent evidence remains `INDETERMINATE` until the standard policy is still
visible through the observer profile five minutes after the cutoff.

## What this does not close

- A workflow or external identity that can assume the role again after the
  cutoff remains a minting path. Stop it separately.
- Long-term IAM user access keys do not carry `aws:TokenIssueTime` and are not
  affected.
- Some resource-based policies may require a separate explicit deny.
- IAM is eventually consistent; a control-plane read is not proof of global
  propagation.

## Rollback

Do not automatically remove the policy. Doing so can restore authority to
attacker sessions that have not expired. After the incident is contained,
review the role and manually restore or delete `AWSRevokeOlderSessions` using
an approved recovery procedure.

The protected
[`aws-provider-lab.yml`](../.github/workflows/aws-provider-lab.yml) workflow
uses short-lived GitHub OIDC profiles and a disposable target role to exercise
the complete preview → apply → propagation → observe → signed receipt flow.
[`labs/aws/cloudformation.yml`](../labs/aws/cloudformation.yml) creates the
three narrowly scoped disposable roles when an account already has GitHub's
OIDC provider configured.
