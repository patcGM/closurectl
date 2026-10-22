# Provider requirements

Live commands are attended, exact-target operations. Grant only the permissions
below and keep mutation credentials separate from observer/recovery credentials.

## Readiness preflight

On a known-clean machine, set the credentials for the providers in scope and
run:

```bash
closurectl readiness --provider github --provider npm --provider aws
```

This read-only preflight authenticates both identities, verifies their required
separation, checks npm 11.18.0, and confirms that the npm recovery identity can
list token metadata. It does not inspect a target or prove resource-specific
permissions. A fresh `execute preview` remains mandatory and performs those
exact-target checks.

## GitHub

Use two different GitHub accounts. For the exact target repository:

- mutation token: repository **Metadata: read** and **Actions: read and write**;
- observer token: repository **Metadata: read** and **Actions: read**.

The mutation token calls only the exact workflow disable or workflow-run cancel
endpoint in the confirmed preview. The observer must be able to read that same
workflow or run before preview and after mutation. Organization administration,
repository contents write, secrets write, and account recovery permissions are
not required.

Read-only inventory additionally requires repository **Administration: read**
to enumerate deploy keys, alongside **Metadata: read** and **Actions: read**.
Missing collection permission is not interpreted as proof that a collection is
empty.

## npm

The supported public registry is `https://registry.npmjs.org`. closurectl 1.0
requires exactly npm CLI 11.18.0 and fails closed on a different version. The
CLI must provide `npm whoami --json`, `npm token list --json`, and
`npm token revoke`.

Set two different userconfig files for the same npm account:

```bash
export CLOSURECTL_NPM_MUTATION_USERCONFIG="$HOME/.npmrc-mutation"
export CLOSURECTL_NPM_RECOVERY_USERCONFIG="$HOME/.npmrc-recovery"
```

The recovery credential must remain valid after the exact mutation token is
revoked and must be able to list token metadata. Never pass an OTP on the
command line. The release drill pins npm 11.18.0 and waits the full documented
propagation safety window before observation.

## AWS

Use two AWS CLI v2 profiles resolving to different STS principals in the exact
target account. The mutation principal needs:

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:PutRolePolicy"
  ],
  "Resource": "arn:aws:iam::123456789012:role/ExactRoleName"
}
```

The observer needs only `iam:GetRole` and `iam:GetRolePolicy` on that role.
`sts:AssumeRole` is needed by the disposable lab mutation role solely to create
pre-cutoff and post-cutoff canary sessions; closurectl itself does not call it.
Neither identity needs `iam:DeleteRolePolicy`, and closurectl has no rollback
operation.

AWS CLI v2 must provide `sts get-caller-identity`, `iam get-role`,
`iam get-role-policy`, and `iam put-role-policy`. Only ordinary roles in the
standard `aws` partition are executable. See
[`AWS_ROLE_SESSIONS.md`](AWS_ROLE_SESSIONS.md) for the exact policy binding.
