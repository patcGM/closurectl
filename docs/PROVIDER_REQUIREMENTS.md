# Provider requirements

Live commands are attended, exact-target operations. Grant only the permissions
below and keep mutation credentials separate from observer/recovery credentials.

## Readiness preflight

On a known-clean machine, set the credentials for the providers in scope and
run:

```bash
closurectl readiness --provider github --provider npm
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
