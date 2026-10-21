# Authority graph format

Authority graphs are deterministic JSON documents. Schema version 1
intentionally uses a small format that can be reviewed without
provider-specific code.

## Top-level object

```json
{
  "schema_version": "1",
  "title": "Compromised release maintainer",
  "roots": ["incident:authority-epoch"],
  "sinks": ["sink:package-publication"],
  "nodes": [],
  "edges": []
}
```

- `roots` identify compromised authority epochs, not necessarily physical
  credentials.
- `sinks` identify effects whose successful invocation matters.
- every referenced ID must exist and all IDs must be unique.

## Nodes

```json
{
  "id": "github:queued-release",
  "kind": "pending_effect",
  "label": "Release job authorized before containment"
}
```

`kind` is descriptive in schema version 1. Recommended values include:

- `authority_epoch`
- `credential_handle`
- `identity`
- `delegation`
- `derived_authority`
- `pending_effect`
- `consequential_sink`

Do not put credential values in node IDs or labels.

## Edges

An edge represents an authority-bearing transition.

```json
{
  "id": "queued-release-can-publish",
  "source": "github:queued-release",
  "target": "sink:package-publication",
  "kind": "pending_effect",
  "label": "Cancel the queued release",
  "revocable": true,
  "cost": 1,
  "enforcement": {
    "provider": "github",
    "operation": "cancel_run",
    "target": "github://example/project/actions/runs/123456",
    "phase": "cancel_pending"
  }
}
```

`cost` is a relative operator-defined disruption value from 1 to 1,000,000.
The planner minimizes total cost. It does not infer business impact.

A non-revocable edge omits `enforcement`:

```json
{
  "id": "authority-copied-before-response",
  "source": "incident:authority-epoch",
  "target": "aws:existing-session",
  "kind": "derived_before_response",
  "label": "The cloud session already exists",
  "revocable": false,
  "cost": 1
}
```

The cost of a non-revocable edge is ignored by the cut algorithm.

## Executable enforcement targets

Provider/operation/target remain descriptive for planning, so existing v0.1
graphs stay valid. `execute`, however, rejects every contract except:

- `github` / `disable_workflow` /
  `github://OWNER/REPOSITORY/actions/workflows/NUMERIC_ID`;
- `github` / `cancel_run` /
  `github://OWNER/REPOSITORY/actions/runs/NUMERIC_ID`;
- `npm` / `revoke_token` /
  `npm://registry.npmjs.org/tokens/FULL_TOKEN_ID`.

The required phases are `stop_minting`, `cancel_pending`, and `revoke_roots`
respectively. Human-readable aliases, workflow paths, partial token keys, and
targets with credentials, query strings, or fragments are never executable.

## Enforcement phases

Supported phases and execution order:

1. `stop_minting`
2. `cancel_pending`
3. `revoke_descendants`
4. `revoke_roots`
5. `verify_sinks`

The sequence prevents a still-active root from immediately recreating
authority while responders are revoking descendants.

## Modelling pending effects

A queued job is not the same thing as a credential. If it was authorized
before revocation and can commit afterwards, model it as its own path:

```text
compromised authority epoch
  └── non-revocable: authorized before response
        └── queued job
              └── revocable: cancel or fence commit
                    └── production sink
```

Otherwise a plan may incorrectly conclude that revoking the original
credential closes work that has already left the authorization boundary.

## Secret-free artifacts

Input documents are rejected when an object contains these field names:

- `access_token`
- `authorization`
- `cookie`
- `password`
- `private_key`
- `refresh_token`
- `secret`
- `token`

Use an opaque `credential_handle`, provider object ID, or incident-local alias.
The rejection is a guardrail, not a complete secret scanner.

## Digest semantics

Documents are encoded as UTF-8 JSON with sorted keys, no insignificant
whitespace, no NaN values, and no ASCII escaping requirement. SHA-256 is
computed over those canonical bytes.

Plan digests bind the graph digest, selected actions, action order, costs, and
blocked witness path. Receipt signatures bind observations and the plan digest.
