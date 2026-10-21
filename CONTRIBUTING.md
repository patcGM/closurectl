# Contributing

Thanks for helping make containment claims more precise.

## Development setup

```bash
git clone https://github.com/patcGM/closurectl.git
cd closurectl
python -m venv .venv
```

Activate the environment, then:

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m coverage run -m unittest discover -s tests -v
python -m coverage report
python -m build
closurectl demo --dir closurectl-demo
```

The runtime supports Python 3.11 and newer. Tests use the standard-library
`unittest` runner so contributors do not need a separate test framework.

## Pull requests

Keep changes narrow and include tests for security-relevant behavior. A useful
pull request explains:

- the authority or failure mode being modelled;
- the exact claim the code is allowed to make;
- ambiguous states and how they fail safely;
- whether an artifact schema or digest changes;
- how the change was tested.

Schema changes require a versioning and migration note. Do not silently alter
canonicalization or receipt semantics.

## Provider adapters

Read-only provider adapters must:

- pass credentials through environment or native provider tooling;
- never accept credentials as command-line arguments;
- persist allow-listed fields rather than redacting arbitrary responses;
- use bounded requests and explicit timeouts;
- treat authorization failures and unexpected response shapes as errors;
- document what an empty result does and does not prove;
- include tests showing credential material is not written.

Live mutation adapters require the safety controls listed in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), exact target and operation
allow-lists, timeout-after-commit tests, an independent observer, a rollback
story, and a successful disposable-provider lab. Every destructive provider
operation requires two human reviewers.

## Commit and style guidance

- Prefer standard-library code where it improves auditability.
- Keep functions small enough to test directly.
- Use typed, user-safe exceptions for expected failures.
- Avoid network access in unit tests.
- Never add real credentials, private incident data, generated private keys, or
  provider exports to fixtures.

## Reporting security issues

Follow [`SECURITY.md`](SECURITY.md). Security reports do not belong in public
issues.
