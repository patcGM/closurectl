"""Human-confirmed authority-graph drafts built from provider inventories."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable, Iterable
from typing import Any

from .adapters.npm import DEFAULT_REGISTRY
from .errors import ValidationError
from .execution_models import parse_rfc3339
from .models import AuthorityGraph, Edge, Node
from .receipts import utc_now
from .serialization import digest_json

INCIDENT_DRAFT_SCHEMA_VERSION = "1"
MAX_DRAFT_CANDIDATES = 2_000
INVENTORY_MAX_AGE_SECONDS = 3_600

_GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_NPM_TOKEN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{3,199}$")
_NPM_PACKAGE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return value.strip()


def _required_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{field} must be an array")
    return value


def _integer_id(value: Any, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValidationError(f"{field} must be a positive integer")
    return str(value)


def _exact_fields(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValidationError(f"{context} has invalid fields")
    return value


def _strict_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{field} must be true or false")
    return value


def _nonnegative_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError(f"{field} must be a non-negative integer")
    return value


def _string_array(value: Any, field: str, *, allow_empty: bool = True) -> list[str]:
    items = _required_list(value, field)
    if not allow_empty and not items:
        raise ValidationError(f"{field} must not be empty")
    if not all(isinstance(item, str) and item for item in items):
        raise ValidationError(f"{field} must contain non-empty strings")
    if len(items) != len(set(items)):
        raise ValidationError(f"{field} must not contain duplicates")
    return items


def _validate_inventory_common(
    inventory: dict[str, Any],
    *,
    adapter: str,
    fields: set[str],
) -> None:
    _exact_fields(inventory, fields, f"{adapter} inventory")
    if inventory.get("schema_version") != "1" or inventory.get("adapter") != adapter:
        raise ValidationError(f"{adapter} inventory identity is invalid")
    parse_rfc3339(inventory.get("collected_at"), f"{adapter} collected_at")
    _required_string(inventory.get("credential_handle"), f"{adapter} credential_handle")
    _string_array(inventory.get("limitations"), f"{adapter} limitations", allow_empty=False)


def _validate_github_inventory(inventory: dict[str, Any]) -> None:
    _validate_inventory_common(
        inventory,
        adapter="github-read-only",
        fields={
            "schema_version",
            "adapter",
            "collected_at",
            "credential_handle",
            "subject",
            "oauth_scopes",
            "repositories",
            "limitations",
        },
    )
    subject = _exact_fields(
        inventory.get("subject"),
        {"login", "id", "type"},
        "GitHub inventory subject",
    )
    _required_string(subject.get("login"), "GitHub inventory subject.login")
    _integer_id(subject.get("id"), "GitHub inventory subject.id")
    _required_string(subject.get("type"), "GitHub inventory subject.type")
    _string_array(inventory.get("oauth_scopes"), "GitHub inventory oauth_scopes")
    repositories = _required_list(inventory.get("repositories"), "GitHub inventory repositories")
    seen_repositories: set[str] = set()
    repository_fields = {
        "full_name",
        "private",
        "archived",
        "default_branch",
        "permissions",
        "workflows",
        "workflow_count",
        "workflow_results_truncated",
        "active_runs",
        "run_count_scanned",
        "run_results_truncated",
        "deploy_keys",
        "deploy_key_count",
        "deploy_key_results_truncated",
    }
    for repository_index, raw_repository in enumerate(repositories):
        repository = _exact_fields(
            raw_repository,
            repository_fields,
            f"GitHub repository[{repository_index}]",
        )
        full_name = _required_string(
            repository.get("full_name"),
            f"GitHub repository[{repository_index}].full_name",
        )
        if not _GITHUB_REPOSITORY.fullmatch(full_name):
            raise ValidationError(f"invalid GitHub repository in inventory: {full_name!r}")
        if full_name in seen_repositories:
            raise ValidationError(f"duplicate GitHub repository in inventory: {full_name}")
        seen_repositories.add(full_name)
        _strict_bool(repository.get("private"), f"GitHub {full_name}.private")
        _strict_bool(repository.get("archived"), f"GitHub {full_name}.archived")
        _required_string(repository.get("default_branch"), f"GitHub {full_name}.default_branch")
        permissions = repository.get("permissions")
        if not isinstance(permissions, dict) or not set(permissions) <= {
            "admin",
            "maintain",
            "push",
            "triage",
            "pull",
        }:
            raise ValidationError(f"GitHub permissions for {full_name} are invalid")
        for permission, enabled in permissions.items():
            _strict_bool(enabled, f"GitHub {full_name}.permissions.{permission}")

        workflows = _required_list(repository.get("workflows"), f"GitHub {full_name}.workflows")
        workflow_ids: set[str] = set()
        for item_index, raw_workflow in enumerate(workflows):
            workflow = _exact_fields(
                raw_workflow,
                {"id", "name", "path", "state"},
                f"GitHub {full_name} workflow[{item_index}]",
            )
            workflow_id = _integer_id(workflow.get("id"), f"GitHub {full_name} workflow.id")
            if workflow_id in workflow_ids:
                raise ValidationError(f"duplicate GitHub workflow ID for {full_name}")
            workflow_ids.add(workflow_id)
            for field in ("name", "path", "state"):
                _required_string(workflow.get(field), f"GitHub {full_name} workflow.{field}")
        workflow_count = _nonnegative_integer(
            repository.get("workflow_count"),
            f"GitHub {full_name}.workflow_count",
        )
        if workflow_count < len(workflows):
            raise ValidationError(f"GitHub workflow_count is inconsistent for {full_name}")
        workflows_truncated = _strict_bool(
            repository.get("workflow_results_truncated"),
            f"GitHub {full_name}.workflow_results_truncated",
        )
        if workflows_truncated != (workflow_count > len(workflows)):
            raise ValidationError(f"GitHub workflow truncation is inconsistent for {full_name}")

        runs = _required_list(repository.get("active_runs"), f"GitHub {full_name}.active_runs")
        run_ids: set[str] = set()
        for item_index, raw_run in enumerate(runs):
            run = _exact_fields(
                raw_run,
                {
                    "id",
                    "workflow_id",
                    "name",
                    "event",
                    "status",
                    "run_attempt",
                    "head_sha",
                    "created_at",
                    "html_url",
                },
                f"GitHub {full_name} run[{item_index}]",
            )
            run_id = _integer_id(run.get("id"), f"GitHub {full_name} run.id")
            if run_id in run_ids:
                raise ValidationError(f"duplicate GitHub run ID for {full_name}")
            run_ids.add(run_id)
            _integer_id(run.get("workflow_id"), f"GitHub {full_name} run.workflow_id")
            _integer_id(run.get("run_attempt"), f"GitHub {full_name} run.run_attempt")
            for field in ("name", "event", "status", "head_sha", "html_url"):
                _required_string(run.get(field), f"GitHub {full_name} run.{field}")
            if run["status"] == "completed":
                raise ValidationError(f"GitHub active run is completed for {full_name}")
            parse_rfc3339(run.get("created_at"), f"GitHub {full_name} run.created_at")
        run_count = _nonnegative_integer(
            repository.get("run_count_scanned"),
            f"GitHub {full_name}.run_count_scanned",
        )
        if run_count < len(runs):
            raise ValidationError(f"GitHub run_count_scanned is inconsistent for {full_name}")
        _strict_bool(
            repository.get("run_results_truncated"),
            f"GitHub {full_name}.run_results_truncated",
        )

        keys = _required_list(repository.get("deploy_keys"), f"GitHub {full_name}.deploy_keys")
        key_ids: set[str] = set()
        for item_index, raw_key in enumerate(keys):
            key = _exact_fields(
                raw_key,
                {"id", "title", "read_only", "verified", "created_at"},
                f"GitHub {full_name} deploy_key[{item_index}]",
            )
            key_id = _integer_id(key.get("id"), f"GitHub {full_name} deploy_key.id")
            if key_id in key_ids:
                raise ValidationError(f"duplicate GitHub deploy key ID for {full_name}")
            key_ids.add(key_id)
            _required_string(key.get("title"), f"GitHub {full_name} deploy_key.title")
            _strict_bool(key.get("read_only"), f"GitHub {full_name} deploy_key.read_only")
            _strict_bool(key.get("verified"), f"GitHub {full_name} deploy_key.verified")
            parse_rfc3339(key.get("created_at"), f"GitHub {full_name} deploy_key.created_at")
        key_count = _nonnegative_integer(
            repository.get("deploy_key_count"),
            f"GitHub {full_name}.deploy_key_count",
        )
        if key_count < len(keys):
            raise ValidationError(f"GitHub deploy_key_count is inconsistent for {full_name}")
        keys_truncated = _strict_bool(
            repository.get("deploy_key_results_truncated"),
            f"GitHub {full_name}.deploy_key_results_truncated",
        )
        if keys_truncated != (key_count > len(keys)):
            raise ValidationError(f"GitHub deploy key truncation is inconsistent for {full_name}")


def _validate_npm_inventory(inventory: dict[str, Any]) -> None:
    _validate_inventory_common(
        inventory,
        adapter="npm-read-only",
        fields={
            "schema_version",
            "adapter",
            "collected_at",
            "credential_handle",
            "registry",
            "credential_metadata",
            "packages",
            "limitations",
        },
    )
    registry = _required_string(inventory.get("registry"), "npm inventory registry")
    try:
        parsed = urllib.parse.urlsplit(registry)
        parsed.port
    except ValueError as exc:
        raise ValidationError("npm inventory registry is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or registry.rstrip("/") != f"https://{parsed.netloc}"
    ):
        raise ValidationError("npm inventory registry must be a canonical HTTPS origin")

    credentials = _required_list(
        inventory.get("credential_metadata"),
        "npm inventory credential_metadata",
    )
    allowed_credential_fields = {
        "id",
        "name",
        "created",
        "updated",
        "readonly",
        "automation",
        "cidr_whitelist",
    }
    credential_ids: set[str] = set()
    for index, raw_credential in enumerate(credentials):
        if (
            not isinstance(raw_credential, dict)
            or not set(raw_credential) <= allowed_credential_fields
            or not {"id", "readonly"} <= set(raw_credential)
        ):
            raise ValidationError(f"npm credential_metadata[{index}] has invalid fields")
        token_id = _required_string(raw_credential.get("id"), "npm credential id")
        if token_id in credential_ids:
            raise ValidationError(f"duplicate npm credential ID: {token_id}")
        credential_ids.add(token_id)
        for field in ("name", "created", "updated"):
            if field in raw_credential:
                _required_string(raw_credential[field], f"npm credential {token_id}.{field}")
        for field in ("readonly", "automation"):
            if field in raw_credential:
                _strict_bool(raw_credential[field], f"npm credential {token_id}.{field}")
        if "cidr_whitelist" in raw_credential:
            _string_array(
                raw_credential["cidr_whitelist"],
                f"npm credential {token_id}.cidr_whitelist",
            )

    packages = _required_list(inventory.get("packages"), "npm inventory packages")
    package_names: set[str] = set()
    for index, raw_package in enumerate(packages):
        package = _exact_fields(
            raw_package,
            {"name", "owners", "dist_tags"},
            f"npm package[{index}]",
        )
        package_name = _required_string(package.get("name"), f"npm package[{index}].name")
        if not _NPM_PACKAGE.fullmatch(package_name):
            raise ValidationError(f"invalid npm package name: {package_name!r}")
        if package_name in package_names:
            raise ValidationError(f"duplicate npm package: {package_name}")
        package_names.add(package_name)
        owners = _required_list(package.get("owners"), f"npm owners for {package_name}")
        owner_names: set[str] = set()
        for owner_index, raw_owner in enumerate(owners):
            owner = _exact_fields(
                raw_owner,
                {"name", "email"},
                f"npm owner[{owner_index}] for {package_name}",
            )
            owner_name = _required_string(owner.get("name"), f"npm owner for {package_name}")
            _required_string(owner.get("email"), f"npm owner email for {package_name}")
            if owner_name in owner_names:
                raise ValidationError(f"duplicate npm owner for {package_name}: {owner_name}")
            owner_names.add(owner_name)
        tags = package.get("dist_tags")
        if not isinstance(tags, dict) or not all(
            isinstance(name, str) and name and isinstance(version, str) and version
            for name, version in tags.items()
        ):
            raise ValidationError(f"npm dist_tags are invalid for {package_name}")


def _validate_aws_inventory(inventory: dict[str, Any]) -> None:
    _validate_inventory_common(
        inventory,
        adapter="aws-iam-read-only",
        fields={
            "schema_version",
            "adapter",
            "collected_at",
            "credential_handle",
            "subject",
            "partition",
            "roles",
            "limitations",
        },
    )
    subject = _exact_fields(
        inventory.get("subject"),
        {"account", "arn", "user_id"},
        "AWS inventory subject",
    )
    account = _required_string(subject.get("account"), "AWS inventory subject.account")
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ValidationError("AWS inventory account must contain 12 digits")
    _required_string(subject.get("arn"), "AWS inventory subject.arn")
    _required_string(subject.get("user_id"), "AWS inventory subject.user_id")
    partition = _required_string(inventory.get("partition"), "AWS inventory partition")
    if not subject["arn"].startswith(f"arn:{partition}:"):
        raise ValidationError("AWS subject ARN does not match the declared partition")
    roles = _required_list(inventory.get("roles"), "AWS inventory roles")
    role_names: set[str] = set()
    role_fields = {
        "name",
        "role_id",
        "arn",
        "path",
        "service_linked",
        "max_session_duration",
        "created_at",
        "last_used_at",
        "inline_policy_names",
        "attached_policies",
        "github_oidc_trust",
    }
    for index, raw_role in enumerate(roles):
        role = _exact_fields(raw_role, role_fields, f"AWS role[{index}]")
        role_name = _required_string(role.get("name"), f"AWS role[{index}].name")
        if not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", role_name):
            raise ValidationError(f"invalid AWS role name in inventory: {role_name!r}")
        if role_name in role_names:
            raise ValidationError(f"duplicate AWS role in inventory: {role_name}")
        role_names.add(role_name)
        _required_string(role.get("role_id"), f"AWS role {role_name}.role_id")
        arn = _required_string(role.get("arn"), f"AWS role {role_name}.arn")
        path = _required_string(role.get("path"), f"AWS role {role_name}.path")
        if not arn.startswith(f"arn:{partition}:") or not arn.endswith(
            f":iam::{account}:role{path}{role_name}"
        ):
            raise ValidationError(f"AWS role ARN does not match {role_name}")
        managed_role = path.startswith(
            (
                "/aws-service-role/",
                "/aws-reserved/sso.amazonaws.com/",
            )
        )
        if (
            _strict_bool(
                role.get("service_linked"),
                f"AWS role {role_name}.service_linked",
            )
            != managed_role
        ):
            raise ValidationError(f"AWS managed-role marker is inconsistent for {role_name}")
        duration = _nonnegative_integer(
            role.get("max_session_duration"),
            f"AWS role {role_name}.max_session_duration",
        )
        if not 3_600 <= duration <= 43_200:
            raise ValidationError(f"AWS role {role_name} max_session_duration is invalid")
        parse_rfc3339(role.get("created_at"), f"AWS role {role_name}.created_at")
        if role.get("last_used_at") is not None:
            parse_rfc3339(role.get("last_used_at"), f"AWS role {role_name}.last_used_at")
        _string_array(
            role.get("inline_policy_names"),
            f"AWS role {role_name}.inline_policy_names",
        )
        attached = _required_list(
            role.get("attached_policies"),
            f"AWS role {role_name}.attached_policies",
        )
        attached_arns: set[str] = set()
        for policy_index, raw_policy in enumerate(attached):
            policy = _exact_fields(
                raw_policy,
                {"name", "arn"},
                f"AWS attached policy[{policy_index}] for {role_name}",
            )
            _required_string(policy.get("name"), f"AWS attached policy name for {role_name}")
            policy_arn = _required_string(
                policy.get("arn"),
                f"AWS attached policy ARN for {role_name}",
            )
            if policy_arn in attached_arns:
                raise ValidationError(f"duplicate AWS attached policy for {role_name}")
            attached_arns.add(policy_arn)
        trusts = _required_list(
            role.get("github_oidc_trust"),
            f"AWS GitHub OIDC trust for {role_name}",
        )
        seen_trusts: set[str] = set()
        for trust_index, raw_trust in enumerate(trusts):
            trust = _exact_fields(
                raw_trust,
                {"providers", "conditions"},
                f"AWS GitHub OIDC trust[{trust_index}] for {role_name}",
            )
            _string_array(
                trust.get("providers"),
                f"AWS GitHub OIDC trust providers for {role_name}",
                allow_empty=False,
            )
            conditions = trust.get("conditions")
            if not isinstance(conditions, dict):
                raise ValidationError(f"AWS GitHub OIDC conditions are invalid for {role_name}")
            for key, values in conditions.items():
                _required_string(key, f"AWS GitHub OIDC condition key for {role_name}")
                _string_array(
                    values,
                    f"AWS GitHub OIDC condition {key} for {role_name}",
                    allow_empty=False,
                )
            trust_digest = digest_json(trust)
            if trust_digest in seen_trusts:
                raise ValidationError(f"duplicate AWS GitHub OIDC trust for {role_name}")
            seen_trusts.add(trust_digest)


def validate_provider_inventory(inventory: Any) -> dict[str, Any]:
    if not isinstance(inventory, dict):
        raise ValidationError("provider inventory must be an object")
    adapter = inventory.get("adapter")
    if adapter == "github-read-only":
        _validate_github_inventory(inventory)
    elif adapter == "npm-read-only":
        _validate_npm_inventory(inventory)
    elif adapter == "aws-iam-read-only":
        _validate_aws_inventory(inventory)
    else:
        raise ValidationError(f"unsupported inventory adapter: {adapter}")
    return inventory


def _candidate(
    *,
    candidate_id: str,
    provider: str,
    resource_kind: str,
    summary: str,
    assumption: str,
    mandatory: bool,
    source: dict[str, str],
    sink: dict[str, str],
    edge: dict[str, Any],
    source_digest: str,
    evidence_paths: list[str],
) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "provider": provider,
        "resource_kind": resource_kind,
        "summary": summary,
        "assumption": assumption,
        "mandatory": mandatory,
        "provenance": {
            "source_digest": source_digest,
            "evidence_paths": evidence_paths,
        },
        "nodes": [source, sink],
        "edge": edge,
    }


def _github_candidates(
    inventory: dict[str, Any],
    source_digest: str,
) -> tuple[list[dict[str, Any]], bool]:
    candidates: list[dict[str, Any]] = []
    subject = inventory.get("subject")
    if not isinstance(subject, dict):
        raise ValidationError("GitHub inventory subject must be an object")
    login = _required_string(subject.get("login"), "GitHub inventory subject.login")
    complete = True

    for repository_index, raw_repository in enumerate(
        _required_list(inventory.get("repositories"), "GitHub inventory repositories")
    ):
        if not isinstance(raw_repository, dict):
            raise ValidationError("each GitHub inventory repository must be an object")
        repository = _required_string(
            raw_repository.get("full_name"), "GitHub inventory repository.full_name"
        )
        if not _GITHUB_REPOSITORY.fullmatch(repository):
            raise ValidationError(f"invalid GitHub repository in inventory: {repository!r}")
        owner, name = repository.split("/", 1)
        sink = {
            "id": f"effect:github:{repository}:repository",
            "kind": "consequential_sink",
            "label": f"Consequential access to GitHub repository {repository}",
        }

        permissions = raw_repository.get("permissions", {})
        if not isinstance(permissions, dict):
            raise ValidationError(f"GitHub permissions for {repository} must be an object")
        consequential_permissions = [
            permission
            for permission in ("admin", "maintain", "push")
            if permissions.get(permission) is True
        ]
        if consequential_permissions:
            candidate_id = f"github:{repository}:subject-access"
            root = {
                "id": f"authority:github:{login}:{repository}",
                "kind": "credential_handle",
                "label": f"GitHub identity {login} access to {repository}",
            }
            candidates.append(
                _candidate(
                    candidate_id=candidate_id,
                    provider="github",
                    resource_kind="repository_access",
                    summary=(
                        f"Treat {login}'s {', '.join(consequential_permissions)} permission "
                        f"on {repository} as compromised authority"
                    ),
                    assumption=(
                        "The inventoried GitHub identity itself is compromised. closurectl "
                        "does not yet revoke that account, grant, or session."
                    ),
                    mandatory=False,
                    source=root,
                    sink=sink,
                    edge={
                        "id": candidate_id,
                        "source": root["id"],
                        "target": sink["id"],
                        "kind": "repository_access",
                        "label": f"{login} can change {repository}",
                        "revocable": False,
                        "cost": 1,
                    },
                    source_digest=source_digest,
                    evidence_paths=[
                        "/subject",
                        f"/repositories/{repository_index}/permissions",
                    ],
                )
            )

        for workflow_index, workflow in enumerate(
            _required_list(
                raw_repository.get("workflows", []),
                f"GitHub workflows for {repository}",
            )
        ):
            if not isinstance(workflow, dict):
                raise ValidationError(f"each GitHub workflow for {repository} must be an object")
            if workflow.get("state") != "active":
                continue
            workflow_id = _integer_id(workflow.get("id"), f"GitHub workflow ID for {repository}")
            workflow_name = _required_string(
                workflow.get("name") or workflow.get("path"),
                f"GitHub workflow name for {repository}",
            )
            candidate_id = f"github:{repository}:disable-workflow:{workflow_id}"
            root = {
                "id": f"authority:github:{repository}:workflow:{workflow_id}",
                "kind": "authority",
                "label": f"GitHub workflow {workflow_name}",
            }
            workflow_sink = {
                "id": f"effect:github:{repository}:workflow:{workflow_id}:execution",
                "kind": "consequential_sink",
                "label": f"Execution capability of GitHub workflow {workflow_name}",
            }
            candidates.append(
                _candidate(
                    candidate_id=candidate_id,
                    provider="github",
                    resource_kind="workflow",
                    summary=f"Disable active workflow {workflow_name} in {repository}",
                    assumption=(
                        "This workflow is compromised or can mint consequential authority. "
                        "Disabling it is an appropriate containment cut."
                    ),
                    mandatory=False,
                    source=root,
                    sink=workflow_sink,
                    edge={
                        "id": candidate_id,
                        "source": root["id"],
                        "target": workflow_sink["id"],
                        "kind": "can_mint",
                        "label": f"Disable compromised workflow {workflow_name}",
                        "revocable": True,
                        "cost": 1,
                        "enforcement": {
                            "provider": "github",
                            "operation": "disable_workflow",
                            "target": (f"github://{owner}/{name}/actions/workflows/{workflow_id}"),
                            "phase": "stop_minting",
                        },
                    },
                    source_digest=source_digest,
                    evidence_paths=[
                        f"/repositories/{repository_index}/full_name",
                        f"/repositories/{repository_index}/workflows/{workflow_index}",
                    ],
                )
            )

        for run_index, run in enumerate(
            _required_list(
                raw_repository.get("active_runs", []),
                f"GitHub active runs for {repository}",
            )
        ):
            if not isinstance(run, dict):
                raise ValidationError(f"each GitHub run for {repository} must be an object")
            run_id = _integer_id(run.get("id"), f"GitHub run ID for {repository}")
            run_name = _required_string(
                run.get("name") or f"run {run_id}", f"GitHub run name for {repository}"
            )
            candidate_id = f"github:{repository}:cancel-run:{run_id}"
            root = {
                "id": f"authority:github:{repository}:run:{run_id}",
                "kind": "pending_effect",
                "label": f"Active GitHub Actions run {run_name}",
            }
            run_sink = {
                "id": f"effect:github:{repository}:run:{run_id}:pending",
                "kind": "consequential_sink",
                "label": f"Pending declared effects of GitHub Actions run {run_name}",
            }
            candidates.append(
                _candidate(
                    candidate_id=candidate_id,
                    provider="github",
                    resource_kind="workflow_run",
                    summary=f"Cancel active run {run_name} ({run_id}) in {repository}",
                    assumption=(
                        "This active run is untrusted and may still commit a consequential effect."
                    ),
                    mandatory=False,
                    source=root,
                    sink=run_sink,
                    edge={
                        "id": candidate_id,
                        "source": root["id"],
                        "target": run_sink["id"],
                        "kind": "pending_effect",
                        "label": f"Cancel untrusted workflow run {run_id}",
                        "revocable": True,
                        "cost": 1,
                        "enforcement": {
                            "provider": "github",
                            "operation": "cancel_run",
                            "target": f"github://{owner}/{name}/actions/runs/{run_id}",
                            "phase": "cancel_pending",
                        },
                    },
                    source_digest=source_digest,
                    evidence_paths=[
                        f"/repositories/{repository_index}/full_name",
                        f"/repositories/{repository_index}/active_runs/{run_index}",
                    ],
                )
            )

        for key_index, deploy_key in enumerate(
            _required_list(
                raw_repository.get("deploy_keys", []),
                f"GitHub deploy keys for {repository}",
            )
        ):
            if not isinstance(deploy_key, dict):
                raise ValidationError(f"each deploy key for {repository} must be an object")
            key_id = _integer_id(deploy_key.get("id"), f"GitHub deploy key ID for {repository}")
            key_title = _required_string(
                deploy_key.get("title") or f"deploy key {key_id}",
                f"GitHub deploy key title for {repository}",
            )
            candidate_id = f"github:{repository}:deploy-key:{key_id}"
            root = {
                "id": f"authority:github:{repository}:deploy-key:{key_id}",
                "kind": "credential_handle",
                "label": f"GitHub deploy key {key_title}",
            }
            candidates.append(
                _candidate(
                    candidate_id=candidate_id,
                    provider="github",
                    resource_kind="deploy_key",
                    summary=f"Treat deploy key {key_title} on {repository} as compromised",
                    assumption=(
                        "The deploy key is compromised. The current release can inventory but "
                        "cannot revoke deploy keys, so selecting it must block closure."
                    ),
                    mandatory=False,
                    source=root,
                    sink=sink,
                    edge={
                        "id": candidate_id,
                        "source": root["id"],
                        "target": sink["id"],
                        "kind": "repository_access",
                        "label": f"Deploy key {key_title} can access {repository}",
                        "revocable": False,
                        "cost": 1,
                    },
                    source_digest=source_digest,
                    evidence_paths=[
                        f"/repositories/{repository_index}/full_name",
                        f"/repositories/{repository_index}/deploy_keys/{key_index}",
                    ],
                )
            )

        truncated_fields = [
            field
            for field in (
                "workflow_results_truncated",
                "run_results_truncated",
                "deploy_key_results_truncated",
            )
            if raw_repository.get(field) is True
        ]
        if truncated_fields:
            complete = False
            candidate_id = f"github:{repository}:inventory-gap"
            root = {
                "id": f"authority:github:{repository}:unobserved",
                "kind": "unknown_authority",
                "label": f"Unobserved GitHub authority in truncated inventory for {repository}",
            }
            candidates.append(
                _candidate(
                    candidate_id=candidate_id,
                    provider="github",
                    resource_kind="inventory_gap",
                    summary=f"Block closure because {repository} inventory was truncated",
                    assumption=(
                        "At least one relevant authority path may be outside the bounded inventory."
                    ),
                    mandatory=True,
                    source=root,
                    sink=sink,
                    edge={
                        "id": candidate_id,
                        "source": root["id"],
                        "target": sink["id"],
                        "kind": "unknown_authority",
                        "label": (
                            "Inventory is incomplete: " + ", ".join(sorted(truncated_fields))
                        ),
                        "revocable": False,
                        "cost": 1,
                    },
                    source_digest=source_digest,
                    evidence_paths=[
                        (f"/repositories/{repository_index}/{field}")
                        for field in sorted(truncated_fields)
                    ],
                )
            )

    return candidates, complete


def _npm_candidates(
    inventory: dict[str, Any],
    source_digest: str,
) -> tuple[list[dict[str, Any]], bool]:
    candidates: list[dict[str, Any]] = []
    registry = _required_string(inventory.get("registry"), "npm inventory registry").rstrip("/")
    try:
        parsed_registry = urllib.parse.urlsplit(registry)
    except ValueError as exc:
        raise ValidationError("npm inventory registry is invalid") from exc
    if parsed_registry.scheme != "https" or not parsed_registry.hostname:
        raise ValidationError("npm inventory registry must be HTTPS")
    executable_registry = registry == DEFAULT_REGISTRY
    registry_label = parsed_registry.hostname.lower()
    publication_sink = {
        "id": f"effect:npm:{registry_label}:publication",
        "kind": "consequential_sink",
        "label": f"Package publication through {registry_label}",
    }

    for credential_index, credential in enumerate(
        _required_list(
            inventory.get("credential_metadata"),
            "npm inventory credential_metadata",
        )
    ):
        if not isinstance(credential, dict):
            raise ValidationError("each npm credential metadata item must be an object")
        if credential.get("readonly") is True:
            continue
        token_id = _required_string(credential.get("id"), "npm credential id")
        candidate_id = f"npm:{registry_label}:revoke-token:{token_id}"
        root = {
            "id": f"authority:npm:{registry_label}:token:{token_id}",
            "kind": "credential_handle",
            "label": f"npm token handle {token_id}",
        }
        edge: dict[str, Any] = {
            "id": candidate_id,
            "source": root["id"],
            "target": publication_sink["id"],
            "kind": "can_publish",
            "label": f"Revoke npm token {token_id}",
            "revocable": executable_registry and bool(_NPM_TOKEN_ID.fullmatch(token_id)),
            "cost": 1,
        }
        if edge["revocable"]:
            edge["enforcement"] = {
                "provider": "npm",
                "operation": "revoke_token",
                "target": f"npm://registry.npmjs.org/tokens/{token_id}",
                "phase": "revoke_roots",
            }
        candidates.append(
            _candidate(
                candidate_id=candidate_id,
                provider="npm",
                resource_kind="token",
                summary=f"Revoke npm token handle {token_id}",
                assumption=(
                    "The selected token is compromised and may publish consequential packages. "
                    + (
                        "The exact token ID is executable against registry.npmjs.org."
                        if edge["revocable"]
                        else "This registry or token ID is not executable by the current release."
                    )
                ),
                mandatory=False,
                source=root,
                sink=publication_sink,
                edge=edge,
                source_digest=source_digest,
                evidence_paths=[f"/credential_metadata/{credential_index}"],
            )
        )

    for package_index, package in enumerate(
        _required_list(inventory.get("packages"), "npm inventory packages")
    ):
        if not isinstance(package, dict):
            raise ValidationError("each npm inventory package must be an object")
        package_name = _required_string(package.get("name"), "npm package name")
        package_sink = {
            "id": f"effect:npm:{registry_label}:package:{package_name}",
            "kind": "consequential_sink",
            "label": f"Publication authority for npm package {package_name}",
        }
        for owner_index, owner in enumerate(
            _required_list(package.get("owners"), f"npm owners for {package_name}")
        ):
            if not isinstance(owner, dict):
                raise ValidationError(f"each npm owner for {package_name} must be an object")
            owner_name = _required_string(owner.get("name"), f"npm owner for {package_name}")
            candidate_id = f"npm:{registry_label}:owner:{owner_name}:package:{package_name}"
            root = {
                "id": f"authority:npm:{registry_label}:owner:{owner_name}",
                "kind": "identity",
                "label": f"npm owner {owner_name}",
            }
            candidates.append(
                _candidate(
                    candidate_id=candidate_id,
                    provider="npm",
                    resource_kind="package_owner",
                    summary=f"Treat npm owner {owner_name} for {package_name} as compromised",
                    assumption=(
                        "The npm account itself is compromised. closurectl does not yet remove "
                        "owners or recover npm accounts, so selecting it must block closure."
                    ),
                    mandatory=False,
                    source=root,
                    sink=package_sink,
                    edge={
                        "id": candidate_id,
                        "source": root["id"],
                        "target": package_sink["id"],
                        "kind": "can_publish",
                        "label": f"{owner_name} can publish {package_name}",
                        "revocable": False,
                        "cost": 1,
                    },
                    source_digest=source_digest,
                    evidence_paths=[
                        f"/packages/{package_index}/name",
                        f"/packages/{package_index}/owners/{owner_index}",
                    ],
                )
            )

    return candidates, True


def _aws_candidates(
    inventory: dict[str, Any],
    source_digest: str,
) -> tuple[list[dict[str, Any]], bool]:
    candidates: list[dict[str, Any]] = []
    subject = inventory.get("subject")
    if not isinstance(subject, dict):
        raise ValidationError("AWS inventory subject must be an object")
    account = _required_string(subject.get("account"), "AWS inventory subject.account")
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ValidationError("AWS inventory account must contain 12 digits")
    partition = _required_string(inventory.get("partition"), "AWS inventory partition")

    for role_index, role in enumerate(
        _required_list(inventory.get("roles"), "AWS inventory roles")
    ):
        if not isinstance(role, dict):
            raise ValidationError("each AWS inventory role must be an object")
        role_name = _required_string(role.get("name"), "AWS inventory role.name")
        if not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", role_name):
            raise ValidationError(f"invalid AWS role name in inventory: {role_name!r}")
        service_linked = role.get("service_linked")
        if not isinstance(service_linked, bool):
            raise ValidationError("AWS inventory role.service_linked must be true or false")
        executable = partition == "aws" and not service_linked
        sink = {
            "id": f"effect:aws:{account}:role:{role_name}",
            "kind": "consequential_sink",
            "label": f"Consequential authority through AWS role {role_name}",
        }
        root = {
            "id": f"authority:aws:{account}:role-sessions:{role_name}",
            "kind": "temporary_credentials",
            "label": f"Existing sessions for AWS role {role_name}",
        }
        candidate_id = f"aws:{account}:revoke-role-sessions:{role_name}"
        edge: dict[str, Any] = {
            "id": candidate_id,
            "source": root["id"],
            "target": sink["id"],
            "kind": "derived_session",
            "label": f"Revoke older sessions for AWS role {role_name}",
            "revocable": executable,
            "cost": 1,
        }
        if executable:
            edge["enforcement"] = {
                "provider": "aws",
                "operation": "revoke_role_sessions",
                "target": f"aws://{account}/iam/roles/{role_name}",
                "phase": "revoke_descendants",
            }
        candidates.append(
            _candidate(
                candidate_id=candidate_id,
                provider="aws",
                resource_kind="role_sessions",
                summary=f"Revoke existing sessions for AWS role {role_name}",
                assumption=(
                    "Existing role sessions are compromised and every minting path has been "
                    "stopped separately. This action denies all sessions issued before the "
                    "recorded cutoff, not one individual session. "
                    + (
                        "The exact standard-partition role is executable."
                        if executable
                        else "This service-linked or non-standard-partition role is not executable."
                    )
                ),
                mandatory=False,
                source=root,
                sink=sink,
                edge=edge,
                source_digest=source_digest,
                evidence_paths=[f"/roles/{role_index}"],
            )
        )

        trusts = _required_list(
            role.get("github_oidc_trust", []),
            f"AWS GitHub OIDC trust for {role_name}",
        )
        for index, trust in enumerate(trusts, start=1):
            if not isinstance(trust, dict):
                raise ValidationError(f"AWS GitHub OIDC trust for {role_name} must be an object")
            trust_id = f"aws:{account}:github-oidc-trust:{role_name}:{index}"
            trust_root = {
                "id": f"authority:aws:{account}:github-oidc:{role_name}:{index}",
                "kind": "can_mint",
                "label": f"GitHub OIDC trust that can assume AWS role {role_name}",
            }
            candidates.append(
                _candidate(
                    candidate_id=trust_id,
                    provider="aws",
                    resource_kind="github_oidc_trust",
                    summary=f"Declare the GitHub OIDC trust for {role_name} as an open minting path",
                    assumption=(
                        "The trust policy itself still lets attacker-controlled GitHub context "
                        "mint new role sessions. closurectl inventories but does not rewrite AWS "
                        "trust policies, so selecting this path must block closure."
                    ),
                    mandatory=False,
                    source=trust_root,
                    sink=sink,
                    edge={
                        "id": trust_id,
                        "source": trust_root["id"],
                        "target": sink["id"],
                        "kind": "can_mint",
                        "label": f"GitHub OIDC can mint sessions for {role_name}",
                        "revocable": False,
                        "cost": 1,
                    },
                    source_digest=source_digest,
                    evidence_paths=[f"/roles/{role_index}/github_oidc_trust/{index - 1}"],
                )
            )

    return candidates, True


def incident_draft_payload(draft: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in draft.items() if key != "draft_digest"}


def create_incident_draft(
    title: str,
    inventories: Iterable[dict[str, Any]],
    *,
    now: Callable[[], str] = utc_now,
) -> dict[str, Any]:
    """Convert bounded inventories into review candidates, never directly into a graph."""
    normalized_title = _required_string(title, "incident title")
    created_at = now()
    created_time = parse_rfc3339(created_at, "incident draft created_at")
    candidates: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    seen_resources: set[tuple[str, ...]] = set()
    limitations = [
        "Inventory metadata proposes paths; it does not prove compromise or causality.",
        "No candidate enters the authority graph without explicit selection.",
        "Mandatory inventory-gap candidates cannot be deselected and force BLOCKED.",
    ]

    for inventory in inventories:
        if not isinstance(inventory, dict):
            raise ValidationError("each inventory must be an object")
        if inventory.get("schema_version") != "1":
            raise ValidationError("inventory schema_version must be '1'")
        adapter = _required_string(inventory.get("adapter"), "inventory adapter")
        source_digest = digest_json(inventory)
        if adapter == "github-read-only":
            _validate_github_inventory(inventory)
            resource_keys = [
                ("github", repository["full_name"]) for repository in inventory["repositories"]
            ]
            proposed, complete = _github_candidates(inventory, source_digest)
        elif adapter == "npm-read-only":
            _validate_npm_inventory(inventory)
            registry = inventory["registry"].rstrip("/")
            resource_keys = [
                ("npm-token", registry, credential["id"])
                for credential in inventory["credential_metadata"]
            ] + [("npm-package", registry, package["name"]) for package in inventory["packages"]]
            proposed, complete = _npm_candidates(inventory, source_digest)
        elif adapter == "aws-iam-read-only":
            _validate_aws_inventory(inventory)
            account = inventory["subject"]["account"]
            resource_keys = [("aws-role", account, role["name"]) for role in inventory["roles"]]
            proposed, complete = _aws_candidates(inventory, source_digest)
        else:
            raise ValidationError(f"unsupported inventory adapter: {adapter}")
        collected_at = _required_string(
            inventory.get("collected_at"),
            "inventory collected_at",
        )
        collected_time = parse_rfc3339(collected_at, "inventory collected_at")
        age = (created_time - collected_time).total_seconds()
        if age < -30:
            raise ValidationError("inventory collected_at is in the future")
        if age > INVENTORY_MAX_AGE_SECONDS:
            raise ValidationError(f"inventory is older than {INVENTORY_MAX_AGE_SECONDS} seconds")
        for resource_key in resource_keys:
            if resource_key in seen_resources:
                raise ValidationError(
                    "inventories contain duplicate or conflicting resources: "
                    + ":".join(resource_key)
                )
            seen_resources.add(resource_key)
        candidates.extend(proposed)
        sources.append(
            {
                "adapter": adapter,
                "collected_at": collected_at,
                "artifact_digest": source_digest,
                "complete": complete,
            }
        )

    candidates.sort(key=lambda item: item["candidate_id"])
    sources.sort(key=lambda item: (item["adapter"], item["artifact_digest"]))
    candidate_ids = [item["candidate_id"] for item in candidates]
    if not candidates:
        raise ValidationError("inventories did not produce any incident candidates")
    if len(candidates) > MAX_DRAFT_CANDIDATES:
        raise ValidationError(
            f"incident draft exceeds the {MAX_DRAFT_CANDIDATES}-candidate safety limit"
        )
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValidationError("inventories produced duplicate incident candidate IDs")

    draft = {
        "schema_version": INCIDENT_DRAFT_SCHEMA_VERSION,
        "title": normalized_title,
        "created_at": created_at,
        "sources": sources,
        "candidates": candidates,
        "limitations": limitations,
    }
    draft["draft_digest"] = digest_json(draft)
    return validate_incident_draft(draft)


def validate_incident_draft(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("incident draft must be an object")
    required = {
        "schema_version",
        "title",
        "created_at",
        "sources",
        "candidates",
        "limitations",
        "draft_digest",
    }
    missing = required - value.keys()
    unknown = value.keys() - required
    if missing:
        raise ValidationError(f"incident draft is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(f"incident draft has unknown fields: {', '.join(sorted(unknown))}")
    if value.get("schema_version") != INCIDENT_DRAFT_SCHEMA_VERSION:
        raise ValidationError("unsupported incident draft schema")
    _required_string(value.get("title"), "incident draft title")
    parse_rfc3339(value.get("created_at"), "incident draft created_at")
    sources = _required_list(value.get("sources"), "incident draft sources")
    candidates = _required_list(value.get("candidates"), "incident draft candidates")
    limitations = _required_list(value.get("limitations"), "incident draft limitations")
    if not sources:
        raise ValidationError("incident draft must contain at least one source")
    if not candidates:
        raise ValidationError("incident draft must contain at least one candidate")
    if len(candidates) > MAX_DRAFT_CANDIDATES:
        raise ValidationError("incident draft contains too many candidates")
    if not all(isinstance(item, str) and item for item in limitations):
        raise ValidationError("incident draft limitations must be non-empty strings")

    source_digests: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "adapter",
            "collected_at",
            "artifact_digest",
            "complete",
        }:
            raise ValidationError("incident draft source has invalid fields")
        _required_string(source.get("adapter"), "incident source adapter")
        parse_rfc3339(source.get("collected_at"), "incident source collected_at")
        digest = _required_string(source.get("artifact_digest"), "incident source digest")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValidationError("incident source digest must be a lowercase SHA-256 digest")
        if not isinstance(source.get("complete"), bool):
            raise ValidationError("incident source complete must be true or false")
        source_digests.add(digest)
    if len(source_digests) != len(sources):
        raise ValidationError("incident draft contains duplicate inventory sources")

    candidate_ids: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != {
            "candidate_id",
            "provider",
            "resource_kind",
            "summary",
            "assumption",
            "mandatory",
            "provenance",
            "nodes",
            "edge",
        }:
            raise ValidationError("incident draft candidate has invalid fields")
        candidate_id = _required_string(candidate.get("candidate_id"), "candidate ID")
        if candidate_id in candidate_ids:
            raise ValidationError("incident draft candidate IDs must be unique")
        candidate_ids.add(candidate_id)
        _required_string(candidate.get("provider"), "candidate provider")
        _required_string(candidate.get("resource_kind"), "candidate resource_kind")
        _required_string(candidate.get("summary"), "candidate summary")
        _required_string(candidate.get("assumption"), "candidate assumption")
        if not isinstance(candidate.get("mandatory"), bool):
            raise ValidationError("candidate mandatory must be true or false")
        provenance = candidate.get("provenance")
        if not isinstance(provenance, dict) or set(provenance) != {
            "source_digest",
            "evidence_paths",
        }:
            raise ValidationError("candidate provenance has invalid fields")
        source_digest = _required_string(
            provenance.get("source_digest"),
            "candidate provenance source_digest",
        )
        if source_digest not in source_digests:
            raise ValidationError("candidate provenance references an unknown source digest")
        evidence_paths = _string_array(
            provenance.get("evidence_paths"),
            "candidate provenance evidence_paths",
            allow_empty=False,
        )
        if not all(re.fullmatch(r"(?:/(?:[^~/]|~[01])*)+", path) for path in evidence_paths):
            raise ValidationError("candidate evidence paths must be RFC 6901 JSON Pointers")
        nodes = _required_list(candidate.get("nodes"), "candidate nodes")
        if len(nodes) != 2:
            raise ValidationError("each candidate must contain exactly two nodes")
        parsed_nodes = [Node.from_dict(node) for node in nodes]
        if parsed_nodes[0].id == parsed_nodes[1].id:
            raise ValidationError("candidate source and sink nodes must be distinct")
        edge = Edge.from_dict(candidate.get("edge"))
        if edge.id != candidate_id:
            raise ValidationError("candidate edge ID must equal candidate_id")
        if edge.source != parsed_nodes[0].id or edge.target != parsed_nodes[1].id:
            raise ValidationError("candidate edge endpoints must match candidate nodes")

    supplied_digest = _required_string(value.get("draft_digest"), "incident draft digest")
    if not re.fullmatch(r"[a-f0-9]{64}", supplied_digest):
        raise ValidationError("incident draft digest must be a lowercase SHA-256 digest")
    if supplied_digest != digest_json(incident_draft_payload(value)):
        raise ValidationError("draft_digest does not match incident draft contents")
    return value


def build_authority_graph(
    draft: dict[str, Any],
    selected_candidate_ids: Iterable[str],
    confirmation: str,
) -> AuthorityGraph:
    """Build a graph only from exact, digest-confirmed human selections."""
    validated = validate_incident_draft(draft)
    if confirmation != validated["draft_digest"]:
        raise ValidationError("incident graph build requires the exact draft digest")
    selected = {_required_string(item, "selected candidate ID") for item in selected_candidate_ids}
    by_id = {candidate["candidate_id"]: candidate for candidate in validated["candidates"]}
    unknown = selected - by_id.keys()
    if unknown:
        raise ValidationError(f"unknown incident candidates: {', '.join(sorted(unknown))}")
    selected.update(
        candidate["candidate_id"] for candidate in validated["candidates"] if candidate["mandatory"]
    )
    if not selected:
        raise ValidationError("select at least one incident candidate")

    nodes: dict[str, dict[str, str]] = {}
    edges: list[dict[str, Any]] = []
    roots: set[str] = set()
    sinks: set[str] = set()
    for candidate_id in sorted(selected):
        candidate = by_id[candidate_id]
        source, sink = candidate["nodes"]
        for node in (source, sink):
            existing = nodes.get(node["id"])
            if existing is not None and existing != node:
                raise ValidationError(f"conflicting incident node definition: {node['id']}")
            nodes[node["id"]] = node
        edges.append(candidate["edge"])
        roots.add(source["id"])
        sinks.add(sink["id"])

    return AuthorityGraph.from_dict(
        {
            "schema_version": "1",
            "title": validated["title"],
            "nodes": [nodes[node_id] for node_id in sorted(nodes)],
            "edges": edges,
            "roots": sorted(roots),
            "sinks": sorted(sinks),
        }
    )
