"""Human-confirmed authority-graph drafts built from provider inventories."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable, Iterable
from typing import Any

from .adapters.npm import DEFAULT_REGISTRY
from .errors import ValidationError
from .models import AuthorityGraph, Edge, Node
from .receipts import utc_now
from .serialization import digest_json

INCIDENT_DRAFT_SCHEMA_VERSION = "1"
MAX_DRAFT_CANDIDATES = 2_000

_GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_NPM_TOKEN_ID = re.compile(r"^[A-Za-z0-9._-]{4,200}$")


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
) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "provider": provider,
        "resource_kind": resource_kind,
        "summary": summary,
        "assumption": assumption,
        "mandatory": mandatory,
        "nodes": [source, sink],
        "edge": edge,
    }


def _github_candidates(inventory: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    candidates: list[dict[str, Any]] = []
    subject = inventory.get("subject")
    if not isinstance(subject, dict):
        raise ValidationError("GitHub inventory subject must be an object")
    login = _required_string(subject.get("login"), "GitHub inventory subject.login")
    complete = True

    for raw_repository in _required_list(
        inventory.get("repositories"), "GitHub inventory repositories"
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
                )
            )

        for workflow in _required_list(
            raw_repository.get("workflows", []), f"GitHub workflows for {repository}"
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
                    sink=sink,
                    edge={
                        "id": candidate_id,
                        "source": root["id"],
                        "target": sink["id"],
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
                )
            )

        for run in _required_list(
            raw_repository.get("active_runs", []), f"GitHub active runs for {repository}"
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
                    sink=sink,
                    edge={
                        "id": candidate_id,
                        "source": root["id"],
                        "target": sink["id"],
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
                )
            )

        for deploy_key in _required_list(
            raw_repository.get("deploy_keys", []), f"GitHub deploy keys for {repository}"
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
                )
            )

    return candidates, complete


def _npm_candidates(inventory: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
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

    for credential in _required_list(
        inventory.get("credential_metadata"), "npm inventory credential_metadata"
    ):
        if not isinstance(credential, dict):
            raise ValidationError("each npm credential metadata item must be an object")
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
            )
        )

    for package in _required_list(inventory.get("packages"), "npm inventory packages"):
        if not isinstance(package, dict):
            raise ValidationError("each npm inventory package must be an object")
        package_name = _required_string(package.get("name"), "npm package name")
        package_sink = {
            "id": f"effect:npm:{registry_label}:package:{package_name}",
            "kind": "consequential_sink",
            "label": f"Publication authority for npm package {package_name}",
        }
        for owner in _required_list(package.get("owners"), f"npm owners for {package_name}"):
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
                )
            )

    return candidates, True


def _aws_candidates(inventory: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    candidates: list[dict[str, Any]] = []
    subject = inventory.get("subject")
    if not isinstance(subject, dict):
        raise ValidationError("AWS inventory subject must be an object")
    account = _required_string(subject.get("account"), "AWS inventory subject.account")
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ValidationError("AWS inventory account must contain 12 digits")
    partition = _required_string(inventory.get("partition"), "AWS inventory partition")

    for role in _required_list(inventory.get("roles"), "AWS inventory roles"):
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
                "target": (f"aws://{account}/iam/roles/{urllib.parse.quote(role_name, safe='')}"),
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
    candidates: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
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
        if adapter == "github-read-only":
            proposed, complete = _github_candidates(inventory)
        elif adapter == "npm-read-only":
            proposed, complete = _npm_candidates(inventory)
        elif adapter == "aws-iam-read-only":
            proposed, complete = _aws_candidates(inventory)
        else:
            raise ValidationError(f"unsupported inventory adapter: {adapter}")
        candidates.extend(proposed)
        sources.append(
            {
                "adapter": adapter,
                "collected_at": _required_string(
                    inventory.get("collected_at"), "inventory collected_at"
                ),
                "artifact_digest": digest_json(inventory),
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
        "created_at": now(),
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
    _required_string(value.get("created_at"), "incident draft created_at")
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
        _required_string(source.get("collected_at"), "incident source collected_at")
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
