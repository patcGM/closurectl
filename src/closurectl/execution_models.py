"""Strict models for opt-in live provider execution."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .errors import ValidationError
from .models import PlanAction
from .serialization import digest_json

EXECUTION_SCHEMA_VERSION = "1"
PREVIEW_TTL_SECONDS = 900

_REPOSITORY_PART = re.compile(r"^[A-Za-z0-9_.-]+$")
_NUMERIC_ID = re.compile(r"^[1-9][0-9]*$")
_NPM_TOKEN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{3,199}$")
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)

OPERATION_PHASES = {
    ("github", "disable_workflow"): "stop_minting",
    ("github", "cancel_run"): "cancel_pending",
    ("npm", "revoke_token"): "revoke_roots",
}


def parse_rfc3339(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise ValidationError(f"{field} must be an RFC 3339 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ExecutionTarget:
    provider: str
    operation: str
    resource_uri: str
    account: str
    repository: str = ""
    resource_kind: str = ""
    resource_id: str = ""

    def to_dict(self) -> dict[str, str]:
        result = {
            "provider": self.provider,
            "operation": self.operation,
            "resource_uri": self.resource_uri,
            "account": self.account,
            "resource_kind": self.resource_kind,
            "resource_id": self.resource_id,
        }
        if self.repository:
            result["repository"] = self.repository
        return result


def parse_execution_target(action: PlanAction) -> ExecutionTarget:
    expected_phase = OPERATION_PHASES.get((action.provider, action.operation))
    if expected_phase is None:
        supported = ", ".join(
            f"{provider}.{operation}" for provider, operation in sorted(OPERATION_PHASES)
        )
        raise ValidationError(
            f"action {action.action_id!r} is not executable; supported operations: {supported}"
        )
    if action.phase != expected_phase:
        raise ValidationError(
            f"action {action.action_id!r} must use phase {expected_phase!r} "
            f"for {action.provider}.{action.operation}"
        )

    try:
        parsed = urllib.parse.urlsplit(action.target)
    except ValueError as exc:
        raise ValidationError(f"invalid execution target for {action.action_id!r}") from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValidationError(f"invalid execution target port for {action.action_id!r}") from exc
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValidationError("execution target must not contain credentials, query, or fragment")
    if port is not None:
        raise ValidationError("execution target must not contain a port")

    if action.provider == "github":
        if parsed.scheme != "github" or not parsed.hostname:
            raise ValidationError(
                "GitHub targets must use github://OWNER/REPO/actions/{workflows|runs}/NUMERIC_ID"
            )
        owner = parsed.netloc
        parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
        if (
            len(parts) != 4
            or parts[1] != "actions"
            or parts[2] not in {"workflows", "runs"}
            or not _REPOSITORY_PART.fullmatch(owner)
            or not _REPOSITORY_PART.fullmatch(parts[0])
            or not _NUMERIC_ID.fullmatch(parts[3])
            or owner in {".", ".."}
            or parts[0] in {".", ".."}
        ):
            raise ValidationError(
                "GitHub targets must use github://OWNER/REPO/actions/{workflows|runs}/NUMERIC_ID"
            )
        kind = parts[2]
        expected_kind = "workflows" if action.operation == "disable_workflow" else "runs"
        if kind != expected_kind:
            raise ValidationError(f"{action.operation} requires a GitHub {expected_kind} target")
        repository = f"{owner}/{parts[0]}"
        canonical = f"github://{repository}/actions/{kind}/{parts[3]}"
        if action.target != canonical:
            raise ValidationError(f"GitHub execution target must be canonical: {canonical}")
        return ExecutionTarget(
            provider="github",
            operation=action.operation,
            resource_uri=action.target,
            account=owner,
            repository=repository,
            resource_kind=kind[:-1],
            resource_id=parts[3],
        )

    if (
        parsed.scheme != "npm"
        or parsed.hostname is None
        or parsed.hostname.lower() != "registry.npmjs.org"
    ):
        raise ValidationError("npm targets must use npm://registry.npmjs.org/tokens/FULL_TOKEN_ID")
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if len(parts) != 2 or parts[0] != "tokens" or not _NPM_TOKEN_ID.fullmatch(parts[1]):
        raise ValidationError("npm targets must use npm://registry.npmjs.org/tokens/FULL_TOKEN_ID")
    canonical = f"npm://registry.npmjs.org/tokens/{parts[1]}"
    if action.target != canonical:
        raise ValidationError(f"npm execution target must be canonical: {canonical}")
    return ExecutionTarget(
        provider="npm",
        operation=action.operation,
        resource_uri=action.target,
        account=parsed.hostname.lower(),
        resource_kind="token",
        resource_id=parts[1],
    )


def preview_payload(preview: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in preview.items() if key != "preview_digest"}


def validate_preview_shape(preview: Any) -> dict[str, Any]:
    if not isinstance(preview, dict):
        raise ValidationError("execution preview must be an object")
    required = {
        "schema_version",
        "created_at",
        "expires_at",
        "graph_digest",
        "plan_digest",
        "actions",
        "preview_digest",
    }
    missing = required - preview.keys()
    unknown = preview.keys() - required
    if missing:
        raise ValidationError(f"execution preview is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(f"execution preview has unknown fields: {', '.join(sorted(unknown))}")
    if preview["schema_version"] != EXECUTION_SCHEMA_VERSION:
        raise ValidationError("unsupported execution preview schema")
    created = parse_rfc3339(preview["created_at"], "preview.created_at")
    expires = parse_rfc3339(preview["expires_at"], "preview.expires_at")
    if expires <= created:
        raise ValidationError("preview.expires_at must be after preview.created_at")
    if expires - created != timedelta(seconds=PREVIEW_TTL_SECONDS):
        raise ValidationError(
            f"execution previews must expire after exactly {PREVIEW_TTL_SECONDS} seconds"
        )
    for field in ("graph_digest", "plan_digest", "preview_digest"):
        if not isinstance(preview[field], str) or not re.fullmatch(r"[a-f0-9]{64}", preview[field]):
            raise ValidationError(f"preview.{field} must be a lowercase SHA-256 digest")
    if not isinstance(preview["actions"], list):
        raise ValidationError("preview.actions must be an array")
    supplied = preview["preview_digest"]
    if supplied != digest_json(preview_payload(preview)):
        raise ValidationError("preview_digest does not match preview contents")
    return preview
