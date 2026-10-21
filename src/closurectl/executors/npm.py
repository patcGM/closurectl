"""Exact npm token revocation with an independent recovery configuration."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from ..adapters.npm import DEFAULT_REGISTRY, _registry_url, _run_npm, _safe_token_metadata
from ..errors import AdapterError, ExecutionError
from ..execution_models import ExecutionTarget, parse_rfc3339
from ..models import PlanAction
from .base import ApplyResult, ObservationResult

NPM_PROPAGATION_SECONDS = 3_600


def _credential_material(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ExecutionError(f"cannot read npm userconfig: {path}") from exc
    credentials: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        normalized_key = key.strip().lower()
        if normalized_key != "//registry.npmjs.org/:_authtoken":
            continue
        credential = value.strip().strip("\"'")
        if not credential or "${" in credential:
            raise ExecutionError(
                "npm lab userconfigs must contain literal, non-empty credential values"
            )
        fingerprint = hashlib.sha256(credential.encode("utf-8")).hexdigest()
        credentials[fingerprint] = credential
    if not credentials:
        raise ExecutionError(f"npm userconfig has no explicit registry credential: {path}")
    if len(credentials) != 1:
        raise ExecutionError("npm userconfig must contain exactly one registry credential")
    return credentials


class NpmExecutor:
    provider = "npm"

    def __init__(
        self,
        mutation_userconfig: str | Path,
        recovery_userconfig: str | Path,
        *,
        registry: str = DEFAULT_REGISTRY,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._mutation_config = Path(mutation_userconfig).resolve()
        self._recovery_config = Path(recovery_userconfig).resolve()
        if self._mutation_config == self._recovery_config:
            raise ExecutionError("npm mutation and recovery userconfig paths must be different")
        mutation_credentials = _credential_material(self._mutation_config)
        recovery_credentials = _credential_material(self._recovery_config)
        if mutation_credentials.keys() & recovery_credentials.keys():
            raise ExecutionError(
                "npm mutation and recovery userconfigs must not share credential material"
            )
        self._mutation_fingerprint, self._mutation_credential = next(
            iter(mutation_credentials.items())
        )
        self._recovery_fingerprint, self._recovery_credential = next(
            iter(recovery_credentials.items())
        )
        self._registry = _registry_url(registry)
        if self._registry != DEFAULT_REGISTRY:
            raise ExecutionError("npm mutation supports only https://registry.npmjs.org")
        self._now = now

    @property
    def api_origin(self) -> str:
        return self._registry

    @staticmethod
    def _username(raw: Any) -> str:
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        if isinstance(raw, dict):
            candidate = raw.get("username", raw.get("name"))
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        raise ExecutionError("npm whoami returned an unexpected identity")

    def _whoami(self, config: Path) -> str:
        raw = _run_npm(
            ["whoami", "--json", f"--registry={self._registry}"],
            userconfig=config,
        )
        return self._username(raw)

    def _tokens(self, config: Path) -> list[dict[str, Any]]:
        return _safe_token_metadata(self._raw_tokens(config))

    def _raw_tokens(self, config: Path) -> list[dict[str, Any]]:
        raw = _run_npm(
            ["token", "list", "--json", f"--registry={self._registry}"],
            userconfig=config,
        )
        candidates = raw.get("objects", raw.get("tokens", [])) if isinstance(raw, dict) else raw
        if not isinstance(candidates, list) or not all(
            isinstance(item, dict) for item in candidates
        ):
            raise ExecutionError("npm token list returned an unexpected shape")
        return candidates

    def _target_present(self, target: ExecutionTarget) -> bool:
        return any(
            str(item.get("id")) == target.resource_id
            for item in self._tokens(self._recovery_config)
        )

    def preview(self, action: PlanAction, target: ExecutionTarget) -> dict[str, Any]:
        binding = self.binding(action, target)
        target_metadata = next(
            (
                item
                for item in self._raw_tokens(self._recovery_config)
                if str(item.get("id")) == target.resource_id
            ),
            None,
        )
        if target_metadata is None:
            raise ExecutionError("the exact npm token ID is not visible to the recovery identity")
        partial = target_metadata.get("token", target_metadata.get("key"))
        if not isinstance(partial, str):
            raise ExecutionError(
                "npm did not expose enough partial token metadata to prevent recovery lockout"
            )
        visible_parts = [
            part.strip() for part in re.split(r"(?:\.{3}|…|\*+)", partial) if part.strip()
        ]
        if sum(len(part) for part in visible_parts) < 6:
            raise ExecutionError(
                "npm partial token metadata is too short to prevent recovery lockout"
            )
        if len(visible_parts) == 1:
            matches_recovery = self._recovery_credential.startswith(
                visible_parts[0]
            ) or self._recovery_credential.endswith(visible_parts[0])
        else:
            matches_recovery = self._recovery_credential.startswith(
                visible_parts[0]
            ) and self._recovery_credential.endswith(visible_parts[-1])
        if matches_recovery:
            raise ExecutionError("refusing to revoke the credential used by the recovery config")
        return {
            **binding,
            "current_state": "present",
            "effect": "revoke this exact npm token",
            "resource": {
                "id": target.resource_id,
                "registry": self._registry,
            },
        }

    def binding(self, action: PlanAction, target: ExecutionTarget) -> dict[str, str]:
        del action, target
        mutation_identity = self._whoami(self._mutation_config)
        recovery_identity = self._whoami(self._recovery_config)
        if mutation_identity != recovery_identity:
            raise ExecutionError(
                "npm mutation and recovery configs must authenticate the same account"
            )
        return {
            "provider_account": mutation_identity,
            "api_origin": self._registry,
            "mutation_identity": (
                f"npm:{mutation_identity}:credential:SHA256:{self._mutation_fingerprint}"
            ),
            "observer_identity": (
                f"npm:{recovery_identity}:credential:SHA256:{self._recovery_fingerprint}"
            ),
        }

    def apply(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        preview_action: Mapping[str, Any] | None = None,
        requested_at: str = "",
    ) -> ApplyResult:
        del action, preview_action, requested_at
        try:
            if not self._target_present(target):
                return ApplyResult(
                    "VERIFIED",
                    "npm token was already absent for the recovery identity",
                    target.resource_uri,
                )
        except AdapterError as exc:
            return ApplyResult(
                "INDETERMINATE",
                f"npm pre-mutation reconciliation failed: {exc}",
                target.resource_uri,
            )

        try:
            _run_npm(
                [
                    "token",
                    "revoke",
                    target.resource_id,
                    f"--registry={self._registry}",
                ],
                userconfig=self._mutation_config,
                expect_json=False,
                allow_otp=True,
            )
        except AdapterError as exc:
            try:
                still_present = self._target_present(target)
            except AdapterError:
                still_present = True
            if still_present:
                return ApplyResult(
                    "INDETERMINATE",
                    f"npm revoke outcome is unknown and the token is still listed: {exc}",
                    target.resource_uri,
                )
            return ApplyResult(
                "VERIFIED",
                "npm command was interrupted but recovery reconciliation shows the token absent",
                target.resource_uri,
            )

        try:
            still_present = self._target_present(target)
        except AdapterError as exc:
            return ApplyResult(
                "INDETERMINATE",
                f"npm revoke returned success but reconciliation failed: {exc}",
                target.resource_uri,
            )
        if still_present:
            return ApplyResult(
                "INDETERMINATE",
                "npm token remains listed; registry propagation may still be in progress",
                target.resource_uri,
            )
        return ApplyResult(
            "VERIFIED",
            "npm token is absent for the recovery identity",
            target.resource_uri,
        )

    def reconcile(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        preview_action: Mapping[str, Any] | None = None,
        requested_at: str = "",
    ) -> ApplyResult:
        del action, preview_action, requested_at
        try:
            present = self._target_present(target)
        except AdapterError as exc:
            return ApplyResult(
                "INDETERMINATE",
                f"npm reconciliation failed: {exc}",
                target.resource_uri,
            )
        if present:
            return ApplyResult(
                "INDETERMINATE",
                "npm token is still listed; mutation was not repeated",
                target.resource_uri,
            )
        return ApplyResult(
            "VERIFIED",
            "npm token is absent for the recovery identity",
            target.resource_uri,
        )

    def observe(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        requested_at: str | None,
        preview_action: Mapping[str, Any] | None = None,
    ) -> ObservationResult:
        del action, preview_action
        try:
            observer = self._whoami(self._recovery_config)
            present = self._target_present(target)
        except (AdapterError, ExecutionError) as exc:
            return ObservationResult(
                "INDETERMINATE",
                f"independent npm observation failed: {exc}",
                target.resource_uri,
                f"npm:unknown:credential:SHA256:{self._recovery_fingerprint}",
                "registry.npmjs.org",
                self._registry,
                "npm-token-list",
            )
        if present:
            status = "STILL_OPEN"
            summary = "npm token remains visible to the recovery identity"
        elif requested_at is None:
            status = "INDETERMINATE"
            summary = "npm token is absent but the mutation time is unavailable"
        else:
            requested = parse_rfc3339(requested_at, "journal.requested_at")
            age = (self._now().astimezone(timezone.utc) - requested).total_seconds()
            if age < NPM_PROPAGATION_SECONDS:
                status = "INDETERMINATE"
                summary = "npm token is absent but the one-hour propagation window has not elapsed"
            else:
                status = "VERIFIED_CLOSED"
                summary = "npm token remains absent after the propagation window"
        return ObservationResult(
            status,
            summary,
            target.resource_uri,
            f"npm:{observer}:credential:SHA256:{self._recovery_fingerprint}",
            observer,
            self._registry,
            "npm-token-list",
        )
