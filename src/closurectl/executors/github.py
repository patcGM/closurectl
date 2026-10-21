"""Narrow, reconciled GitHub Actions mutations."""

from __future__ import annotations

import time
import urllib.parse
from typing import Any, Callable, Mapping

from ..adapters.github import GitHubClient
from ..errors import AdapterError, ExecutionError
from ..execution_models import ExecutionTarget
from ..models import PlanAction
from .base import ApplyResult, ObservationResult


def _identity(client: GitHubClient) -> tuple[str, int]:
    body = client.get("/user").body
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("login"), str)
        or isinstance(body.get("id"), bool)
        or not isinstance(body.get("id"), int)
    ):
        raise ExecutionError("GitHub /user returned an incomplete identity")
    return body["login"], body["id"]


class GitHubExecutor:
    provider = "github"

    def __init__(
        self,
        mutation_credential: str,
        observer_credential: str,
        *,
        api_url: str = "https://api.github.com",
        reconcile_attempts: int = 5,
        reconcile_interval: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not observer_credential:
            raise ExecutionError(
                "CLOSURECTL_GITHUB_OBSERVER_TOKEN is required for independent observation"
            )
        if mutation_credential == observer_credential:
            raise ExecutionError("GitHub mutation and observer credentials must be different")
        self._mutation = GitHubClient(mutation_credential, api_url=api_url)
        self._observer = GitHubClient(observer_credential, api_url=api_url)
        self._attempts = max(1, reconcile_attempts)
        self._interval = max(0.0, reconcile_interval)
        self._sleep = sleep

    @property
    def api_origin(self) -> str:
        return self._mutation.api_url

    @staticmethod
    def _path(target: ExecutionTarget) -> str:
        owner, repository = target.repository.split("/", 1)
        encoded = f"{urllib.parse.quote(owner)}/{urllib.parse.quote(repository)}"
        plural = "workflows" if target.resource_kind == "workflow" else "runs"
        return f"/repos/{encoded}/actions/{plural}/{target.resource_id}"

    @staticmethod
    def _safe_resource(target: ExecutionTarget, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ExecutionError("GitHub returned an unexpected resource shape")
        if target.resource_kind == "workflow":
            if str(body.get("id")) != target.resource_id or not isinstance(body.get("state"), str):
                raise ExecutionError("GitHub workflow identity/state does not match the target")
            return {
                "id": body["id"],
                "name": str(body.get("name", "")),
                "path": str(body.get("path", "")),
                "state": body["state"],
            }
        if str(body.get("id")) != target.resource_id or not isinstance(body.get("status"), str):
            raise ExecutionError("GitHub run identity/state does not match the target")
        return {
            "id": body["id"],
            "workflow_id": body.get("workflow_id"),
            "run_attempt": body.get("run_attempt"),
            "head_sha": str(body.get("head_sha", "")),
            "status": body["status"],
            "conclusion": body.get("conclusion"),
        }

    def preview(self, action: PlanAction, target: ExecutionTarget) -> dict[str, Any]:
        binding = self.binding(action, target)
        resource = self._safe_resource(target, self._mutation.get(self._path(target)).body)
        current_state = (
            str(resource["state"])
            if target.resource_kind == "workflow"
            else f"{resource['status']}:{resource.get('conclusion') or ''}".rstrip(":")
        )
        effect = (
            "disable this exact workflow"
            if action.operation == "disable_workflow"
            else "cancel this exact workflow run"
        )
        return {
            **binding,
            "current_state": current_state,
            "effect": effect,
            "resource": resource,
        }

    def binding(self, action: PlanAction, target: ExecutionTarget) -> dict[str, str]:
        del action
        mutation_login, mutation_id = _identity(self._mutation)
        observer_login, observer_id = _identity(self._observer)
        if mutation_id == observer_id:
            raise ExecutionError(
                "GitHub observer must be a different account to preserve break-glass access"
            )
        return {
            "provider_account": target.repository,
            "api_origin": self._mutation.api_url,
            "mutation_identity": f"github:{mutation_login}#{mutation_id}",
            "observer_identity": f"github:{observer_login}#{observer_id}",
        }

    def _reconcile(self, target: ExecutionTarget) -> ApplyResult:
        path = self._path(target)
        last_summary = "GitHub state did not converge before the reconciliation deadline"
        for attempt in range(self._attempts):
            try:
                resource = self._safe_resource(target, self._mutation.get(path).body)
            except (AdapterError, ExecutionError) as exc:
                last_summary = f"GitHub reconciliation was inconclusive: {exc}"
            else:
                if target.resource_kind == "workflow":
                    if resource["state"] == "disabled_manually":
                        return ApplyResult("VERIFIED", "workflow is disabled", path)
                    last_summary = f"workflow remains {resource['state']}"
                else:
                    if resource["status"] == "completed" and resource["conclusion"] == "cancelled":
                        return ApplyResult("VERIFIED", "workflow run is cancelled", path)
                    if resource["status"] == "completed":
                        return ApplyResult(
                            "FAILED",
                            f"workflow run completed as {resource['conclusion'] or 'unknown'}",
                            path,
                        )
                    last_summary = f"workflow run remains {resource['status']}"
            if attempt + 1 < self._attempts:
                self._sleep(self._interval)
        return ApplyResult("INDETERMINATE", last_summary, path)

    def apply(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        preview_action: Mapping[str, Any] | None = None,
        requested_at: str = "",
    ) -> ApplyResult:
        del preview_action, requested_at
        path = self._path(target)
        try:
            resource = self._safe_resource(target, self._mutation.get(path).body)
        except (AdapterError, ExecutionError) as exc:
            return ApplyResult("INDETERMINATE", f"pre-mutation check failed: {exc}", path)

        if target.resource_kind == "workflow":
            if resource["state"] == "disabled_manually":
                return ApplyResult("VERIFIED", "workflow was already disabled", path)
            try:
                self._mutation.put(f"{path}/disable", accepted_statuses=(204,))
            except AdapterError as exc:
                return ApplyResult(
                    "INDETERMINATE",
                    f"workflow disable outcome is unknown: {exc}",
                    path,
                )
            return self._reconcile(target)

        if resource["status"] == "completed":
            if resource["conclusion"] == "cancelled":
                return ApplyResult("VERIFIED", "workflow run was already cancelled", path)
            return ApplyResult(
                "FAILED",
                f"workflow run already completed as {resource['conclusion'] or 'unknown'}",
                path,
            )
        try:
            self._mutation.post(f"{path}/cancel", accepted_statuses=(202, 409))
        except AdapterError as exc:
            return ApplyResult(
                "INDETERMINATE",
                f"workflow cancellation outcome is unknown: {exc}",
                path,
            )
        return self._reconcile(target)

    def reconcile(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        preview_action: Mapping[str, Any] | None = None,
        requested_at: str = "",
    ) -> ApplyResult:
        del action, preview_action, requested_at
        return self._reconcile(target)

    def observe(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        requested_at: str | None,
        preview_action: Mapping[str, Any] | None = None,
    ) -> ObservationResult:
        del requested_at, preview_action
        path = self._path(target)
        try:
            resource = self._safe_resource(target, self._observer.get(path).body)
            observer_login, observer_id = _identity(self._observer)
        except (AdapterError, ExecutionError) as exc:
            return ObservationResult(
                "INDETERMINATE",
                f"independent GitHub observation failed: {exc}",
                path,
                "github:independent-observer",
                target.repository,
                self._observer.api_url,
                "github-actions-state",
            )
        if target.resource_kind == "workflow":
            closed = resource["state"] == "disabled_manually"
            summary = f"workflow state is {resource['state']}"
        else:
            closed = resource["status"] == "completed" and resource["conclusion"] == "cancelled"
            summary = (
                f"workflow run state is {resource['status']}:{resource['conclusion'] or 'none'}"
            )
        return ObservationResult(
            "VERIFIED_CLOSED" if closed else "STILL_OPEN",
            summary,
            path,
            f"github:{observer_login}#{observer_id}",
            target.repository,
            self._observer.api_url,
            "github-actions-state",
        )
