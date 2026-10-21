"""Provider executor interfaces and secret-free result types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from ..execution_models import ExecutionTarget
from ..models import PlanAction


@dataclass(frozen=True)
class ApplyResult:
    state: str
    summary: str
    reference: str


@dataclass(frozen=True)
class ObservationResult:
    status: str
    summary: str
    reference: str
    observer_identity: str
    provider_account: str
    api_origin: str
    probe_type: str


class ProviderExecutor(Protocol):
    provider: str

    @property
    def api_origin(self) -> str:
        """Return the configured provider API origin without making a request."""

    def preview(self, action: PlanAction, target: ExecutionTarget) -> dict[str, Any]:
        """Return allow-listed current state and actor identities."""

    def binding(self, action: PlanAction, target: ExecutionTarget) -> dict[str, str]:
        """Return provider and credential identities without inspecting target state."""

    def apply(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        preview_action: Mapping[str, Any] | None = None,
        requested_at: str = "",
    ) -> ApplyResult:
        """Request one exact mutation and reconcile its result."""

    def reconcile(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        preview_action: Mapping[str, Any] | None = None,
        requested_at: str = "",
    ) -> ApplyResult:
        """Read provider state without repeating a mutation."""

    def observe(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        requested_at: str | None,
        preview_action: Mapping[str, Any] | None = None,
    ) -> ObservationResult:
        """Observe closure using credentials independent of the mutation identity."""
