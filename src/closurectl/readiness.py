"""Read-only break-glass readiness checks for live provider containment."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import Any, Callable

from .errors import ClosureCtlError, ValidationError
from .executors.github import GitHubExecutor
from .executors.npm import NpmExecutor

READINESS_PROVIDERS = ("github", "npm")


def _required_environment(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise ValidationError(f"set {name} before checking readiness")
    return value


def _github_readiness(environment: Mapping[str, str]) -> dict[str, Any]:
    executor = GitHubExecutor(
        _required_environment(environment, "GITHUB_TOKEN"),
        _required_environment(environment, "CLOSURECTL_GITHUB_OBSERVER_TOKEN"),
        api_url=environment.get("GITHUB_API_URL", "https://api.github.com"),
    )
    return executor.readiness()


def _npm_readiness(environment: Mapping[str, str]) -> dict[str, Any]:
    executor = NpmExecutor(
        _required_environment(environment, "CLOSURECTL_NPM_MUTATION_USERCONFIG"),
        _required_environment(environment, "CLOSURECTL_NPM_RECOVERY_USERCONFIG"),
        registry=environment.get("CLOSURECTL_NPM_REGISTRY", "https://registry.npmjs.org"),
    )
    return executor.readiness()


_CHECKS: dict[str, Callable[[Mapping[str, str]], dict[str, Any]]] = {
    "github": _github_readiness,
    "npm": _npm_readiness,
}


def assess_readiness(
    providers: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Check selected credentials without reading or mutating an incident target."""
    selected = list(providers)
    if not selected:
        raise ValidationError("select at least one readiness provider")
    if len(selected) != len(set(selected)):
        raise ValidationError("readiness providers must be unique")
    unknown = [provider for provider in selected if provider not in READINESS_PROVIDERS]
    if unknown:
        raise ValidationError(f"unsupported readiness provider: {unknown[0]}")

    current_environment = os.environ if environment is None else environment
    results: list[dict[str, Any]] = []
    for provider in selected:
        try:
            details = _CHECKS[provider](current_environment)
        except ClosureCtlError as exc:
            results.append(
                {
                    "provider": provider,
                    "status": "NOT_READY",
                    "error": str(exc),
                }
            )
        else:
            results.append(
                {
                    "provider": provider,
                    "status": "READY",
                    **details,
                }
            )

    ready = all(result["status"] == "READY" for result in results)
    return {
        "status": "READY" if ready else "NOT_READY",
        "providers": results,
    }
