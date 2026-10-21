"""Preview, journal, execute, resume, and independent observation flows."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .errors import ExecutionError, ValidationError
from .execution_models import (
    EXECUTION_SCHEMA_VERSION,
    PREVIEW_TTL_SECONDS,
    parse_execution_target,
    parse_rfc3339,
    validate_preview_shape,
)
from .executors.base import ProviderExecutor
from .models import AuthorityGraph, ClosurePlan, PlanAction
from .receipts import utc_now
from .serialization import digest_json, parse_json_text, reject_secret_fields

TERMINAL_STATES = {"VERIFIED", "FAILED", "INDETERMINATE"}


def _isoformat(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _executor_for(
    executors: Mapping[str, ProviderExecutor], action: PlanAction
) -> ProviderExecutor:
    executor = executors.get(action.provider)
    if executor is None:
        raise ExecutionError(f"no executor is configured for provider {action.provider!r}")
    return executor


def create_execution_preview(
    graph: AuthorityGraph,
    plan: ClosurePlan,
    executors: Mapping[str, ProviderExecutor],
    *,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    if plan.graph_digest != graph.digest:
        raise ValidationError("plan graph_digest does not match the supplied graph")
    if plan.status != "PLANNED":
        raise ExecutionError("a BLOCKED closure plan cannot be executed")
    created = now().astimezone(timezone.utc)
    actions: list[dict[str, Any]] = []
    for action in plan.actions:
        target = parse_execution_target(action)
        provider_preview = _executor_for(executors, action).preview(action, target)
        required_provider_fields = {
            "provider_account",
            "api_origin",
            "mutation_identity",
            "observer_identity",
            "current_state",
            "effect",
            "resource",
        }
        if provider_preview.keys() != required_provider_fields:
            raise ExecutionError("provider preview returned an unsafe or incomplete shape")
        if not all(
            isinstance(provider_preview[field], str) and provider_preview[field]
            for field in required_provider_fields - {"resource"}
        ) or not isinstance(provider_preview["resource"], dict):
            raise ExecutionError("provider preview contains invalid metadata")
        actions.append(
            {
                "action_id": action.action_id,
                "edge_id": action.edge_id,
                "provider": action.provider,
                "operation": action.operation,
                "phase": action.phase,
                "target": action.target,
                "target_details": target.to_dict(),
                **provider_preview,
            }
        )
    preview: dict[str, Any] = {
        "schema_version": EXECUTION_SCHEMA_VERSION,
        "created_at": _isoformat(created),
        "expires_at": _isoformat(created + timedelta(seconds=PREVIEW_TTL_SECONDS)),
        "graph_digest": graph.digest,
        "plan_digest": plan.digest,
        "actions": actions,
    }
    reject_secret_fields(preview)
    preview["preview_digest"] = digest_json(preview)
    return preview


def validate_execution_preview(
    preview: Any,
    graph: AuthorityGraph,
    plan: ClosurePlan,
    *,
    require_fresh: bool,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    validated = validate_preview_shape(preview)
    if validated["graph_digest"] != graph.digest:
        raise ValidationError("preview graph_digest does not match the supplied graph")
    if validated["plan_digest"] != plan.digest:
        raise ValidationError("preview plan_digest does not match the supplied plan")
    created = parse_rfc3339(validated["created_at"], "preview.created_at")
    if require_fresh:
        current = now().astimezone(timezone.utc)
        expires = parse_rfc3339(validated["expires_at"], "preview.expires_at")
        if created > current + timedelta(seconds=30):
            raise ExecutionError("execution preview creation time is in the future")
        if current >= expires:
            raise ExecutionError("execution preview has expired; generate a new preview")
    if len(validated["actions"]) != len(plan.actions):
        raise ValidationError("preview action count does not match the plan")
    action_fields = {
        "action_id",
        "edge_id",
        "provider",
        "operation",
        "phase",
        "target",
        "target_details",
        "provider_account",
        "api_origin",
        "mutation_identity",
        "observer_identity",
        "current_state",
        "effect",
        "resource",
    }
    for expected, actual in zip(plan.actions, validated["actions"], strict=True):
        if not isinstance(actual, dict) or actual.keys() != action_fields:
            raise ValidationError("preview action has an invalid shape")
        string_fields = action_fields - {"target_details", "resource"}
        if not all(isinstance(actual[field], str) and actual[field] for field in string_fields):
            raise ValidationError("preview action metadata must be non-empty strings")
        if not isinstance(actual["resource"], dict):
            raise ValidationError("preview action resource must be an object")
        for field in ("action_id", "edge_id", "provider", "operation", "phase", "target"):
            if actual[field] != getattr(expected, field):
                raise ValidationError(f"preview action {field} does not match the plan")
        target = parse_execution_target(expected)
        if actual["target_details"] != target.to_dict():
            raise ValidationError("preview target details do not match the plan")
        if expected.provider == "aws":
            planned_cutoff = actual["resource"].get("planned_cutoff")
            cutoff = parse_rfc3339(planned_cutoff, "preview AWS planned_cutoff")
            cutoff_delay = (cutoff - created).total_seconds()
            if not PREVIEW_TTL_SECONDS + 15 <= cutoff_delay <= PREVIEW_TTL_SECONDS + 60:
                raise ValidationError(
                    "AWS planned cutoff must be 15 to 60 seconds after preview expiry"
                )
    return validated


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in event.items() if key != "event_digest"}


def read_execution_journal(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.exists():
        return []
    events: list[dict[str, Any]] = []
    previous = ""
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ExecutionError(f"cannot read execution journal: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ValidationError("execution journal is not valid UTF-8") from exc
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            raise ValidationError(f"execution journal has a blank line at {index}")
        event = parse_json_text(line, source=f"execution journal line {index}")
        if not isinstance(event, dict):
            raise ValidationError(f"execution journal line {index} must be an object")
        required = {
            "schema_version",
            "sequence",
            "at",
            "preview_digest",
            "plan_digest",
            "action_id",
            "phase",
            "operation",
            "target",
            "state",
            "summary",
            "reference",
            "previous_event_digest",
            "event_digest",
        }
        if event.keys() != required:
            raise ValidationError(f"execution journal line {index} has an invalid shape")
        string_fields = required - {"sequence"}
        if not all(isinstance(event[field], str) for field in string_fields):
            raise ValidationError(f"execution journal types are invalid at line {index}")
        if (
            event["schema_version"] != EXECUTION_SCHEMA_VERSION
            or type(event["sequence"]) is not int
            or event["sequence"] != index
        ):
            raise ValidationError(f"execution journal sequence is invalid at line {index}")
        if event["previous_event_digest"] != previous:
            raise ValidationError(f"execution journal hash chain is invalid at line {index}")
        parse_rfc3339(event["at"], f"journal[{index}].at")
        if event["state"] not in {"PREVIEWED", "REQUESTED", "RECONCILING", *TERMINAL_STATES}:
            raise ValidationError(f"execution journal state is invalid at line {index}")
        if event["event_digest"] != digest_json(_event_payload(event)):
            raise ValidationError(f"execution journal digest is invalid at line {index}")
        reject_secret_fields(event)
        previous = event["event_digest"]
        events.append(event)
    return events


def _append_event(
    path: str | Path,
    events: list[dict[str, Any]],
    preview: dict[str, Any],
    action: PlanAction,
    state: str,
    summary: str,
    reference: str = "",
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "schema_version": EXECUTION_SCHEMA_VERSION,
        "sequence": len(events) + 1,
        "at": utc_now(),
        "preview_digest": preview["preview_digest"],
        "plan_digest": preview["plan_digest"],
        "action_id": action.action_id,
        "phase": action.phase,
        "operation": f"{action.provider}.{action.operation}",
        "target": action.target,
        "state": state,
        "summary": summary,
        "reference": reference,
        "previous_event_digest": events[-1]["event_digest"] if events else "",
    }
    reject_secret_fields(event)
    event["event_digest"] = digest_json(event)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise ExecutionError(f"cannot append execution journal: {path}") from exc
    events.append(event)
    return event


def _latest_action_events(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {event["action_id"]: event for event in events}


def _requested_at(events: list[dict[str, Any]], action_id: str) -> str | None:
    return next(
        (
            event["at"]
            for event in events
            if event["action_id"] == action_id and event["state"] == "REQUESTED"
        ),
        None,
    )


def _assert_journal_binding(
    events: list[dict[str, Any]], preview: dict[str, Any], plan: ClosurePlan
) -> None:
    actions = {action.action_id: action for action in plan.actions}
    action_order = {action.action_id: index for index, action in enumerate(plan.actions)}
    latest: dict[str, str] = {}
    transitions = {
        None: {"PREVIEWED"},
        "PREVIEWED": {"REQUESTED"},
        "REQUESTED": {"RECONCILING"},
        "RECONCILING": {*TERMINAL_STATES, "RECONCILING"},
        "INDETERMINATE": {"RECONCILING"},
        "VERIFIED": set(),
        "FAILED": set(),
    }
    for event in events:
        if event["preview_digest"] != preview["preview_digest"]:
            raise ValidationError("journal contains an event for a different preview")
        if event["plan_digest"] != plan.digest:
            raise ValidationError("journal contains an event for a different plan")
        action = actions.get(event["action_id"])
        if action is None:
            raise ValidationError("journal references an unknown action")
        if (
            event["phase"] != action.phase
            or event["operation"] != f"{action.provider}.{action.operation}"
            or event["target"] != action.target
        ):
            raise ValidationError("journal event does not match its plan action")
        previous_state = latest.get(action.action_id)
        if event["state"] not in transitions[previous_state]:
            raise ValidationError(
                f"invalid journal transition for {action.action_id}: "
                f"{previous_state or 'START'} -> {event['state']}"
            )
        if previous_state is None:
            for earlier in plan.actions[: action_order[action.action_id]]:
                if latest.get(earlier.action_id) != "VERIFIED":
                    raise ValidationError("journal starts a later action before earlier closure")
        latest[action.action_id] = event["state"]


@contextmanager
def _journal_lock(path: str | Path):
    lock_path = Path(f"{path}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ExecutionError(
                f"another execution process holds the journal lock: {lock_path}"
            ) from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _apply_execution_locked(
    graph: AuthorityGraph,
    plan: ClosurePlan,
    preview: dict[str, Any],
    confirmation: str,
    journal_path: str | Path,
    executors: Mapping[str, ProviderExecutor],
    *,
    resume: bool = False,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    validated = validate_execution_preview(preview, graph, plan, require_fresh=not resume, now=now)
    if confirmation != validated["preview_digest"]:
        raise ExecutionError("confirmation digest does not match the execution preview")
    events = read_execution_journal(journal_path)
    _assert_journal_binding(events, validated, plan)
    if resume and not events:
        raise ExecutionError("resume requires a non-empty execution journal")
    if not resume and events:
        raise ExecutionError("journal already contains events; use execute resume")
    latest = _latest_action_events(events)

    for action, preview_action in zip(plan.actions, validated["actions"], strict=True):
        target = parse_execution_target(action)
        executor = _executor_for(executors, action)
        if executor.api_origin != preview_action["api_origin"]:
            raise ExecutionError(
                f"configured API origin changed after preview for {action.action_id}"
            )
        prior = latest.get(action.action_id)
        requested_at = _requested_at(events, action.action_id)
        if prior is not None:
            current_binding = executor.binding(action, target)
            expected_binding = {
                key: preview_action[key]
                for key in (
                    "provider_account",
                    "api_origin",
                    "mutation_identity",
                    "observer_identity",
                )
            }
            if current_binding != expected_binding:
                raise ExecutionError(
                    f"provider or credential identity changed after preview for {action.action_id}"
                )
        if prior and prior["state"] == "VERIFIED":
            if resume:
                if requested_at is None:
                    raise ValidationError("verified journal action has no REQUESTED event")
                revalidated = executor.reconcile(
                    action,
                    target,
                    preview_action=preview_action,
                    requested_at=requested_at,
                )
                if revalidated.state != "VERIFIED":
                    raise ExecutionError(
                        f"journal success no longer reconciles for {action.action_id}: "
                        f"{revalidated.summary}"
                    )
            continue
        if prior and prior["state"] in {"FAILED"}:
            break

        if prior is None:
            if resume:
                break
            validator = getattr(executor, "validate_confirmed_preview", None)
            if callable(validator):
                validator(action, target, preview_action)
            else:
                current = executor.preview(action, target)
                expected = {
                    key: preview_action[key]
                    for key in (
                        "provider_account",
                        "api_origin",
                        "mutation_identity",
                        "observer_identity",
                        "current_state",
                        "effect",
                        "resource",
                    )
                }
                if current != expected:
                    raise ExecutionError(
                        f"provider state changed after preview for {action.action_id}; "
                        "generate a new preview"
                    )
            _append_event(
                journal_path,
                events,
                validated,
                action,
                "PREVIEWED",
                "fresh provider state matched the confirmed preview",
            )
            requested = _append_event(
                journal_path,
                events,
                validated,
                action,
                "REQUESTED",
                "mutation request started; reconcile before any retry",
            )
            result = executor.apply(
                action,
                target,
                preview_action=preview_action,
                requested_at=requested["at"],
            )
        else:
            if prior["state"] == "PREVIEWED":
                break
            if requested_at is None:
                raise ValidationError("journal action has no REQUESTED event")
            result = executor.reconcile(
                action,
                target,
                preview_action=preview_action,
                requested_at=requested_at,
            )

        _append_event(
            journal_path,
            events,
            validated,
            action,
            "RECONCILING",
            "provider state reconciliation completed",
            result.reference,
        )
        terminal = _append_event(
            journal_path,
            events,
            validated,
            action,
            result.state,
            result.summary,
            result.reference,
        )
        latest[action.action_id] = terminal
        if result.state != "VERIFIED":
            break

    latest = _latest_action_events(events)
    verified = sum(
        latest.get(action.action_id, {}).get("state") == "VERIFIED" for action in plan.actions
    )
    unresolved = [
        action.action_id
        for action in plan.actions
        if latest.get(action.action_id, {}).get("state") != "VERIFIED"
    ]
    return {
        "preview_digest": validated["preview_digest"],
        "plan_digest": plan.digest,
        "verified_actions": verified,
        "total_actions": len(plan.actions),
        "complete": not unresolved,
        "unresolved_actions": unresolved,
        "journal": str(Path(journal_path).resolve()),
    }


def apply_execution(
    graph: AuthorityGraph,
    plan: ClosurePlan,
    preview: dict[str, Any],
    confirmation: str,
    journal_path: str | Path,
    executors: Mapping[str, ProviderExecutor],
    *,
    resume: bool = False,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    with _journal_lock(journal_path):
        return _apply_execution_locked(
            graph,
            plan,
            preview,
            confirmation,
            journal_path,
            executors,
            resume=resume,
            now=now,
        )


def observe_execution(
    graph: AuthorityGraph,
    plan: ClosurePlan,
    preview: dict[str, Any],
    journal_path: str | Path,
    executors: Mapping[str, ProviderExecutor],
) -> dict[str, Any]:
    validated = validate_execution_preview(preview, graph, plan, require_fresh=False)
    events = read_execution_journal(journal_path)
    _assert_journal_binding(events, validated, plan)
    observations: list[dict[str, str]] = []
    for action in plan.actions:
        requested_at = _requested_at(events, action.action_id)
        target = parse_execution_target(action)
        executor = _executor_for(executors, action)
        preview_action = next(
            item for item in validated["actions"] if item["action_id"] == action.action_id
        )
        if executor.api_origin != preview_action["api_origin"]:
            raise ExecutionError(
                f"configured API origin changed after preview for {action.action_id}"
            )
        result = executor.observe(
            action,
            target,
            requested_at=requested_at,
            preview_action=preview_action,
        )
        status = result.status
        summary = result.summary
        if (
            result.observer_identity != preview_action["observer_identity"]
            or result.provider_account != preview_action["provider_account"]
            or result.api_origin != preview_action["api_origin"]
        ):
            status = "INDETERMINATE"
            summary = (
                "Observer identity, provider account, or API origin differs "
                "from the confirmed preview"
            )
        observations.append(
            {
                "action_id": action.action_id,
                "status": status,
                "checked_at": utc_now(),
                "summary": summary,
                "reference": result.reference,
                "provider": action.provider,
                "operation": action.operation,
                "target": action.target,
                "provider_account": result.provider_account,
                "observer_identity": result.observer_identity,
                "api_origin": result.api_origin,
                "probe_type": result.probe_type,
            }
        )
    observations.sort(key=lambda item: item["action_id"])
    return {
        "schema_version": "2",
        "plan_digest": plan.digest,
        "observations": observations,
    }
