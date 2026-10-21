"""Validated data models for authority graphs and closure plans."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .errors import ValidationError
from .serialization import digest_json

SCHEMA_VERSION = "1"
ALLOWED_PHASES = {
    "stop_minting": 10,
    "cancel_pending": 20,
    "revoke_descendants": 30,
    "revoke_roots": 40,
    "verify_sinks": 50,
}


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return value.strip()


def _require_exact_fields(
    value: dict[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    context: str,
) -> None:
    optional = optional or set()
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise ValidationError(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")


def _sha256_digest(value: Any, field: str) -> str:
    digest = _required_string(value, field)
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return digest


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    label: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Node":
        if not isinstance(value, dict):
            raise ValidationError("each node must be an object")
        _require_exact_fields(value, required={"id", "kind", "label"}, context="node")
        return cls(
            id=_required_string(value.get("id"), "node.id"),
            kind=_required_string(value.get("kind"), "node.kind"),
            label=_required_string(value.get("label"), "node.label"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "label": self.label}


@dataclass(frozen=True)
class Enforcement:
    provider: str
    operation: str
    target: str
    phase: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Enforcement":
        if not isinstance(value, dict):
            raise ValidationError("revocable edges require an enforcement object")
        _require_exact_fields(
            value,
            required={"provider", "operation", "target", "phase"},
            context="enforcement",
        )
        phase = _required_string(value.get("phase"), "enforcement.phase")
        if phase not in ALLOWED_PHASES:
            allowed = ", ".join(sorted(ALLOWED_PHASES))
            raise ValidationError(f"enforcement.phase must be one of: {allowed}")
        return cls(
            provider=_required_string(value.get("provider"), "enforcement.provider"),
            operation=_required_string(value.get("operation"), "enforcement.operation"),
            target=_required_string(value.get("target"), "enforcement.target"),
            phase=phase,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "operation": self.operation,
            "target": self.target,
            "phase": self.phase,
        }


@dataclass(frozen=True)
class Edge:
    id: str
    source: str
    target: str
    kind: str
    label: str
    revocable: bool
    cost: int
    enforcement: Enforcement | None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Edge":
        if not isinstance(value, dict):
            raise ValidationError("each edge must be an object")
        _require_exact_fields(
            value,
            required={
                "id",
                "source",
                "target",
                "kind",
                "label",
                "revocable",
                "cost",
            },
            optional={"enforcement"},
            context="edge",
        )
        revocable = value.get("revocable")
        if not isinstance(revocable, bool):
            raise ValidationError("edge.revocable must be true or false")
        raw_cost = value.get("cost", 1)
        if isinstance(raw_cost, bool) or not isinstance(raw_cost, int):
            raise ValidationError("edge.cost must be an integer")
        if raw_cost < 1 or raw_cost > 1_000_000:
            raise ValidationError("edge.cost must be between 1 and 1,000,000")
        raw_enforcement = value.get("enforcement")
        if revocable and raw_enforcement is None:
            raise ValidationError("revocable edges require enforcement metadata")
        if not revocable and raw_enforcement is not None:
            raise ValidationError("non-revocable edges must not declare enforcement")
        return cls(
            id=_required_string(value.get("id"), "edge.id"),
            source=_required_string(value.get("source"), "edge.source"),
            target=_required_string(value.get("target"), "edge.target"),
            kind=_required_string(value.get("kind"), "edge.kind"),
            label=_required_string(value.get("label"), "edge.label"),
            revocable=revocable,
            cost=raw_cost,
            enforcement=(
                Enforcement.from_dict(raw_enforcement) if raw_enforcement is not None else None
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "label": self.label,
            "revocable": self.revocable,
            "cost": self.cost,
        }
        if self.enforcement:
            result["enforcement"] = self.enforcement.to_dict()
        return result


@dataclass(frozen=True)
class AuthorityGraph:
    title: str
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    roots: tuple[str, ...]
    sinks: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AuthorityGraph":
        if not isinstance(value, dict):
            raise ValidationError("authority graph must be an object")
        _require_exact_fields(
            value,
            required={"schema_version", "title", "nodes", "edges", "roots", "sinks"},
            context="authority graph",
        )
        if value.get("schema_version") != SCHEMA_VERSION:
            raise ValidationError(f"schema_version must be {SCHEMA_VERSION!r}")
        raw_nodes = value.get("nodes")
        raw_edges = value.get("edges")
        raw_roots = value.get("roots")
        raw_sinks = value.get("sinks")
        if not isinstance(raw_nodes, list) or not raw_nodes:
            raise ValidationError("nodes must be a non-empty array")
        if not isinstance(raw_edges, list):
            raise ValidationError("edges must be an array")
        if not isinstance(raw_roots, list) or not raw_roots:
            raise ValidationError("roots must be a non-empty array")
        if not isinstance(raw_sinks, list) or not raw_sinks:
            raise ValidationError("sinks must be a non-empty array")

        nodes = tuple(Node.from_dict(item) for item in raw_nodes)
        edges = tuple(Edge.from_dict(item) for item in raw_edges)
        roots = tuple(_required_string(item, "root") for item in raw_roots)
        sinks = tuple(_required_string(item, "sink") for item in raw_sinks)

        node_ids = [node.id for node in nodes]
        edge_ids = [edge.id for edge in edges]
        if len(node_ids) != len(set(node_ids)):
            raise ValidationError("node IDs must be unique")
        if len(edge_ids) != len(set(edge_ids)):
            raise ValidationError("edge IDs must be unique")
        if len(roots) != len(set(roots)):
            raise ValidationError("roots must be unique")
        if len(sinks) != len(set(sinks)):
            raise ValidationError("sinks must be unique")
        known = set(node_ids)
        for root in roots:
            if root not in known:
                raise ValidationError(f"unknown root node: {root}")
        for sink in sinks:
            if sink not in known:
                raise ValidationError(f"unknown sink node: {sink}")
        for edge in edges:
            if edge.source not in known:
                raise ValidationError(f"edge {edge.id!r} has unknown source {edge.source!r}")
            if edge.target not in known:
                raise ValidationError(f"edge {edge.id!r} has unknown target {edge.target!r}")

        return cls(
            title=_required_string(value.get("title"), "title"),
            nodes=nodes,
            edges=edges,
            roots=roots,
            sinks=sinks,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "title": self.title,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "roots": list(self.roots),
            "sinks": list(self.sinks),
        }

    @property
    def digest(self) -> str:
        return digest_json(self.to_dict())


@dataclass(frozen=True)
class PlanAction:
    action_id: str
    edge_id: str
    provider: str
    operation: str
    target: str
    phase: str
    cost: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "edge_id": self.edge_id,
            "provider": self.provider,
            "operation": self.operation,
            "target": self.target,
            "phase": self.phase,
            "cost": self.cost,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ClosurePlan:
    title: str
    graph_digest: str
    status: str
    total_cost: int
    actions: tuple[PlanAction, ...]
    blocked_path: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "title": self.title,
            "graph_digest": self.graph_digest,
            "status": self.status,
            "total_cost": self.total_cost,
            "actions": [action.to_dict() for action in self.actions],
            "blocked_path": list(self.blocked_path),
        }

    @property
    def digest(self) -> str:
        return digest_json(self.unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        result = self.unsigned_dict()
        result["plan_digest"] = self.digest
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ClosurePlan":
        if not isinstance(value, dict):
            raise ValidationError("invalid closure plan schema")
        _require_exact_fields(
            value,
            required={
                "schema_version",
                "title",
                "graph_digest",
                "status",
                "total_cost",
                "actions",
                "blocked_path",
                "plan_digest",
            },
            context="closure plan",
        )
        if value.get("schema_version") != SCHEMA_VERSION:
            raise ValidationError("invalid closure plan schema")
        raw_actions = value.get("actions")
        if not isinstance(raw_actions, list):
            raise ValidationError("plan.actions must be an array")
        actions: list[PlanAction] = []
        for raw in raw_actions:
            if not isinstance(raw, dict):
                raise ValidationError("each plan action must be an object")
            _require_exact_fields(
                raw,
                required={
                    "action_id",
                    "edge_id",
                    "provider",
                    "operation",
                    "target",
                    "phase",
                    "cost",
                    "reason",
                },
                context="plan action",
            )
            phase = _required_string(raw.get("phase"), "action.phase")
            if phase not in ALLOWED_PHASES:
                raise ValidationError(f"unknown action phase: {phase}")
            cost = raw.get("cost")
            if isinstance(cost, bool) or not isinstance(cost, int) or cost < 1:
                raise ValidationError("action.cost must be a positive integer")
            actions.append(
                PlanAction(
                    action_id=_required_string(raw.get("action_id"), "action.action_id"),
                    edge_id=_required_string(raw.get("edge_id"), "action.edge_id"),
                    provider=_required_string(raw.get("provider"), "action.provider"),
                    operation=_required_string(raw.get("operation"), "action.operation"),
                    target=_required_string(raw.get("target"), "action.target"),
                    phase=phase,
                    cost=cost,
                    reason=_required_string(raw.get("reason"), "action.reason"),
                )
            )
        blocked_path = value.get("blocked_path", [])
        if not isinstance(blocked_path, list) or not all(
            isinstance(item, str) for item in blocked_path
        ):
            raise ValidationError("plan.blocked_path must be an array of strings")
        status = _required_string(value.get("status"), "plan.status")
        if status not in {"PLANNED", "BLOCKED"}:
            raise ValidationError("plan.status must be PLANNED or BLOCKED")
        total_cost = value.get("total_cost")
        if isinstance(total_cost, bool) or not isinstance(total_cost, int) or total_cost < 0:
            raise ValidationError("plan.total_cost must be a non-negative integer")
        if total_cost != sum(action.cost for action in actions):
            raise ValidationError("plan.total_cost does not equal the action cost sum")
        action_ids = [action.action_id for action in actions]
        edge_ids = [action.edge_id for action in actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValidationError("plan action IDs must be unique")
        if len(edge_ids) != len(set(edge_ids)):
            raise ValidationError("plan edge IDs must be unique")
        if status == "PLANNED" and blocked_path:
            raise ValidationError("a PLANNED result must not contain blocked_path")
        if status == "BLOCKED" and (actions or total_cost != 0):
            raise ValidationError("a BLOCKED result must not contain closure actions")
        plan = cls(
            title=_required_string(value.get("title"), "plan.title"),
            graph_digest=_sha256_digest(value.get("graph_digest"), "plan.graph_digest"),
            status=status,
            total_cost=total_cost,
            actions=tuple(actions),
            blocked_path=tuple(blocked_path),
        )
        supplied_digest = _sha256_digest(value.get("plan_digest"), "plan.plan_digest")
        if supplied_digest != plan.digest:
            raise ValidationError("plan_digest does not match plan contents")
        return plan
