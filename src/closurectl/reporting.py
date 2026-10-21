"""Deterministic, offline HTML reports for verified closure receipts."""

from __future__ import annotations

import hashlib
import html
import re
import unicodedata
from pathlib import Path
from typing import Any, Iterable

from .errors import ValidationError
from .execution_models import EXECUTION_SCHEMA_VERSION, parse_rfc3339
from .models import AuthorityGraph, ClosurePlan
from .receipts import validate_evidence_binding, verify_receipt
from .serialization import atomic_write_bytes, digest_json


def _escape(value: Any) -> str:
    neutralized = "".join(
        (
            f"\\u{ord(character):04x}"
            if unicodedata.category(character) in {"Cc", "Cf", "Cs"}
            else character
        )
        for character in str(value)
    )
    return html.escape(neutralized, quote=True)


def _state_class(value: str) -> str:
    return {
        "CLOSED": "closed",
        "VERIFIED_CLOSED": "closed",
        "VERIFIED": "closed",
        "PARTIAL": "partial",
        "OPEN": "open",
        "STILL_OPEN": "open",
        "FAILED": "open",
        "INDETERMINATE": "unknown",
        "BLOCKED": "blocked",
        "REQUESTED": "pending",
        "RECONCILING": "pending",
        "PREVIEWED": "pending",
    }.get(value, "unknown")


def _validate_journal_binding(
    journal_events: Iterable[dict[str, Any]],
    plan: ClosurePlan,
    preview_digest: str | None,
) -> list[dict[str, Any]]:
    events = list(journal_events)
    if events and preview_digest is None:
        raise ValidationError("report journal requires a validated execution preview")
    actions = {action.action_id: action for action in plan.actions}
    action_order = {action.action_id: index for index, action in enumerate(plan.actions)}
    preview_digests: set[str] = set()
    previous_digest = ""
    latest: dict[str, str] = {}
    required_fields = {
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
    transitions = {
        None: {"PREVIEWED"},
        "PREVIEWED": {"REQUESTED"},
        "REQUESTED": {"RECONCILING"},
        "RECONCILING": {"VERIFIED", "FAILED", "INDETERMINATE", "RECONCILING"},
        "INDETERMINATE": {"RECONCILING"},
        "VERIFIED": set(),
        "FAILED": set(),
    }
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict) or set(event) != required_fields:
            raise ValidationError(f"report journal event {index} has an invalid shape")
        string_fields = required_fields - {"sequence"}
        if (
            event.get("schema_version") != EXECUTION_SCHEMA_VERSION
            or type(event.get("sequence")) is not int
            or event["sequence"] != index
            or not all(isinstance(event.get(field), str) for field in string_fields)
        ):
            raise ValidationError(f"report journal event {index} has invalid types")
        if not event["summary"]:
            raise ValidationError(f"report journal event {index} has an empty summary")
        parse_rfc3339(event["at"], f"report journal event {index}.at")
        if event["previous_event_digest"] != previous_digest:
            raise ValidationError("report journal hash chain is invalid")
        payload = {key: value for key, value in event.items() if key != "event_digest"}
        if event["event_digest"] != digest_json(payload):
            raise ValidationError("report journal event digest is invalid")
        if event.get("plan_digest") != plan.digest:
            raise ValidationError("report journal plan_digest does not match the plan")
        action = actions.get(event["action_id"])
        if action is None:
            raise ValidationError("report journal references an unknown plan action")
        if (
            event["phase"] != action.phase
            or event["operation"] != f"{action.provider}.{action.operation}"
            or event["target"] != action.target
        ):
            raise ValidationError("report journal event does not match its plan action")
        event_preview_digest = event.get("preview_digest")
        if not re.fullmatch(r"[a-f0-9]{64}", event_preview_digest):
            raise ValidationError("report journal preview_digest is invalid")
        if event_preview_digest != preview_digest:
            raise ValidationError(
                "report journal preview_digest does not match the supplied preview"
            )
        preview_digests.add(event_preview_digest)
        previous_state = latest.get(action.action_id)
        if event["state"] not in transitions.get(previous_state, set()):
            raise ValidationError(
                f"invalid report journal transition for {action.action_id}: "
                f"{previous_state or 'START'} -> {event['state']}"
            )
        if previous_state is None:
            for earlier in plan.actions[: action_order[action.action_id]]:
                if latest.get(earlier.action_id) != "VERIFIED":
                    raise ValidationError(
                        "report journal starts a later action before earlier closure"
                    )
        latest[action.action_id] = event["state"]
        previous_digest = event["event_digest"]
    if len(preview_digests) > 1:
        raise ValidationError("report journal contains more than one execution preview")
    return events


def render_html_report(
    graph: AuthorityGraph,
    plan: ClosurePlan,
    evidence: dict[str, Any],
    receipt: dict[str, Any],
    public_key_path: str | Path,
    *,
    journal_events: Iterable[dict[str, Any]] = (),
    preview_digest: str | None = None,
) -> str:
    """Render only verified, escaped artifact data into a self-contained report."""
    verification = verify_receipt(receipt, public_key_path, plan)
    if plan.graph_digest != graph.digest:
        raise ValidationError("report plan does not match the authority graph")
    if receipt.get("receipt_digest") != verification.get("receipt_digest"):
        raise ValidationError("report receipt has not been verified")
    if receipt.get("closure_state") != verification.get("closure_state"):
        raise ValidationError("report receipt state does not match verification")
    evidence_binding = validate_evidence_binding(plan, evidence, receipt)
    events = _validate_journal_binding(journal_events, plan, preview_digest)

    observations = {
        observation["action_id"]: observation for observation in receipt["observations"]
    }
    action_rows: list[str] = []
    for action in plan.actions:
        observation = observations.get(action.action_id)
        state = observation["status"] if observation else "MISSING"
        checked_at = observation["checked_at"] if observation else ""
        summary = observation["summary"] if observation else "No signed observation"
        action_rows.append(
            "<tr>"
            f"<td><code>{_escape(action.action_id)}</code></td>"
            f"<td>{_escape(action.phase)}</td>"
            f"<td>{_escape(action.provider)}.{_escape(action.operation)}</td>"
            f"<td><code>{_escape(action.target)}</code></td>"
            f'<td><span class="state {_state_class(state)}">{_escape(state)}</span></td>'
            f"<td>{_escape(checked_at)}</td>"
            f"<td>{_escape(summary)}</td>"
            "</tr>"
        )

    timeline: list[tuple[str, int, str]] = []
    for event in events:
        state = str(event["state"])
        timeline.append(
            (
                str(event["at"]),
                int(event["sequence"]),
                "<li>"
                f"<time>{_escape(event['at'])}</time>"
                f'<span class="state {_state_class(state)}">{_escape(state)}</span>'
                f"<code>{_escape(event['action_id'])}</code>"
                f"<span>{_escape(event['summary'])}</span>"
                "</li>",
            )
        )
    for position, observation in enumerate(receipt["observations"], start=1):
        state = str(observation["status"])
        timeline.append(
            (
                str(observation["checked_at"]),
                1_000_000 + position,
                "<li>"
                f"<time>{_escape(observation['checked_at'])}</time>"
                f'<span class="state {_state_class(state)}">{_escape(state)}</span>'
                f"<code>{_escape(observation['action_id'])}</code>"
                f"<span>{_escape(observation['summary'])}</span>"
                "</li>",
            )
        )
    timeline.sort(key=lambda item: (item[0], item[1]))

    node_rows = [
        "<tr>"
        f"<td><code>{_escape(node.id)}</code></td>"
        f"<td>{_escape(node.kind)}</td>"
        f"<td>{_escape(node.label)}</td>"
        "</tr>"
        for node in sorted(graph.nodes, key=lambda item: item.id)
    ]
    edge_rows = [
        "<tr>"
        f"<td><code>{_escape(edge.id)}</code></td>"
        f"<td><code>{_escape(edge.source)}</code> → <code>{_escape(edge.target)}</code></td>"
        f"<td>{_escape(edge.kind)}</td>"
        f"<td>{'yes' if edge.revocable else 'no'}</td>"
        f"<td>{_escape(edge.label)}</td>"
        "</tr>"
        for edge in sorted(graph.edges, key=lambda item: item.id)
    ]

    closure_state = str(receipt["closure_state"])
    fingerprint = receipt.get("signing_key_fingerprint", "not present in receipt v1")
    css = """
    :root{color-scheme:light dark;--bg:#0b1020;--panel:#151c31;--text:#e8ecf4;
      --muted:#9ca9bf;--line:#2a3552;--closed:#2dcf88;--open:#ff6b6b;
      --partial:#f5b942;--unknown:#a78bfa;--blocked:#ff8f3d;--pending:#59a5ff}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
      font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
    main{max-width:1200px;margin:auto;padding:32px 20px 64px}h1{font-size:32px;margin:0 0 8px}
    h2{margin-top:32px}.muted{color:var(--muted)}.warning{border-left:4px solid var(--partial);
      background:var(--panel);padding:14px 16px;margin:22px 0}.grid{display:grid;
      grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.card{background:var(--panel);
      border:1px solid var(--line);border-radius:10px;padding:16px}.card strong{display:block;
      font-size:24px}table{width:100%;border-collapse:collapse;background:var(--panel);
      border:1px solid var(--line)}th,td{text-align:left;vertical-align:top;padding:10px;
      border-bottom:1px solid var(--line)}th{color:var(--muted)}code{overflow-wrap:anywhere}
    .state{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:2px 8px;
      font-size:12px;font-weight:700}.closed{color:var(--closed)}.open{color:var(--open)}
    .partial{color:var(--partial)}.unknown{color:var(--unknown)}.blocked{color:var(--blocked)}
    .pending{color:var(--pending)}ol.timeline{list-style:none;padding:0}.timeline li{display:grid;
      grid-template-columns:minmax(190px,auto) auto minmax(170px,auto) 1fr;gap:10px;
      align-items:start;padding:10px 0;border-bottom:1px solid var(--line)}
    .integrity code{display:block;margin:4px 0}@media(max-width:760px){.table-wrap{overflow:auto}
      .timeline li{grid-template-columns:1fr}.timeline time{color:var(--muted)}}
    """
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="'
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
        "font-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\">"
        f"<title>{_escape(graph.title)} — closurectl report</title>"
        f"<style>{css}</style></head><body><main>"
        f"<h1>{_escape(graph.title)}</h1>"
        f'<p class="muted">Signed closure report issued {_escape(receipt["issued_at"])}</p>'
        f'<p><span class="state {_state_class(closure_state)}">{_escape(closure_state)}</span></p>'
        f'<div class="warning"><strong>Scoped claim.</strong> '
        f"{_escape(receipt['scope_statement'])}</div>"
        '<section class="grid">'
        f'<div class="card"><span class="muted">Planned actions</span><strong>{len(plan.actions)}</strong></div>'
        f'<div class="card"><span class="muted">Verified closed</span><strong>'
        f"{sum(1 for item in receipt['observations'] if item['status'] == 'VERIFIED_CLOSED')}"
        "</strong></div>"
        f'<div class="card"><span class="muted">Missing observations</span><strong>'
        f"{len(receipt['missing_actions'])}</strong></div>"
        f'<div class="card"><span class="muted">Journal events</span><strong>{len(events)}</strong></div>'
        "</section>"
        '<h2>Closure actions</h2><div class="table-wrap"><table><thead><tr>'
        "<th>Action</th><th>Phase</th><th>Operation</th><th>Target</th>"
        "<th>Signed state</th><th>Checked</th><th>Observation</th>"
        "</tr></thead><tbody>" + "".join(action_rows) + "</tbody></table></div>"
        '<h2>Timeline</h2><ol class="timeline">'
        + ("".join(item[2] for item in timeline) or "<li>No timeline events.</li>")
        + "</ol>"
        '<h2>Declared nodes</h2><div class="table-wrap"><table><thead><tr>'
        "<th>ID</th><th>Kind</th><th>Label</th></tr></thead><tbody>"
        + "".join(node_rows)
        + "</tbody></table></div>"
        '<h2>Declared authority paths</h2><div class="table-wrap"><table><thead><tr>'
        "<th>ID</th><th>Path</th><th>Kind</th><th>Revocable</th><th>Label</th>"
        "</tr></thead><tbody>" + "".join(edge_rows) + "</tbody></table></div>"
        '<h2>Integrity</h2><div class="card integrity">'
        f"<code>graph sha256: {_escape(graph.digest)}</code>"
        f"<code>plan sha256: {_escape(plan.digest)}</code>"
        f"<code>evidence sha256: {_escape(evidence_binding['evidence_digest'])}</code>"
        f"<code>receipt sha256: {_escape(receipt['receipt_digest'])}</code>"
        f"<code>signing key: {_escape(fingerprint)}</code>"
        "<p>Receipt signature: VALID</p></div>"
        '<p class="muted">Generated offline by closurectl. No external assets or scripts.</p>'
        "</main></body></html>\n"
    )


def write_html_report(path: str | Path, content: str) -> str:
    encoded = content.encode("utf-8")
    atomic_write_bytes(path, encoded)
    return hashlib.sha256(encoded).hexdigest()
