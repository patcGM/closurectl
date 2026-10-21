"""Deterministic, offline HTML reports for verified closure receipts."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, Iterable

from .errors import ValidationError
from .models import AuthorityGraph, ClosurePlan


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


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
    journal_events: Iterable[dict[str, Any]], plan: ClosurePlan
) -> list[dict[str, Any]]:
    events = list(journal_events)
    actions = {action.action_id for action in plan.actions}
    preview_digests: set[str] = set()
    for event in events:
        if event.get("plan_digest") != plan.digest:
            raise ValidationError("report journal plan_digest does not match the plan")
        if event.get("action_id") not in actions:
            raise ValidationError("report journal references an unknown plan action")
        preview_digest = event.get("preview_digest")
        if not isinstance(preview_digest, str) or not preview_digest:
            raise ValidationError("report journal preview_digest is invalid")
        preview_digests.add(preview_digest)
    if len(preview_digests) > 1:
        raise ValidationError("report journal contains more than one execution preview")
    return events


def render_html_report(
    graph: AuthorityGraph,
    plan: ClosurePlan,
    receipt: dict[str, Any],
    verification: dict[str, str],
    *,
    journal_events: Iterable[dict[str, Any]] = (),
) -> str:
    """Render only verified, escaped artifact data into a self-contained report."""
    if plan.graph_digest != graph.digest:
        raise ValidationError("report plan does not match the authority graph")
    if receipt.get("receipt_digest") != verification.get("receipt_digest"):
        raise ValidationError("report receipt has not been verified")
    if receipt.get("closure_state") != verification.get("closure_state"):
        raise ValidationError("report receipt state does not match verification")
    events = _validate_journal_binding(journal_events, plan)

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
        f"<code>receipt sha256: {_escape(receipt['receipt_digest'])}</code>"
        f"<code>signing key: {_escape(fingerprint)}</code>"
        "<p>Receipt signature: VALID</p></div>"
        '<p class="muted">Generated offline by closurectl. No external assets or scripts.</p>'
        "</main></body></html>\n"
    )


def write_html_report(path: str | Path, content: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(destination)
