"""Minimum-cut closure planning over a declared authority graph."""

from __future__ import annotations

from collections import deque

from .models import ALLOWED_PHASES, AuthorityGraph, ClosurePlan, PlanAction


def _add_capacity(
    residual: list[dict[int, int]],
    adjacency: list[set[int]],
    source: int,
    target: int,
    capacity: int,
) -> None:
    residual[source][target] = residual[source].get(target, 0) + capacity
    residual[target].setdefault(source, 0)
    adjacency[source].add(target)
    adjacency[target].add(source)


def _max_flow_and_reachable(
    residual: list[dict[int, int]],
    adjacency: list[set[int]],
    source: int,
    sink: int,
) -> tuple[int, set[int]]:
    total = 0
    size = len(residual)
    while True:
        parent = [-1] * size
        parent[source] = source
        queue: deque[int] = deque([source])
        while queue and parent[sink] == -1:
            current = queue.popleft()
            for neighbor in adjacency[current]:
                if parent[neighbor] == -1 and residual[current].get(neighbor, 0) > 0:
                    parent[neighbor] = current
                    queue.append(neighbor)
                    if neighbor == sink:
                        break
        if parent[sink] == -1:
            break
        bottleneck: int | None = None
        current = sink
        while current != source:
            previous = parent[current]
            capacity = residual[previous][current]
            bottleneck = capacity if bottleneck is None else min(bottleneck, capacity)
            current = previous
        if bottleneck is None:
            raise RuntimeError("internal planner invariant: augmenting path has no capacity")
        current = sink
        while current != source:
            previous = parent[current]
            residual[previous][current] -= bottleneck
            residual[current][previous] = residual[current].get(previous, 0) + bottleneck
            current = previous
        total += bottleneck

    reachable = {source}
    queue = deque([source])
    while queue:
        current = queue.popleft()
        for neighbor in adjacency[current]:
            if neighbor not in reachable and residual[current].get(neighbor, 0) > 0:
                reachable.add(neighbor)
                queue.append(neighbor)
    return total, reachable


def _unclosable_path(graph: AuthorityGraph) -> tuple[str, ...]:
    """Return a root-to-sink path made only of non-revocable edges."""
    outgoing: dict[str, list[tuple[str, str]]] = {}
    for edge in graph.edges:
        if not edge.revocable:
            outgoing.setdefault(edge.source, []).append((edge.target, edge.id))
    queue: deque[str] = deque(graph.roots)
    previous: dict[str, tuple[str, str] | None] = {root: None for root in graph.roots}
    found: str | None = None
    sinks = set(graph.sinks)
    while queue:
        node = queue.popleft()
        if node in sinks:
            found = node
            break
        for target, edge_id in outgoing.get(node, []):
            if target not in previous:
                previous[target] = (node, edge_id)
                queue.append(target)
    if found is None:
        return ()
    segments: list[str] = [found]
    current = found
    while previous[current] is not None:
        parent, edge_id = previous[current]  # type: ignore[misc]
        segments.extend((edge_id, parent))
        current = parent
    segments.reverse()
    return tuple(segments)


def plan_closure(graph: AuthorityGraph) -> ClosurePlan:
    """Find the least-cost declared set of revocations that separates roots from sinks."""
    node_index = {node.id: index for index, node in enumerate(graph.nodes)}
    original_count = len(graph.nodes)
    edge_offset = original_count
    source_index = original_count + 2 * len(graph.edges)
    sink_index = source_index + 1
    size = sink_index + 1
    residual: list[dict[int, int]] = [dict() for _ in range(size)]
    adjacency: list[set[int]] = [set() for _ in range(size)]

    total_revocable_cost = sum(edge.cost for edge in graph.edges if edge.revocable)
    infinite = total_revocable_cost + 1

    edge_vertices: dict[str, tuple[int, int]] = {}
    for position, edge in enumerate(graph.edges):
        edge_in = edge_offset + 2 * position
        edge_out = edge_in + 1
        edge_vertices[edge.id] = (edge_in, edge_out)
        _add_capacity(
            residual,
            adjacency,
            node_index[edge.source],
            edge_in,
            infinite,
        )
        _add_capacity(
            residual,
            adjacency,
            edge_in,
            edge_out,
            edge.cost if edge.revocable else infinite,
        )
        _add_capacity(
            residual,
            adjacency,
            edge_out,
            node_index[edge.target],
            infinite,
        )
    for root in graph.roots:
        _add_capacity(residual, adjacency, source_index, node_index[root], infinite)
    for consequential_sink in graph.sinks:
        _add_capacity(
            residual,
            adjacency,
            node_index[consequential_sink],
            sink_index,
            infinite,
        )

    flow, reachable = _max_flow_and_reachable(residual, adjacency, source_index, sink_index)
    if flow >= infinite:
        return ClosurePlan(
            title=f"Closure plan: {graph.title}",
            graph_digest=graph.digest,
            status="BLOCKED",
            total_cost=0,
            actions=(),
            blocked_path=_unclosable_path(graph),
        )

    selected = []
    for edge in graph.edges:
        edge_in, edge_out = edge_vertices[edge.id]
        if edge.revocable and edge_in in reachable and edge_out not in reachable:
            if edge.enforcement is None:
                raise RuntimeError("internal planner invariant: revocable edge has no enforcement")
            selected.append(
                PlanAction(
                    action_id=f"close:{edge.id}",
                    edge_id=edge.id,
                    provider=edge.enforcement.provider,
                    operation=edge.enforcement.operation,
                    target=edge.enforcement.target,
                    phase=edge.enforcement.phase,
                    cost=edge.cost,
                    reason=edge.label,
                )
            )
    selected.sort(
        key=lambda action: (
            ALLOWED_PHASES[action.phase],
            action.cost,
            action.action_id,
        )
    )
    return ClosurePlan(
        title=f"Closure plan: {graph.title}",
        graph_digest=graph.digest,
        status="PLANNED",
        total_cost=sum(action.cost for action in selected),
        actions=tuple(selected),
    )
