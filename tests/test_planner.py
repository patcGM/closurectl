from __future__ import annotations

import itertools
import random
import unittest

from closurectl.demo import compromised_maintainer_graph
from closurectl.models import AuthorityGraph
from closurectl.planner import plan_closure


class PlannerTests(unittest.TestCase):
    @staticmethod
    def _path_exists(edges: list[dict], removed: set[str]) -> bool:
        reachable = {"n0"}
        changed = True
        while changed:
            changed = False
            for edge in edges:
                if (
                    edge["id"] not in removed
                    and edge["source"] in reachable
                    and edge["target"] not in reachable
                ):
                    reachable.add(edge["target"])
                    changed = True
        return "n4" in reachable

    @classmethod
    def _brute_force_cost(cls, edges: list[dict]) -> int | None:
        if not cls._path_exists(edges, set()):
            return 0
        revocable = [edge for edge in edges if edge["revocable"]]
        best: int | None = None
        for size in range(len(revocable) + 1):
            for subset in itertools.combinations(revocable, size):
                removed = {edge["id"] for edge in subset}
                if not cls._path_exists(edges, removed):
                    cost = sum(edge["cost"] for edge in subset)
                    best = cost if best is None else min(best, cost)
        return best

    def test_demo_requires_each_surviving_authority_path(self) -> None:
        graph = AuthorityGraph.from_dict(compromised_maintainer_graph())
        plan = plan_closure(graph)
        self.assertEqual(plan.status, "PLANNED")
        self.assertEqual(plan.total_cost, 7)
        self.assertEqual(
            [action.edge_id for action in plan.actions],
            [
                "github-can-mint-oidc",
                "queued-deploy-can-commit",
                "cloud-session-can-deploy",
                "npm-can-publish",
                "github-repository-access",
            ],
        )
        self.assertEqual(
            [action.phase for action in plan.actions],
            [
                "stop_minting",
                "cancel_pending",
                "revoke_descendants",
                "revoke_roots",
                "revoke_roots",
            ],
        )

    def test_parallel_edges_are_not_collapsed(self) -> None:
        raw = {
            "schema_version": "1",
            "title": "Parallel authority",
            "roots": ["root"],
            "sinks": ["sink"],
            "nodes": [
                {"id": "root", "kind": "root", "label": "Root"},
                {"id": "sink", "kind": "sink", "label": "Sink"},
            ],
            "edges": [
                {
                    "id": "route-a",
                    "source": "root",
                    "target": "sink",
                    "kind": "access",
                    "label": "Close route A",
                    "revocable": True,
                    "cost": 1,
                    "enforcement": {
                        "provider": "demo",
                        "operation": "close",
                        "target": "a",
                        "phase": "revoke_roots",
                    },
                },
                {
                    "id": "route-b",
                    "source": "root",
                    "target": "sink",
                    "kind": "access",
                    "label": "Close route B",
                    "revocable": True,
                    "cost": 1,
                    "enforcement": {
                        "provider": "demo",
                        "operation": "close",
                        "target": "b",
                        "phase": "revoke_roots",
                    },
                },
            ],
        }
        plan = plan_closure(AuthorityGraph.from_dict(raw))
        self.assertEqual({action.edge_id for action in plan.actions}, {"route-a", "route-b"})

    def test_non_revocable_path_blocks_closure(self) -> None:
        raw = {
            "schema_version": "1",
            "title": "Uncontrolled provider",
            "roots": ["root"],
            "sinks": ["sink"],
            "nodes": [
                {"id": "root", "kind": "root", "label": "Root"},
                {"id": "middle", "kind": "session", "label": "Session"},
                {"id": "sink", "kind": "sink", "label": "Sink"},
            ],
            "edges": [
                {
                    "id": "uncontrolled-a",
                    "source": "root",
                    "target": "middle",
                    "kind": "derived",
                    "label": "Outside control",
                    "revocable": False,
                    "cost": 1,
                },
                {
                    "id": "uncontrolled-b",
                    "source": "middle",
                    "target": "sink",
                    "kind": "effect",
                    "label": "Outside control",
                    "revocable": False,
                    "cost": 1,
                },
            ],
        }
        plan = plan_closure(AuthorityGraph.from_dict(raw))
        self.assertEqual(plan.status, "BLOCKED")
        self.assertEqual(
            plan.blocked_path,
            ("root", "uncontrolled-a", "middle", "uncontrolled-b", "sink"),
        )

    def test_min_cut_matches_brute_force_on_small_graphs(self) -> None:
        candidates = [(source, target) for source in range(5) for target in range(source + 1, 5)]
        for seed in range(75):
            generator = random.Random(seed)
            chosen = generator.sample(candidates, generator.randint(1, 8))
            edges = []
            for index, (source, target) in enumerate(chosen):
                revocable = generator.random() < 0.7
                edge = {
                    "id": f"e{index}",
                    "source": f"n{source}",
                    "target": f"n{target}",
                    "kind": "authority",
                    "label": f"Edge {index}",
                    "revocable": revocable,
                    "cost": generator.randint(1, 5),
                }
                if revocable:
                    edge["enforcement"] = {
                        "provider": "test",
                        "operation": "close",
                        "target": f"edge-{index}",
                        "phase": "revoke_roots",
                    }
                edges.append(edge)
            graph = AuthorityGraph.from_dict(
                {
                    "schema_version": "1",
                    "title": f"Generated graph {seed}",
                    "roots": ["n0"],
                    "sinks": ["n4"],
                    "nodes": [
                        {"id": f"n{index}", "kind": "node", "label": f"Node {index}"}
                        for index in range(5)
                    ],
                    "edges": edges,
                }
            )
            expected = self._brute_force_cost(edges)
            plan = plan_closure(graph)
            with self.subTest(seed=seed):
                if expected is None:
                    self.assertEqual(plan.status, "BLOCKED")
                else:
                    self.assertEqual(plan.status, "PLANNED")
                    self.assertEqual(plan.total_cost, expected)


if __name__ == "__main__":
    unittest.main()
