from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from closurectl.demo import compromised_maintainer_graph
from closurectl.errors import ValidationError
from closurectl.models import AuthorityGraph
from closurectl.serialization import read_json


class AuthorityGraphTests(unittest.TestCase):
    def test_demo_graph_is_valid_and_stable(self) -> None:
        graph = AuthorityGraph.from_dict(compromised_maintainer_graph())
        self.assertEqual(len(graph.nodes), 9)
        self.assertEqual(len(graph.edges), 10)
        self.assertEqual(len(graph.digest), 64)
        self.assertEqual(graph.digest, AuthorityGraph.from_dict(graph.to_dict()).digest)

    def test_unknown_edge_endpoint_is_rejected(self) -> None:
        raw = compromised_maintainer_graph()
        raw["edges"][0]["target"] = "missing-node"
        with self.assertRaisesRegex(ValidationError, "unknown target"):
            AuthorityGraph.from_dict(raw)

    def test_revocable_edge_requires_enforcement(self) -> None:
        raw = compromised_maintainer_graph()
        raw["edges"][1].pop("enforcement")
        with self.assertRaisesRegex(ValidationError, "require enforcement"):
            AuthorityGraph.from_dict(raw)

    def test_empty_enforcement_is_rejected(self) -> None:
        raw = compromised_maintainer_graph()
        raw["edges"][1]["enforcement"] = {}
        with self.assertRaisesRegex(ValidationError, "missing fields"):
            AuthorityGraph.from_dict(raw)

    def test_unknown_fields_are_rejected(self) -> None:
        raw = compromised_maintainer_graph()
        raw["unhashed_annotation"] = "must not disappear from the digest"
        with self.assertRaisesRegex(ValidationError, "unknown fields"):
            AuthorityGraph.from_dict(raw)

    def test_plaintext_secret_fields_are_rejected_on_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.json"
            path.write_text(json.dumps({"clientSecret": "do-not-store"}))
            with self.assertRaisesRegex(ValidationError, "forbidden"):
                read_json(path)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"title":"first","title":"second"}')
            with self.assertRaisesRegex(ValidationError, "duplicate JSON"):
                read_json(path)


if __name__ == "__main__":
    unittest.main()
