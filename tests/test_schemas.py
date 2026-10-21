from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from closurectl.demo import closed_evidence, compromised_maintainer_graph
from closurectl.models import AuthorityGraph
from closurectl.planner import plan_closure
from closurectl.receipts import create_receipt, generate_keypair

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"


def load_schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


class SchemaCompatibilityTests(unittest.TestCase):
    def test_published_schemas_are_valid_and_accept_generated_artifacts(self) -> None:
        graph_dict = compromised_maintainer_graph()
        graph = AuthorityGraph.from_dict(graph_dict)
        plan = plan_closure(graph)
        evidence = closed_evidence(plan, "2026-10-21T12:00:00Z")

        artifacts = [
            ("authority-graph.schema.json", graph_dict),
            ("closure-plan.schema.json", plan.to_dict()),
            ("evidence.schema.json", evidence),
        ]
        for schema_name, artifact in artifacts:
            with self.subTest(schema=schema_name):
                schema = load_schema(schema_name)
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(artifact)

        with tempfile.TemporaryDirectory() as directory:
            private_key = Path(directory) / "private.pem"
            public_key_path = Path(directory) / "public.pem"
            generate_keypair(private_key, public_key_path)
            receipt = create_receipt(
                plan,
                evidence,
                private_key,
                issued_at="2026-10-21T12:01:00Z",
            )
            schema = load_schema("closure-receipt.schema.json")
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(receipt)


if __name__ == "__main__":
    unittest.main()
