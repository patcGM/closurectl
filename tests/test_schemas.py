from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaError

from closurectl.demo import closed_evidence, compromised_maintainer_graph
from closurectl.models import AuthorityGraph, ClosurePlan
from closurectl.planner import plan_closure
from closurectl.receipts import create_receipt, generate_keypair

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "tests" / "fixtures"


def load_schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


class SchemaCompatibilityTests(unittest.TestCase):
    def test_v01_graph_plan_and_evidence_fixture_remain_readable(self) -> None:
        fixture = FIXTURES / "v0.1"
        graph = AuthorityGraph.from_dict(
            json.loads((fixture / "authority-graph.json").read_text(encoding="utf-8"))
        )
        plan = ClosurePlan.from_dict(
            json.loads((fixture / "closure-plan.json").read_text(encoding="utf-8"))
        )
        evidence = json.loads((fixture / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(plan.to_dict(), plan_closure(graph).to_dict())
        self.assertEqual(evidence["plan_digest"], plan.digest)

    def test_every_published_schema_is_valid(self) -> None:
        for path in SCHEMAS.glob("*.json"):
            with self.subTest(schema=path.name):
                Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))

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

    def test_provider_evidence_and_receipt_v2_match_schemas(self) -> None:
        graph = AuthorityGraph.from_dict(compromised_maintainer_graph())
        plan = plan_closure(graph)
        evidence = {
            "schema_version": "2",
            "plan_digest": plan.digest,
            "observations": [
                {
                    "action_id": action.action_id,
                    "status": "VERIFIED_CLOSED",
                    "checked_at": "2026-10-21T12:00:00Z",
                    "summary": "Independent provider probe",
                    "reference": f"test://{action.action_id}",
                    "provider": action.provider,
                    "operation": action.operation,
                    "target": action.target,
                    "provider_account": "test-account",
                    "observer_identity": "test:observer",
                    "api_origin": "https://api.provider.test",
                    "probe_type": "provider-state",
                }
                for action in plan.actions
            ],
        }
        Draft202012Validator(load_schema("evidence-v2.schema.json")).validate(evidence)
        with tempfile.TemporaryDirectory() as directory:
            private_key = Path(directory) / "private.pem"
            public_key = Path(directory) / "public.pem"
            generate_keypair(private_key, public_key)
            receipt = create_receipt(
                plan,
                evidence,
                private_key,
                issued_at="2026-10-21T12:01:00Z",
            )
        Draft202012Validator(load_schema("closure-receipt-v2.schema.json")).validate(receipt)

        invalid = dict(evidence)
        invalid["unhashed_annotation"] = "not allowed"
        with self.assertRaises(JsonSchemaError):
            Draft202012Validator(load_schema("evidence-v2.schema.json")).validate(invalid)


if __name__ == "__main__":
    unittest.main()
