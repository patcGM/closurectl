from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from closurectl.demo import compromised_maintainer_graph
from closurectl.errors import SignatureError, ValidationError
from closurectl.models import AuthorityGraph
from closurectl.planner import plan_closure
from closurectl.receipts import create_receipt, generate_keypair, verify_receipt


class ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        graph = AuthorityGraph.from_dict(compromised_maintainer_graph())
        self.plan = plan_closure(graph)
        self.directory = tempfile.TemporaryDirectory()
        self.private_key = Path(self.directory.name) / "private.pem"
        self.public_key = Path(self.directory.name) / "public.pem"
        generate_keypair(self.private_key, self.public_key)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def evidence(self, status: str = "VERIFIED_CLOSED") -> dict:
        return {
            "schema_version": "1",
            "plan_digest": self.plan.digest,
            "observations": [
                {
                    "action_id": action.action_id,
                    "status": status,
                    "checked_at": "2026-10-21T12:00:00Z",
                    "summary": "Controlled verifier result",
                    "reference": "test://observation",
                }
                for action in self.plan.actions
            ],
        }

    def test_closed_receipt_verifies(self) -> None:
        receipt = create_receipt(
            self.plan,
            self.evidence(),
            self.private_key,
            issued_at="2026-10-21T12:01:00Z",
        )
        result = verify_receipt(receipt, self.public_key, self.plan)
        self.assertEqual(result["closure_state"], "CLOSED")
        self.assertEqual(len(result["receipt_digest"]), 64)

    def test_missing_observation_is_partial(self) -> None:
        evidence = self.evidence()
        evidence["observations"].pop()
        receipt = create_receipt(self.plan, evidence, self.private_key)
        self.assertEqual(receipt["closure_state"], "PARTIAL")
        self.assertEqual(len(receipt["missing_actions"]), 1)

    def test_all_indeterminate_stays_indeterminate(self) -> None:
        receipt = create_receipt(self.plan, self.evidence("INDETERMINATE"), self.private_key)
        self.assertEqual(receipt["closure_state"], "INDETERMINATE")

    def test_tampering_breaks_digest_before_signature(self) -> None:
        receipt = create_receipt(self.plan, self.evidence(), self.private_key)
        tampered = copy.deepcopy(receipt)
        tampered["closure_state"] = "OPEN"
        with self.assertRaisesRegex(SignatureError, "digest"):
            verify_receipt(tampered, self.public_key, self.plan)

    def test_invalid_timestamp_is_rejected_before_signing(self) -> None:
        with self.assertRaisesRegex(ValidationError, "RFC 3339"):
            create_receipt(
                self.plan,
                self.evidence(),
                self.private_key,
                issued_at="not-a-time",
            )

    def test_key_paths_must_be_distinct(self) -> None:
        path = Path(self.directory.name) / "same.pem"
        with self.assertRaisesRegex(ValidationError, "must be different"):
            generate_keypair(path, path)


if __name__ == "__main__":
    unittest.main()
