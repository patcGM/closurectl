from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from closurectl.cli import main
from closurectl.demo import closed_evidence, compromised_maintainer_graph
from closurectl.errors import ValidationError
from closurectl.models import AuthorityGraph
from closurectl.planner import plan_closure
from closurectl.receipts import create_receipt, generate_keypair, verify_receipt
from closurectl.reporting import render_html_report
from closurectl.serialization import write_json


class HtmlReportTests(unittest.TestCase):
    def test_report_is_deterministic_offline_and_escapes_artifact_text(self) -> None:
        graph_dict = compromised_maintainer_graph()
        graph_dict["title"] = "<script>alert('graph')</script>"
        graph_dict["nodes"][0]["label"] = "<b>compromised</b>"
        graph = AuthorityGraph.from_dict(graph_dict)
        plan = plan_closure(graph)
        evidence = closed_evidence(plan, "2026-10-21T12:00:00Z")
        evidence["observations"][0]["summary"] = '<img src=x onerror="alert(1)">'

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
            verification = verify_receipt(receipt, public_key, plan)
            event = {
                "sequence": 1,
                "at": "2026-10-21T11:59:00Z",
                "plan_digest": plan.digest,
                "preview_digest": "a" * 64,
                "action_id": plan.actions[0].action_id,
                "state": "PREVIEWED",
                "summary": "reviewed <preview>",
            }
            first = render_html_report(
                graph,
                plan,
                receipt,
                verification,
                journal_events=[event],
            )
            second = render_html_report(
                graph,
                plan,
                receipt,
                verification,
                journal_events=[event],
            )

        self.assertEqual(first, second)
        self.assertNotIn("<script>", first)
        self.assertNotIn("<img", first)
        self.assertIn("&lt;script&gt;", first)
        self.assertIn("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;", first)
        self.assertIn("reviewed &lt;preview&gt;", first)
        self.assertNotIn("https://", first)
        self.assertNotIn("<script src=", first)

    def test_report_rejects_a_journal_from_another_plan(self) -> None:
        graph = AuthorityGraph.from_dict(compromised_maintainer_graph())
        plan = plan_closure(graph)
        evidence = closed_evidence(plan, "2026-10-21T12:00:00Z")
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
            verification = verify_receipt(receipt, public_key, plan)
            event = {
                "plan_digest": "0" * 64,
                "preview_digest": "1" * 64,
                "action_id": plan.actions[0].action_id,
            }
            with self.assertRaisesRegex(ValidationError, "plan_digest"):
                render_html_report(
                    graph,
                    plan,
                    receipt,
                    verification,
                    journal_events=[event],
                )

    def test_cli_verifies_receipt_before_writing_report(self) -> None:
        graph = AuthorityGraph.from_dict(compromised_maintainer_graph())
        plan = plan_closure(graph)
        evidence = closed_evidence(plan, "2026-10-21T12:00:00Z")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph_path = root / "graph.json"
            plan_path = root / "plan.json"
            receipt_path = root / "receipt.json"
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            report_path = root / "report.html"
            generate_keypair(private_key, public_key)
            receipt = create_receipt(
                plan,
                evidence,
                private_key,
                issued_at="2026-10-21T12:01:00Z",
            )
            write_json(graph_path, graph.to_dict())
            write_json(plan_path, plan.to_dict())
            write_json(receipt_path, receipt)

            result = main(
                [
                    "report",
                    str(graph_path),
                    str(plan_path),
                    str(receipt_path),
                    "--public-key",
                    str(public_key),
                    "--out",
                    str(report_path),
                ]
            )
            self.assertEqual(result, 0)
            content = report_path.read_text(encoding="utf-8")
            self.assertIn("Receipt signature: VALID", content)
            self.assertIn(receipt["receipt_digest"], content)


if __name__ == "__main__":
    unittest.main()
