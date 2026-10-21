from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from closurectl.cli import main
from closurectl.demo import closed_evidence, compromised_maintainer_graph
from closurectl.errors import ValidationError
from closurectl.models import AuthorityGraph
from closurectl.planner import plan_closure
from closurectl.receipts import create_receipt, generate_keypair
from closurectl.reporting import render_html_report
from closurectl.serialization import digest_json, read_json, write_json


def journal_event(plan, **overrides) -> dict:
    action = plan.actions[0]
    event = {
        "schema_version": "1",
        "sequence": 1,
        "at": "2026-10-21T11:59:00Z",
        "plan_digest": plan.digest,
        "preview_digest": "a" * 64,
        "action_id": action.action_id,
        "phase": action.phase,
        "operation": f"{action.provider}.{action.operation}",
        "target": action.target,
        "state": "PREVIEWED",
        "summary": "reviewed <preview>",
        "reference": "",
        "previous_event_digest": "",
    }
    event.update(overrides)
    event["event_digest"] = digest_json(event)
    return event


class HtmlReportTests(unittest.TestCase):
    def test_report_is_deterministic_offline_and_escapes_artifact_text(self) -> None:
        graph_dict = compromised_maintainer_graph()
        graph_dict["title"] = "<script>alert('graph')</script>\u202e"
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
            event = journal_event(plan)
            first = render_html_report(
                graph,
                plan,
                evidence,
                receipt,
                public_key,
                journal_events=[event],
                preview_digest="a" * 64,
            )
            second = render_html_report(
                graph,
                plan,
                evidence,
                receipt,
                public_key,
                journal_events=[event],
                preview_digest="a" * 64,
            )

        self.assertEqual(first, second)
        self.assertNotIn("<script>", first)
        self.assertNotIn("<img", first)
        self.assertIn("&lt;script&gt;", first)
        self.assertIn("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;", first)
        self.assertIn("reviewed &lt;preview&gt;", first)
        self.assertIn("\\u202e", first)
        self.assertNotIn("\u202e", first)
        self.assertIn("default-src 'none'", first)
        self.assertNotIn("https://", first)
        self.assertNotIn("<script src=", first)
        self.assertNotIn("<a ", first)

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
            event = journal_event(plan, plan_digest="0" * 64)
            with self.assertRaisesRegex(ValidationError, "plan_digest"):
                render_html_report(
                    graph,
                    plan,
                    evidence,
                    receipt,
                    public_key,
                    journal_events=[event],
                    preview_digest="a" * 64,
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
            evidence_path = root / "evidence.json"
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
            write_json(evidence_path, evidence)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(
                    [
                        "report",
                        str(graph_path),
                        str(plan_path),
                        str(receipt_path),
                        str(evidence_path),
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
            self.assertRegex(output.getvalue(), r"report sha256: [a-f0-9]{64}")

    def test_report_rejects_mismatched_evidence_and_invalid_journal_binding(self) -> None:
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
            changed = {
                **evidence,
                "observations": [dict(item) for item in evidence["observations"]],
            }
            changed["observations"][0]["summary"] = "different evidence"
            with self.assertRaisesRegex(ValidationError, "do not match"):
                render_html_report(
                    graph,
                    plan,
                    changed,
                    receipt,
                    public_key,
                )

            event = journal_event(plan, sequence=1.0)
            with self.assertRaisesRegex(ValidationError, "invalid types"):
                render_html_report(
                    graph,
                    plan,
                    evidence,
                    receipt,
                    public_key,
                    journal_events=[event],
                    preview_digest="a" * 64,
                )

    def test_cli_refuses_report_output_collision(self) -> None:
        graph = AuthorityGraph.from_dict(compromised_maintainer_graph())
        plan = plan_closure(graph)
        evidence = closed_evidence(plan, "2026-10-21T12:00:00Z")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph_path = root / "graph.json"
            plan_path = root / "plan.json"
            evidence_path = root / "evidence.json"
            receipt_path = root / "receipt.json"
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            generate_keypair(private_key, public_key)
            receipt = create_receipt(
                plan,
                evidence,
                private_key,
                issued_at="2026-10-21T12:01:00Z",
            )
            write_json(graph_path, graph.to_dict())
            write_json(plan_path, plan.to_dict())
            write_json(evidence_path, evidence)
            write_json(receipt_path, receipt)
            result = main(
                [
                    "report",
                    str(graph_path),
                    str(plan_path),
                    str(receipt_path),
                    str(evidence_path),
                    "--public-key",
                    str(public_key),
                    "--out",
                    str(receipt_path),
                ]
            )
            self.assertEqual(result, 2)
            self.assertEqual(read_json(receipt_path), receipt)


if __name__ == "__main__":
    unittest.main()
