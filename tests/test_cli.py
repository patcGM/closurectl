from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from closurectl.cli import main
from closurectl.serialization import digest_json, read_json, write_json


class CliTests(unittest.TestCase):
    def test_non_utf8_input_returns_validation_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "graph.json"
            path.write_bytes(b"\xff")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                result = main(["validate", str(path)])
        self.assertEqual(result, 2)
        self.assertIn("valid UTF-8", errors.getvalue())

    def test_blocked_plan_has_nonzero_exit_code(self) -> None:
        graph = {
            "schema_version": "1",
            "title": "Unclosable authority",
            "nodes": [
                {"id": "root", "kind": "root", "label": "Root"},
                {"id": "sink", "kind": "sink", "label": "Sink"},
            ],
            "edges": [
                {
                    "id": "permanent",
                    "source": "root",
                    "target": "sink",
                    "kind": "permanent",
                    "label": "Cannot revoke",
                    "revocable": False,
                    "cost": 1,
                }
            ],
            "roots": ["root"],
            "sinks": ["sink"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_json(root / "graph.json", graph)
            with contextlib.redirect_stdout(io.StringIO()):
                result = main(
                    [
                        "plan",
                        str(root / "graph.json"),
                        "--out",
                        str(root / "plan.json"),
                    ]
                )
        self.assertEqual(result, 3)

    def test_demo_produces_verifiable_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                result = main(["demo", "--dir", directory])
            self.assertEqual(result, 0)
            self.assertIn("receipt: CLOSED", stream.getvalue())
            expected = {
                "authority-graph.json",
                "closure-plan.json",
                "evidence.json",
                "demo-private.pem",
                "demo-public.pem",
                "closure-receipt.json",
            }
            self.assertEqual({path.name for path in Path(directory).iterdir()}, expected)

            verify_output = io.StringIO()
            with contextlib.redirect_stdout(verify_output):
                result = main(
                    [
                        "verify",
                        str(Path(directory) / "closure-receipt.json"),
                        "--public-key",
                        str(Path(directory) / "demo-public.pem"),
                        "--graph",
                        str(Path(directory) / "authority-graph.json"),
                        "--plan",
                        str(Path(directory) / "closure-plan.json"),
                    ]
                )
            self.assertEqual(result, 0)
            self.assertIn("signature: VALID", verify_output.getvalue())

    def test_receipt_recomputes_plan_from_graph(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["demo", "--dir", directory]), 0)

            root = Path(directory)
            forged_plan = read_json(root / "closure-plan.json")
            forged_plan["actions"] = []
            forged_plan["total_cost"] = 0
            unsigned = {key: value for key, value in forged_plan.items() if key != "plan_digest"}
            forged_plan["plan_digest"] = digest_json(unsigned)
            write_json(root / "forged-plan.json", forged_plan)
            write_json(
                root / "forged-evidence.json",
                {
                    "schema_version": "1",
                    "plan_digest": forged_plan["plan_digest"],
                    "observations": [],
                },
            )

            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                result = main(
                    [
                        "receipt",
                        str(root / "authority-graph.json"),
                        str(root / "forged-plan.json"),
                        str(root / "forged-evidence.json"),
                        "--private-key",
                        str(root / "demo-private.pem"),
                        "--out",
                        str(root / "forged-receipt.json"),
                    ]
                )
            self.assertEqual(result, 2)
            self.assertIn("does not match a fresh computation", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
