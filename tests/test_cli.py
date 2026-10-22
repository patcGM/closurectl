from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from closurectl.cli import _configure_utf8_output, main
from closurectl.serialization import digest_json, read_json, write_json


class CliTests(unittest.TestCase):
    def test_windows_console_streams_are_reconfigured_for_utf8(self) -> None:
        class ReconfigurableStream(io.StringIO):
            def __init__(self) -> None:
                super().__init__()
                self.configuration = None

            def reconfigure(self, **kwargs) -> None:
                self.configuration = kwargs

        stdout = ReconfigurableStream()
        stderr = ReconfigurableStream()
        with (
            patch("closurectl.cli.sys.stdout", stdout),
            patch("closurectl.cli.sys.stderr", stderr),
        ):
            _configure_utf8_output()
        self.assertEqual(stdout.configuration, {"encoding": "utf-8", "errors": "backslashreplace"})
        self.assertEqual(stderr.configuration, {"encoding": "utf-8", "errors": "backslashreplace"})

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

    def test_artifact_commands_refuse_input_output_collisions_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            original = b"must remain unchanged"
            source.write_bytes(original)
            commands = {
                "plan": ["plan", str(source), "--out", str(source)],
                "receipt": [
                    "receipt",
                    str(source),
                    str(source),
                    str(source),
                    "--private-key",
                    str(source),
                    "--out",
                    str(source),
                ],
                "incident draft": [
                    "incident",
                    "draft",
                    "--title",
                    "Collision",
                    "--github-inventory",
                    str(source),
                    "--out",
                    str(source),
                ],
                "incident build": [
                    "incident",
                    "build",
                    str(source),
                    "--confirm",
                    "digest",
                    "--out",
                    str(source),
                ],
                "incident wizard": [
                    "incident",
                    "wizard",
                    str(source),
                    "--out",
                    str(source),
                ],
                "execute preview": [
                    "execute",
                    "preview",
                    str(source),
                    str(source),
                    "--out",
                    str(source),
                ],
                "execute apply": [
                    "execute",
                    "apply",
                    str(source),
                    str(source),
                    str(source),
                    "--confirm",
                    "digest",
                    "--journal",
                    str(source),
                ],
                "execute resume": [
                    "execute",
                    "resume",
                    str(source),
                    str(source),
                    str(source),
                    "--confirm",
                    "digest",
                    "--journal",
                    str(source),
                ],
                "observe": [
                    "observe",
                    str(source),
                    str(source),
                    str(source),
                    "--journal",
                    str(source),
                    "--out",
                    str(source),
                ],
                "report": [
                    "report",
                    str(source),
                    str(source),
                    str(source),
                    str(source),
                    "--public-key",
                    str(source),
                    "--out",
                    str(source),
                ],
            }
            for name, command in commands.items():
                with self.subTest(command=name), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(command), 2)
                    self.assertEqual(source.read_bytes(), original)

    def test_plan_refuses_hard_link_output_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "graph.json"
            alias = Path(directory) / "plan.json"
            original = b"must remain unchanged"
            source.write_bytes(original)
            try:
                os.link(source, alias)
            except OSError as exc:
                self.skipTest(f"hard links are unavailable: {exc}")
            with contextlib.redirect_stderr(io.StringIO()):
                result = main(["plan", str(source), "--out", str(alias)])
            self.assertEqual(result, 2)
            self.assertEqual(source.read_bytes(), original)

    def test_provider_outputs_refuse_active_credential_config_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            config = root / "recovery.npmrc"
            original = b"credential config must remain unchanged"
            source.write_bytes(b"not parsed because the collision check runs first")
            config.write_bytes(original)
            commands = {
                "inventory": [
                    "inventory",
                    "github",
                    "--repo",
                    "example/project",
                    "--out",
                    str(config),
                ],
                "execute preview": [
                    "execute",
                    "preview",
                    str(source),
                    str(source),
                    "--out",
                    str(config),
                ],
                "execute apply": [
                    "execute",
                    "apply",
                    str(source),
                    str(source),
                    str(source),
                    "--confirm",
                    "digest",
                    "--journal",
                    str(config),
                ],
                "observe": [
                    "observe",
                    str(source),
                    str(source),
                    str(source),
                    "--journal",
                    str(source),
                    "--out",
                    str(config),
                ],
            }
            with patch.dict(
                "closurectl.cli.os.environ",
                {"CLOSURECTL_NPM_RECOVERY_USERCONFIG": str(config)},
                clear=False,
            ):
                for name, command in commands.items():
                    with self.subTest(command=name), contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(main(command), 2)
                        self.assertEqual(config.read_bytes(), original)

    def test_plan_refuses_symbolic_link_output_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "graph.json"
            alias = Path(directory) / "plan.json"
            original = b"must remain unchanged"
            source.write_bytes(original)
            try:
                alias.symlink_to(source)
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")
            with contextlib.redirect_stderr(io.StringIO()):
                result = main(["plan", str(source), "--out", str(alias)])
            self.assertEqual(result, 2)
            self.assertEqual(source.read_bytes(), original)

    def test_demo_preflights_every_artifact_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = root / "authority-graph.json"
            original = b"existing incident artifact"
            graph.write_bytes(original)
            with contextlib.redirect_stderr(io.StringIO()):
                result = main(["demo", "--dir", directory])
            self.assertEqual(result, 2)
            self.assertEqual(graph.read_bytes(), original)
            self.assertEqual([path.name for path in root.iterdir()], [graph.name])


if __name__ == "__main__":
    unittest.main()
