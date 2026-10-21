from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from closurectl.errors import AdapterError, ExecutionError
from closurectl.execution_models import parse_execution_target
from closurectl.executors.npm import NpmExecutor
from closurectl.models import PlanAction


def npm_action() -> PlanAction:
    return PlanAction(
        action_id="close:npm-token",
        edge_id="npm-token",
        provider="npm",
        operation="revoke_token",
        target="npm://registry.npmjs.org/tokens/12345678-abcd",
        phase="revoke_roots",
        cost=1,
        reason="test",
    )


class NpmExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.mutation_config = root / "mutation.npmrc"
        self.recovery_config = root / "recovery.npmrc"
        self.mutation_config.write_text("//registry.npmjs.org/:_authToken=mutation")
        self.recovery_config.write_text("//registry.npmjs.org/:_authToken=npm_NYn6_middle_jCq0")
        self.now = datetime(2026, 10, 21, 14, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def executor(self) -> NpmExecutor:
        return NpmExecutor(
            self.mutation_config,
            self.recovery_config,
            now=lambda: self.now,
        )

    def test_configs_must_be_independent(self) -> None:
        self.recovery_config.write_text(self.mutation_config.read_text())
        with self.assertRaisesRegex(ExecutionError, "share credential"):
            self.executor()

    def test_comments_cannot_hide_a_reused_credential(self) -> None:
        self.recovery_config.write_text(
            "# a different file\n//registry.npmjs.org/:_authToken=mutation\n"
        )
        with self.assertRaisesRegex(ExecutionError, "share credential"):
            self.executor()

    @patch("closurectl.executors.npm._run_npm")
    def test_preview_checks_recovery_identity_and_exact_id(self, run_npm) -> None:
        run_npm.side_effect = [
            "maintainer",
            "maintainer",
            [
                {
                    "id": "12345678-abcd",
                    "name": "compromised",
                    "readonly": False,
                    "key": "***",
                    "token": "target-token...",
                }
            ],
        ]
        subject = npm_action()
        preview = self.executor().preview(subject, parse_execution_target(subject))
        self.assertEqual(preview["provider_account"], "maintainer")
        self.assertEqual(preview["resource"]["id"], "12345678-abcd")
        rendered_calls = repr(run_npm.call_args_list)
        self.assertNotIn("_authToken", rendered_calls)
        self.assertNotIn("npm_NYn6_middle_jCq0", rendered_calls)

    @patch("closurectl.executors.npm._run_npm")
    def test_preview_refuses_to_revoke_recovery_credential(self, run_npm) -> None:
        run_npm.side_effect = [
            "maintainer",
            "maintainer",
            [
                {
                    "id": "12345678-abcd",
                    "readonly": False,
                    "key": "different-id",
                    "token": "npm_NYn6...jCq0",
                }
            ],
        ]
        subject = npm_action()
        with self.assertRaisesRegex(ExecutionError, "recovery config"):
            self.executor().preview(subject, parse_execution_target(subject))

    @patch("closurectl.executors.npm._run_npm")
    def test_revoke_reconciles_with_recovery_config(self, run_npm) -> None:
        run_npm.side_effect = [
            [{"id": "12345678-abcd", "readonly": False}],
            "",
            [],
        ]
        subject = npm_action()
        result = self.executor().apply(subject, parse_execution_target(subject))
        self.assertEqual(result.state, "VERIFIED")
        revoke_call = run_npm.call_args_list[1]
        self.assertIn("revoke", revoke_call.args[0])
        self.assertNotIn("--otp", revoke_call.args[0])

    @patch("closurectl.executors.npm._run_npm")
    def test_already_absent_token_is_idempotent(self, run_npm) -> None:
        run_npm.return_value = []
        subject = npm_action()
        result = self.executor().apply(subject, parse_execution_target(subject))
        self.assertEqual(result.state, "VERIFIED")
        self.assertFalse(any("revoke" in call.args[0] for call in run_npm.call_args_list))

    @patch("closurectl.executors.npm._run_npm")
    def test_timeout_after_commit_does_not_repeat_revoke(self, run_npm) -> None:
        run_npm.side_effect = [
            [{"id": "12345678-abcd", "readonly": False}],
            AdapterError("npm command timed out; reconcile before retrying a mutation"),
            [],
        ]
        subject = npm_action()
        result = self.executor().apply(subject, parse_execution_target(subject))
        self.assertEqual(result.state, "VERIFIED")
        revoke_calls = [call for call in run_npm.call_args_list if "revoke" in call.args[0]]
        self.assertEqual(len(revoke_calls), 1)

    @patch("closurectl.executors.npm._run_npm")
    def test_observation_waits_for_propagation_window(self, run_npm) -> None:
        run_npm.side_effect = ["maintainer", []]
        subject = npm_action()
        result = self.executor().observe(
            subject,
            parse_execution_target(subject),
            requested_at="2026-10-21T13:30:00Z",
        )
        self.assertEqual(result.status, "INDETERMINATE")

        run_npm.side_effect = ["maintainer", []]
        result = self.executor().observe(
            subject,
            parse_execution_target(subject),
            requested_at="2026-10-21T12:00:00Z",
        )
        self.assertEqual(result.status, "VERIFIED_CLOSED")


if __name__ == "__main__":
    unittest.main()
