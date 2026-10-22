from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from closurectl.cli import main
from closurectl.errors import ExecutionError, ValidationError
from closurectl.executors.aws import AwsExecutor
from closurectl.executors.github import GitHubExecutor
from closurectl.executors.npm import NpmExecutor
from closurectl.readiness import _CHECKS, assess_readiness


class ReadinessTests(unittest.TestCase):
    @patch("closurectl.executors.github._identity")
    def test_github_readiness_authenticates_distinct_accounts(self, identity) -> None:
        identity.side_effect = [("mutator", 1), ("observer", 2)]
        result = GitHubExecutor("mutation-token", "observer-token").readiness()
        self.assertEqual(result["mutation_identity"], "github:mutator#1")
        self.assertEqual(result["observer_identity"], "github:observer#2")
        self.assertIn("distinct", result["checks"][-1])

    @patch("closurectl.executors.github._identity")
    def test_github_readiness_rejects_one_account_with_two_tokens(self, identity) -> None:
        identity.side_effect = [("maintainer", 1), ("maintainer", 1)]
        with self.assertRaisesRegex(ExecutionError, "different account"):
            GitHubExecutor("mutation-token", "observer-token").readiness()

    def test_npm_readiness_checks_recovery_listing_without_returning_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mutation = Path(directory) / "mutation.npmrc"
            recovery = Path(directory) / "recovery.npmrc"
            mutation.write_text("//registry.npmjs.org/:_authToken=mutation-secret")
            recovery.write_text("//registry.npmjs.org/:_authToken=recovery-secret")
            with (
                patch("closurectl.executors.npm.require_supported_npm_version"),
                patch(
                    "closurectl.executors.npm._run_npm",
                    side_effect=["maintainer", "maintainer", []],
                ) as run_npm,
            ):
                result = NpmExecutor(mutation, recovery).readiness()
        self.assertEqual(result["provider_account"], "maintainer")
        self.assertEqual(run_npm.call_count, 3)
        self.assertNotIn("mutation-secret", repr(result))
        self.assertNotIn("recovery-secret", repr(result))

    @patch("closurectl.executors.aws._identity")
    def test_aws_readiness_requires_distinct_principals_in_one_account(self, identity) -> None:
        identity.side_effect = [
            {
                "account": "123456789012",
                "arn": "arn:aws:iam::123456789012:role/mutator",
                "user_id": "AROA_MUTATOR:session",
            },
            {
                "account": "123456789012",
                "arn": "arn:aws:iam::123456789012:role/observer",
                "user_id": "AROA_OBSERVER:session",
            },
        ]
        result = AwsExecutor("mutation", "observer").readiness()
        self.assertEqual(result["provider_account"], "123456789012")
        self.assertEqual(result["mutation_identity"], "aws-principal:AROA_MUTATOR")
        self.assertEqual(result["observer_identity"], "aws-principal:AROA_OBSERVER")

    def test_assessment_reports_every_selected_provider_failure(self) -> None:
        def ready(_environment):
            return {
                "mutation_identity": "github:mutator#1",
                "observer_identity": "github:observer#2",
                "checks": [],
                "limitations": [],
            }

        def not_ready(_environment):
            raise ValidationError("observer profile is unavailable")

        with patch.dict(_CHECKS, {"github": ready, "aws": not_ready}, clear=False):
            result = assess_readiness(["github", "aws"], environment={})
        self.assertEqual(result["status"], "NOT_READY")
        self.assertEqual([item["status"] for item in result["providers"]], ["READY", "NOT_READY"])
        self.assertEqual(result["providers"][1]["error"], "observer profile is unavailable")

    def test_assessment_routes_environment_to_every_provider(self) -> None:
        details = {
            "mutation_identity": "test:mutation",
            "observer_identity": "test:observer",
            "checks": [],
            "limitations": [],
        }
        environment = {
            "GITHUB_TOKEN": "github-mutation",
            "CLOSURECTL_GITHUB_OBSERVER_TOKEN": "github-observer",
            "CLOSURECTL_NPM_MUTATION_USERCONFIG": "mutation.npmrc",
            "CLOSURECTL_NPM_RECOVERY_USERCONFIG": "recovery.npmrc",
            "CLOSURECTL_AWS_MUTATION_PROFILE": "mutation",
            "CLOSURECTL_AWS_OBSERVER_PROFILE": "observer",
        }
        with (
            patch("closurectl.readiness.GitHubExecutor") as github,
            patch("closurectl.readiness.NpmExecutor") as npm,
            patch("closurectl.readiness.AwsExecutor") as aws,
        ):
            for constructor in (github, npm, aws):
                constructor.return_value.readiness.return_value = details
            result = assess_readiness(["github", "npm", "aws"], environment=environment)
        self.assertEqual(result["status"], "READY")
        self.assertEqual(
            [item["provider"] for item in result["providers"]], ["github", "npm", "aws"]
        )
        github.assert_called_once_with(
            "github-mutation",
            "github-observer",
            api_url="https://api.github.com",
        )
        npm.assert_called_once_with(
            "mutation.npmrc",
            "recovery.npmrc",
            registry="https://registry.npmjs.org",
        )
        aws.assert_called_once_with("mutation", "observer")

    def test_assessment_rejects_duplicate_providers(self) -> None:
        with self.assertRaisesRegex(ValidationError, "unique"):
            assess_readiness(["github", "github"], environment={})

    @patch("closurectl.cli.assess_readiness")
    def test_cli_json_readiness_uses_incomplete_exit_code(self, assess) -> None:
        assess.return_value = {
            "status": "NOT_READY",
            "providers": [
                {
                    "provider": "github",
                    "status": "NOT_READY",
                    "error": "observer credential is unavailable",
                }
            ],
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["--json", "readiness", "--provider", "github"])
        self.assertEqual(result, 5)
        self.assertEqual(json.loads(output.getvalue())["status"], "NOT_READY")

    @patch("closurectl.cli.assess_readiness")
    def test_cli_text_readiness_explains_checks_and_limitations(self, assess) -> None:
        assess.return_value = {
            "status": "READY",
            "providers": [
                {
                    "provider": "github",
                    "status": "READY",
                    "mutation_identity": "github:mutator#1",
                    "observer_identity": "github:observer#2",
                    "checks": ["accounts are distinct"],
                    "limitations": ["exact target is checked by preview"],
                }
            ],
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["readiness", "--provider", "github"])
        self.assertEqual(result, 0)
        self.assertIn("readiness: READY", output.getvalue())
        self.assertIn("check: accounts are distinct", output.getvalue())
        self.assertIn("limitation: exact target is checked by preview", output.getvalue())


if __name__ == "__main__":
    unittest.main()
