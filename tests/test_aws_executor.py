from __future__ import annotations

import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from closurectl.adapters.aws import AwsCliError, _run_aws, collect_aws_inventory
from closurectl.errors import AdapterError, ExecutionError
from closurectl.execution_models import parse_execution_target
from closurectl.executors.aws import AwsExecutor
from closurectl.models import PlanAction

ACCOUNT = "123456789012"


def action() -> PlanAction:
    return PlanAction(
        action_id="close:aws-role-sessions",
        edge_id="aws-role-sessions",
        provider="aws",
        operation="revoke_role_sessions",
        target=f"aws://{ACCOUNT}/iam/roles/ProductionDeployer",
        phase="revoke_descendants",
        cost=1,
        reason="Revoke compromised AWS role sessions",
    )


class AwsHarness:
    def __init__(self) -> None:
        self.policy = None
        self.path = "/"
        self.raise_after_put = False

    def run(self, arguments, *, profile, timeout=30.0, expect_json=True):
        del timeout
        if arguments[:2] == ["iam", "get-role"]:
            return {
                "Role": {
                    "RoleName": "ProductionDeployer",
                    "Arn": f"arn:aws:iam::{ACCOUNT}:role{self.path}ProductionDeployer",
                    "Path": self.path,
                    "MaxSessionDuration": 3600,
                }
            }
        if arguments[:2] == ["iam", "get-role-policy"]:
            if self.policy is None:
                raise AwsCliError("NoSuchEntity", "not found")
            return {
                "RoleName": "ProductionDeployer",
                "PolicyName": "AWSRevokeOlderSessions",
                "PolicyDocument": self.policy,
            }
        if arguments[:2] == ["iam", "put-role-policy"]:
            document = arguments[arguments.index("--policy-document") + 1]
            self.policy = json.loads(document)
            if self.raise_after_put:
                raise AdapterError("simulated timeout after commit")
            return "" if not expect_json else None
        raise AssertionError((arguments, profile, expect_json))


def identity(profile: str) -> dict[str, str]:
    suffix = "mutator" if profile == "mutation" else "observer"
    return {
        "account": ACCOUNT,
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{suffix}",
        "user_id": suffix,
    }


class AwsExecutorTests(unittest.TestCase):
    @patch("closurectl.adapters.aws.subprocess.run")
    @patch("closurectl.adapters.aws.shutil.which", return_value="aws")
    def test_aws_child_uses_profile_without_inheriting_credentials(self, which, run) -> None:
        del which
        run.return_value.returncode = 0
        run.return_value.stdout = "{}"
        run.return_value.stderr = ""
        with patch.dict(
            os.environ,
            {
                "AWS_ACCESS_KEY_ID": "must-not-reach-child",
                "AWS_SECRET_ACCESS_KEY": "must-not-reach-child",
                "AWS_SESSION_TOKEN": "must-not-reach-child",
                "AWS_PROFILE": "wrong-profile",
            },
        ):
            _run_aws(["sts", "get-caller-identity"], profile="observer")
        child_environment = run.call_args.kwargs["env"]
        self.assertNotIn("AWS_ACCESS_KEY_ID", child_environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", child_environment)
        self.assertNotIn("AWS_SESSION_TOKEN", child_environment)
        self.assertNotIn("AWS_PROFILE", child_environment)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--profile") + 1], "observer")

    def test_exact_aws_role_target_is_parsed(self) -> None:
        target = parse_execution_target(action())
        self.assertEqual(target.account, ACCOUNT)
        self.assertEqual(target.resource_kind, "role")
        self.assertEqual(target.resource_id, "ProductionDeployer")

    def test_apply_reconciles_policy_and_observer_waits_for_propagation(self) -> None:
        harness = AwsHarness()
        current = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
        executor = AwsExecutor("mutation", "observer", now=lambda: current)
        target = parse_execution_target(action())
        requested_at = "2026-10-21T12:00:00Z"
        with (
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            preview = executor.preview(action(), target)
            result = executor.apply(
                action(),
                target,
                preview_action=preview,
                requested_at=requested_at,
            )
            self.assertEqual(result.state, "VERIFIED")
            early = executor.observe(
                action(),
                target,
                requested_at=requested_at,
                preview_action=preview,
            )
            self.assertEqual(early.status, "INDETERMINATE")
            current += timedelta(minutes=6)
            closed = executor.observe(
                action(),
                target,
                requested_at=requested_at,
                preview_action=preview,
            )
        self.assertEqual(closed.status, "VERIFIED_CLOSED")
        self.assertIn("12:00:30Z", closed.summary)

    def test_timeout_after_commit_reconciles_without_a_second_put(self) -> None:
        harness = AwsHarness()
        harness.raise_after_put = True
        executor = AwsExecutor(
            "mutation",
            "observer",
            now=lambda: datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc),
        )
        target = parse_execution_target(action())
        with (
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            preview = executor.preview(action(), target)
            result = executor.apply(
                action(),
                target,
                preview_action=preview,
                requested_at="2026-10-21T12:00:00Z",
            )
        self.assertEqual(result.state, "VERIFIED")

    def test_resume_does_not_accept_an_unchanged_old_policy(self) -> None:
        harness = AwsHarness()
        harness.policy = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": "2026-10-20T12:00:00Z",
                    }
                },
            },
        }
        executor = AwsExecutor("mutation", "observer")
        target = parse_execution_target(action())
        with (
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            preview = executor.preview(action(), target)
            result = executor.reconcile(
                action(),
                target,
                preview_action=preview,
                requested_at="2026-10-21T12:00:00Z",
            )
        self.assertEqual(result.state, "INDETERMINATE")
        self.assertIn("unchanged", result.summary)

    def test_service_linked_role_is_refused(self) -> None:
        harness = AwsHarness()
        harness.path = "/aws-service-role/example.amazonaws.com/"
        executor = AwsExecutor("mutation", "observer")
        with (
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            with self.assertRaisesRegex(ExecutionError, "service-linked"):
                executor.preview(action(), parse_execution_target(action()))

    @patch("closurectl.adapters.aws._run_aws")
    @patch("closurectl.adapters.aws._identity")
    def test_inventory_allowlists_github_oidc_trust(self, get_identity, run_aws) -> None:
        get_identity.return_value = {
            "account": ACCOUNT,
            "arn": f"arn:aws:iam::{ACCOUNT}:user/inventory",
            "user_id": "inventory",
        }

        def response(arguments, *, profile, timeout=30.0, expect_json=True):
            del profile, timeout, expect_json
            if arguments[:2] == ["iam", "get-role"]:
                return {
                    "Role": {
                        "RoleName": "ProductionDeployer",
                        "Arn": f"arn:aws:iam::{ACCOUNT}:role/ProductionDeployer",
                        "Path": "/",
                        "CreateDate": "2026-10-01T00:00:00Z",
                        "MaxSessionDuration": 3600,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRoleWithWebIdentity",
                                "Principal": {
                                    "Federated": (
                                        f"arn:aws:iam::{ACCOUNT}:oidc-provider/"
                                        "token.actions.githubusercontent.com"
                                    )
                                },
                                "Condition": {
                                    "StringEquals": {
                                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                        "not-allowlisted": "must-not-persist",
                                    },
                                    "StringLike": {
                                        "token.actions.githubusercontent.com:sub": (
                                            "repo:example/project:*"
                                        )
                                    },
                                },
                            },
                        },
                    }
                }
            if arguments[:2] == ["iam", "list-role-policies"]:
                return {"PolicyNames": ["ReadOnly"]}
            if arguments[:2] == ["iam", "list-attached-role-policies"]:
                return {
                    "AttachedPolicies": [
                        {
                            "PolicyName": "Example",
                            "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                        }
                    ]
                }
            raise AssertionError(arguments)

        run_aws.side_effect = response
        result = collect_aws_inventory(["ProductionDeployer"], profile="inventory")
        rendered = json.dumps(result)
        self.assertIn("repo:example/project:*", rendered)
        self.assertNotIn("must-not-persist", rendered)
        self.assertEqual(result["partition"], "aws")


if __name__ == "__main__":
    unittest.main()
