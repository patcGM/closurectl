from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from closurectl.adapters.aws import (
    MAX_OUTPUT_BYTES,
    AwsCliError,
    _run_aws,
    collect_aws_inventory,
)
from closurectl.errors import AdapterError, ExecutionError
from closurectl.execution import apply_execution, create_execution_preview
from closurectl.execution_models import parse_execution_target
from closurectl.executors.aws import AWS_REVOKE_POLICY_PREFIX, AwsExecutor
from closurectl.models import AuthorityGraph, PlanAction
from closurectl.planner import plan_closure

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


def aws_graph() -> AuthorityGraph:
    return AuthorityGraph.from_dict(
        {
            "schema_version": "1",
            "title": "AWS execution",
            "nodes": [
                {"id": "sessions", "kind": "temporary_credentials", "label": "Sessions"},
                {"id": "effect", "kind": "consequential_sink", "label": "AWS effect"},
            ],
            "edges": [
                {
                    "id": "aws-role-sessions",
                    "source": "sessions",
                    "target": "effect",
                    "kind": "derived_session",
                    "label": "Revoke role sessions",
                    "revocable": True,
                    "cost": 1,
                    "enforcement": {
                        "provider": "aws",
                        "operation": "revoke_role_sessions",
                        "target": f"aws://{ACCOUNT}/iam/roles/ProductionDeployer",
                        "phase": "revoke_descendants",
                    },
                }
            ],
            "roots": ["sessions"],
            "sinks": ["effect"],
        }
    )


class AwsHarness:
    def __init__(self) -> None:
        self.policies: dict[str, dict] = {}
        self.path = "/"
        self.role_id = "AROAEXAMPLECLOSURECTL"
        self.raise_after_put = False
        self.interrupt_after_put = False
        self.put_count = 0
        self.put_max_attempts: list[int | None] = []

    def run(
        self,
        arguments,
        *,
        profile,
        timeout=30.0,
        expect_json=True,
        max_attempts=None,
    ):
        del timeout
        if arguments[:2] == ["iam", "get-role"]:
            return {
                "Role": {
                    "RoleName": "ProductionDeployer",
                    "RoleId": self.role_id,
                    "Arn": f"arn:aws:iam::{ACCOUNT}:role{self.path}ProductionDeployer",
                    "Path": self.path,
                    "MaxSessionDuration": 3600,
                }
            }
        if arguments[:2] == ["iam", "get-role-policy"]:
            policy_name = arguments[arguments.index("--policy-name") + 1]
            if policy_name not in self.policies:
                raise AwsCliError("NoSuchEntity", "not found")
            return {
                "RoleName": "ProductionDeployer",
                "PolicyName": policy_name,
                "PolicyDocument": self.policies[policy_name],
            }
        if arguments[:2] == ["iam", "put-role-policy"]:
            self.put_count += 1
            self.put_max_attempts.append(max_attempts)
            policy_name = arguments[arguments.index("--policy-name") + 1]
            document = arguments[arguments.index("--policy-document") + 1]
            self.policies[policy_name] = json.loads(document)
            if self.interrupt_after_put:
                raise KeyboardInterrupt
            if self.raise_after_put:
                raise AdapterError("simulated timeout after commit")
            return "" if not expect_json else None
        raise AssertionError((arguments, profile, expect_json, max_attempts))


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

        def complete(*args, **kwargs):
            del args
            kwargs["stdout"].write(b"{}")
            return type("Completed", (), {"returncode": 0})()

        run.side_effect = complete
        with patch.dict(
            os.environ,
            {
                "AWS_ACCESS_KEY_ID": "must-not-reach-child",
                "AWS_SECRET_ACCESS_KEY": "must-not-reach-child",
                "AWS_SESSION_TOKEN": "must-not-reach-child",
                "AWS_PROFILE": "wrong-profile",
                "AWS_MAX_ATTEMPTS": "99",
            },
        ):
            _run_aws(
                ["sts", "get-caller-identity"],
                profile="observer",
                max_attempts=1,
            )
        child_environment = run.call_args.kwargs["env"]
        self.assertNotIn("AWS_ACCESS_KEY_ID", child_environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", child_environment)
        self.assertNotIn("AWS_SESSION_TOKEN", child_environment)
        self.assertNotIn("AWS_PROFILE", child_environment)
        self.assertEqual(child_environment["AWS_MAX_ATTEMPTS"], "1")
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--profile") + 1], "observer")

    @patch("closurectl.adapters.aws.subprocess.run")
    @patch("closurectl.adapters.aws.shutil.which", return_value="aws")
    def test_aws_stdout_and_stderr_are_bounded(self, which, run) -> None:
        del which
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):

                def complete(*args, **kwargs):
                    del args
                    kwargs["stdout"].write(
                        b"{}" if stream == "stderr" else b"x" * (MAX_OUTPUT_BYTES + 1)
                    )
                    if stream == "stderr":
                        kwargs["stderr"].write(b"x" * (MAX_OUTPUT_BYTES + 1))
                    return type("Completed", (), {"returncode": 0})()

                run.side_effect = complete
                with self.assertRaisesRegex(AdapterError, "safety limit"):
                    _run_aws(["sts", "get-caller-identity"], profile="observer")

    def test_exact_aws_role_target_is_parsed(self) -> None:
        target = parse_execution_target(action())
        self.assertEqual(target.account, ACCOUNT)
        self.assertEqual(target.resource_kind, "role")
        self.assertEqual(target.resource_id, "ProductionDeployer")

    def test_profiles_for_the_same_role_are_not_independent(self) -> None:
        harness = AwsHarness()

        def same_role_identity(profile: str) -> dict[str, str]:
            return {
                "account": ACCOUNT,
                "arn": (f"arn:aws:sts::{ACCOUNT}:assumed-role/shared-role/{profile}-session"),
                "user_id": f"AROAEXAMPLESHARED:{profile}-session",
            }

        executor = AwsExecutor("mutation", "observer")
        with (
            patch(
                "closurectl.executors.aws._identity",
                side_effect=same_role_identity,
            ),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            with self.assertRaisesRegex(ExecutionError, "different principal"):
                executor.preview(action(), parse_execution_target(action()))

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
            policy_name = preview["resource"]["policy_name"]
            self.assertTrue(policy_name.startswith(AWS_REVOKE_POLICY_PREFIX))
            self.assertEqual(preview["resource"]["role"]["role_id"], harness.role_id)
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
            current += timedelta(minutes=21)
            closed = executor.observe(
                action(),
                target,
                requested_at=requested_at,
                preview_action=preview,
            )
        self.assertEqual(closed.status, "VERIFIED_CLOSED")
        self.assertIn(policy_name, closed.reference)
        self.assertIn("12:15:30Z", closed.summary)
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1] / "schemas" / "execution-preview.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(
            {
                "schema_version": "1",
                "created_at": "2026-10-21T12:00:00Z",
                "expires_at": "2026-10-21T12:15:00Z",
                "graph_digest": "0" * 64,
                "plan_digest": "1" * 64,
                "actions": [
                    {
                        "action_id": action().action_id,
                        "edge_id": action().edge_id,
                        "provider": action().provider,
                        "operation": action().operation,
                        "phase": action().phase,
                        "target": action().target,
                        "target_details": target.to_dict(),
                        **preview,
                    }
                ],
                "preview_digest": "2" * 64,
            }
        )

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
            policy_name = preview["resource"]["policy_name"]
            harness.policies[policy_name]["Statement"] = [
                harness.policies[policy_name]["Statement"]
            ]
            resumed = executor.reconcile(
                action(),
                target,
                preview_action=preview,
                requested_at="2026-10-21T12:00:00Z",
            )
        self.assertEqual(result.state, "VERIFIED")
        self.assertEqual(resumed.state, "VERIFIED")
        self.assertEqual(harness.put_count, 1)
        self.assertEqual(harness.put_max_attempts, [1])

    def test_apply_refuses_a_preview_after_its_bound_cutoff(self) -> None:
        harness = AwsHarness()
        current = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
        executor = AwsExecutor("mutation", "observer", now=lambda: current)
        target = parse_execution_target(action())
        with (
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            preview = executor.preview(action(), target)
            current += timedelta(minutes=16)
            result = executor.apply(
                action(),
                target,
                preview_action=preview,
                requested_at="2026-10-21T12:16:00Z",
            )
        self.assertEqual(result.state, "INDETERMINATE")
        self.assertIn("cutoff has passed", result.summary)
        self.assertEqual(harness.put_count, 0)

    def test_execution_engine_revalidates_bound_preview_without_replanning(self) -> None:
        harness = AwsHarness()
        current = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
        executor = AwsExecutor("mutation", "observer", now=lambda: current)
        graph = aws_graph()
        plan = plan_closure(graph)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            preview = create_execution_preview(
                graph,
                plan,
                {"aws": executor},
                now=lambda: current,
            )
            planned_cutoff = preview["actions"][0]["resource"]["planned_cutoff"]
            current += timedelta(seconds=10)
            summary = apply_execution(
                graph,
                plan,
                preview,
                preview["preview_digest"],
                Path(directory) / "execution.jsonl",
                {"aws": executor},
                now=lambda: current,
            )
        self.assertTrue(summary["complete"])
        self.assertEqual(planned_cutoff, "2026-10-21T12:15:30Z")
        self.assertEqual(harness.put_count, 1)

    def test_engine_resume_after_committed_put_never_mutates_twice(self) -> None:
        harness = AwsHarness()
        harness.interrupt_after_put = True
        current = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
        executor = AwsExecutor("mutation", "observer", now=lambda: current)
        graph = aws_graph()
        plan = plan_closure(graph)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            preview = create_execution_preview(
                graph,
                plan,
                {"aws": executor},
                now=lambda: current,
            )
            journal = Path(directory) / "execution.jsonl"
            with self.assertRaises(KeyboardInterrupt):
                apply_execution(
                    graph,
                    plan,
                    preview,
                    preview["preview_digest"],
                    journal,
                    {"aws": executor},
                    now=lambda: current,
                )
            harness.interrupt_after_put = False
            resumed = apply_execution(
                graph,
                plan,
                preview,
                preview["preview_digest"],
                journal,
                {"aws": executor},
                resume=True,
                now=lambda: current,
            )
        self.assertTrue(resumed["complete"])
        self.assertEqual(harness.put_count, 1)

    def test_unique_policy_does_not_overwrite_aws_managed_revocation_name(self) -> None:
        harness = AwsHarness()
        standard_policy = {
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
        harness.policies["AWSRevokeOlderSessions"] = standard_policy
        executor = AwsExecutor("mutation", "observer")
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
        self.assertEqual(harness.policies["AWSRevokeOlderSessions"], standard_policy)
        self.assertIn(preview["resource"]["policy_name"], harness.policies)

    def test_role_delete_and_recreate_is_refused_before_mutation(self) -> None:
        harness = AwsHarness()
        executor = AwsExecutor("mutation", "observer")
        target = parse_execution_target(action())
        with (
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            preview = executor.preview(action(), target)
            harness.role_id = "AROARECREATEDROLEID"
            result = executor.apply(
                action(),
                target,
                preview_action=preview,
                requested_at="2026-10-21T12:00:00Z",
            )
        self.assertEqual(result.state, "INDETERMINATE")
        self.assertIn("role ID changed", result.summary)
        self.assertEqual(harness.put_count, 0)

    def test_observer_requires_the_exact_preview_bound_policy(self) -> None:
        harness = AwsHarness()
        current = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
        executor = AwsExecutor("mutation", "observer", now=lambda: current)
        target = parse_execution_target(action())
        with (
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            preview = executor.preview(action(), target)
            executor.apply(
                action(),
                target,
                preview_action=preview,
                requested_at="2026-10-21T12:00:00Z",
            )
            policy_name = preview["resource"]["policy_name"]
            harness.policies[policy_name]["Statement"]["Condition"]["DateLessThan"][
                "aws:TokenIssueTime"
            ] = "2026-10-21T12:00:31Z"
            current += timedelta(minutes=6)
            observed = executor.observe(
                action(),
                target,
                requested_at="2026-10-21T12:00:00Z",
                preview_action=preview,
            )
        self.assertEqual(observed.status, "INDETERMINATE")
        self.assertIn("exactly match", observed.summary)

    def test_service_linked_role_is_refused(self) -> None:
        harness = AwsHarness()
        harness.path = "/aws-service-role/example.amazonaws.com/"
        executor = AwsExecutor("mutation", "observer")
        with (
            patch("closurectl.executors.aws._identity", side_effect=identity),
            patch("closurectl.executors.aws._run_aws", side_effect=harness.run),
        ):
            with self.assertRaisesRegex(ExecutionError, "AWS-managed"):
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
                        "RoleId": "AROAEXAMPLEPRODUCTION",
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
