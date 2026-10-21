"""Exact AWS IAM role-session revocation with independent observation."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from ..adapters.aws import AwsCliError, _identity, _run_aws
from ..errors import AdapterError, ExecutionError
from ..execution_models import ExecutionTarget, parse_rfc3339
from ..models import PlanAction
from ..serialization import digest_json
from .base import ApplyResult, ObservationResult

AWS_REVOKE_POLICY_NAME = "AWSRevokeOlderSessions"
AWS_CUTOFF_SKEW_SECONDS = 30
AWS_PROPAGATION_SECONDS = 300


def _utc_seconds(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _revoke_policy(cutoff: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "DateLessThan": {
                    "aws:TokenIssueTime": cutoff,
                }
            },
        },
    }


def _policy_cutoff(policy: Any) -> str:
    if not isinstance(policy, dict) or policy.get("Version") != "2012-10-17":
        raise ExecutionError(f"{AWS_REVOKE_POLICY_NAME} has an unexpected policy document")
    statement = policy.get("Statement")
    if isinstance(statement, list) and len(statement) == 1:
        statement = statement[0]
    if not isinstance(statement, dict):
        raise ExecutionError(f"{AWS_REVOKE_POLICY_NAME} has an unexpected statement")
    if (
        statement.get("Effect") != "Deny"
        or statement.get("Action") != "*"
        or statement.get("Resource") != "*"
    ):
        raise ExecutionError(f"{AWS_REVOKE_POLICY_NAME} is not the standard deny policy")
    condition = statement.get("Condition")
    if not isinstance(condition, dict) or set(condition) != {"DateLessThan"}:
        raise ExecutionError(f"{AWS_REVOKE_POLICY_NAME} has an unexpected condition")
    date_less_than = condition.get("DateLessThan")
    if not isinstance(date_less_than, dict) or set(date_less_than) != {"aws:TokenIssueTime"}:
        raise ExecutionError(f"{AWS_REVOKE_POLICY_NAME} has an unexpected cutoff condition")
    cutoff = date_less_than.get("aws:TokenIssueTime")
    parse_rfc3339(cutoff, f"{AWS_REVOKE_POLICY_NAME}.aws:TokenIssueTime")
    return str(cutoff)


class AwsExecutor:
    provider = "aws"

    def __init__(
        self,
        mutation_profile: str,
        observer_profile: str,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not mutation_profile or not observer_profile:
            raise ExecutionError("AWS mutation and observer profiles are required")
        if mutation_profile == observer_profile:
            raise ExecutionError("AWS mutation and observer profiles must be different")
        self._mutation_profile = mutation_profile
        self._observer_profile = observer_profile
        self._now = now

    @property
    def api_origin(self) -> str:
        return "https://iam.amazonaws.com"

    @staticmethod
    def _policy_reference(target: ExecutionTarget) -> str:
        return f"{target.resource_uri}/policies/{AWS_REVOKE_POLICY_NAME}"

    @staticmethod
    def _role(profile: str, target: ExecutionTarget) -> dict[str, Any]:
        raw = _run_aws(
            ["iam", "get-role", "--role-name", target.resource_id],
            profile=profile,
        )
        if not isinstance(raw, dict) or not isinstance(raw.get("Role"), dict):
            raise ExecutionError("AWS IAM get-role returned an unexpected shape")
        role = raw["Role"]
        if role.get("RoleName") != target.resource_id:
            raise ExecutionError("AWS IAM returned a different role than the target")
        arn = role.get("Arn")
        path = role.get("Path")
        if not isinstance(arn, str) or not isinstance(path, str):
            raise ExecutionError("AWS IAM role identity is incomplete")
        expected_arn_suffix = f":iam::{target.account}:role{path}{target.resource_id}"
        if not arn.startswith("arn:aws:") or not arn.endswith(expected_arn_suffix):
            raise ExecutionError("AWS IAM role ARN does not match the exact target")
        if path.startswith("/aws-service-role/"):
            raise ExecutionError("service-linked IAM roles cannot revoke active sessions")
        return {
            "name": target.resource_id,
            "arn": arn,
            "path": path,
            "max_session_duration": role.get("MaxSessionDuration"),
        }

    @staticmethod
    def _policy(profile: str, target: ExecutionTarget) -> dict[str, Any] | None:
        try:
            raw = _run_aws(
                [
                    "iam",
                    "get-role-policy",
                    "--role-name",
                    target.resource_id,
                    "--policy-name",
                    AWS_REVOKE_POLICY_NAME,
                ],
                profile=profile,
            )
        except AwsCliError as exc:
            if exc.code == "NoSuchEntity":
                return None
            raise
        if not isinstance(raw, dict) or raw.get("PolicyName") != AWS_REVOKE_POLICY_NAME:
            raise ExecutionError("AWS IAM get-role-policy returned an unexpected shape")
        document = raw.get("PolicyDocument")
        cutoff = _policy_cutoff(document)
        return {
            "cutoff": cutoff,
            "document_digest": digest_json(document),
        }

    def _snapshot(self, profile: str, target: ExecutionTarget) -> dict[str, Any]:
        role = self._role(profile, target)
        policy = self._policy(profile, target)
        return {
            "role": role,
            "revoke_policy_present": policy is not None,
            "revoke_before": policy["cutoff"] if policy else "",
            "revoke_policy_digest": policy["document_digest"] if policy else "",
        }

    def binding(self, action: PlanAction, target: ExecutionTarget) -> dict[str, str]:
        del action
        mutation = _identity(self._mutation_profile)
        observer = _identity(self._observer_profile)
        if mutation["account"] != target.account or observer["account"] != target.account:
            raise ExecutionError("AWS profiles and exact role target must use the same account")
        if mutation["arn"] == observer["arn"]:
            raise ExecutionError("AWS observer must be a different principal")
        return {
            "provider_account": target.account,
            "api_origin": self.api_origin,
            "mutation_identity": f"aws:{mutation['arn']}",
            "observer_identity": f"aws:{observer['arn']}",
        }

    def preview(self, action: PlanAction, target: ExecutionTarget) -> dict[str, Any]:
        binding = self.binding(action, target)
        mutation_snapshot = self._snapshot(self._mutation_profile, target)
        observer_snapshot = self._snapshot(self._observer_profile, target)
        if mutation_snapshot != observer_snapshot:
            raise ExecutionError("AWS mutation and observer profiles see different role state")
        return {
            **binding,
            "current_state": (
                f"sessions_revoked_before:{mutation_snapshot['revoke_before']}"
                if mutation_snapshot["revoke_policy_present"]
                else "no_role_session_revocation_policy"
            ),
            "effect": (
                "replace AWSRevokeOlderSessions and deny every role session issued before "
                "the mutation time plus 30 seconds"
            ),
            "resource": mutation_snapshot,
        }

    @staticmethod
    def _requested_cutoff_is_current(cutoff: str, requested_at: str) -> bool:
        requested = parse_rfc3339(requested_at, "journal.requested_at")
        parsed_cutoff = parse_rfc3339(cutoff, "AWS role-session cutoff")
        delta = (parsed_cutoff - requested).total_seconds()
        return 15 <= delta <= 300

    def _reconcile(
        self,
        target: ExecutionTarget,
        preview_action: Mapping[str, Any],
        requested_at: str,
        *,
        profile: str,
    ) -> ApplyResult:
        reference = self._policy_reference(target)
        try:
            current = self._snapshot(profile, target)
        except (AdapterError, ExecutionError) as exc:
            return ApplyResult(
                "INDETERMINATE",
                f"AWS role-session reconciliation failed: {exc}",
                reference,
            )
        previous = preview_action.get("resource")
        if not isinstance(previous, dict):
            return ApplyResult("INDETERMINATE", "AWS preview resource is invalid", reference)
        if not current["revoke_policy_present"]:
            return ApplyResult(
                "INDETERMINATE",
                "AWSRevokeOlderSessions is absent; mutation was not repeated",
                reference,
            )
        if current["revoke_policy_digest"] == previous.get("revoke_policy_digest"):
            return ApplyResult(
                "INDETERMINATE",
                "AWSRevokeOlderSessions is unchanged from preview; mutation was not repeated",
                reference,
            )
        if not self._requested_cutoff_is_current(current["revoke_before"], requested_at):
            return ApplyResult(
                "INDETERMINATE",
                "AWSRevokeOlderSessions cutoff is not bound to the recorded request time",
                reference,
            )
        return ApplyResult(
            "VERIFIED",
            f"AWS role sessions issued before {current['revoke_before']} are denied",
            reference,
        )

    def apply(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        preview_action: Mapping[str, Any] | None = None,
        requested_at: str = "",
    ) -> ApplyResult:
        del action
        if preview_action is None or not requested_at:
            raise ExecutionError("AWS apply requires the confirmed preview and request time")
        cutoff = _utc_seconds(
            self._now().astimezone(timezone.utc) + timedelta(seconds=AWS_CUTOFF_SKEW_SECONDS)
        )
        document = json.dumps(_revoke_policy(cutoff), sort_keys=True, separators=(",", ":"))
        try:
            _run_aws(
                [
                    "iam",
                    "put-role-policy",
                    "--role-name",
                    target.resource_id,
                    "--policy-name",
                    AWS_REVOKE_POLICY_NAME,
                    "--policy-document",
                    document,
                ],
                profile=self._mutation_profile,
                expect_json=False,
            )
        except AdapterError:
            pass
        return self._reconcile(
            target,
            preview_action,
            requested_at,
            profile=self._mutation_profile,
        )

    def reconcile(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        preview_action: Mapping[str, Any] | None = None,
        requested_at: str = "",
    ) -> ApplyResult:
        del action
        if preview_action is None or not requested_at:
            raise ExecutionError(
                "AWS reconciliation requires the confirmed preview and request time"
            )
        return self._reconcile(
            target,
            preview_action,
            requested_at,
            profile=self._mutation_profile,
        )

    def observe(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        requested_at: str | None,
        preview_action: Mapping[str, Any] | None = None,
    ) -> ObservationResult:
        del action
        reference = self._policy_reference(target)
        try:
            observer = _identity(self._observer_profile)
            current = self._snapshot(self._observer_profile, target)
        except (AdapterError, ExecutionError) as exc:
            return ObservationResult(
                "INDETERMINATE",
                f"independent AWS observation failed: {exc}",
                reference,
                "aws:independent-observer",
                target.account,
                self.api_origin,
                "aws-iam-role-policy",
            )
        if requested_at is None or preview_action is None:
            status = "INDETERMINATE"
            summary = "AWS revocation policy is not bound to a recorded mutation request"
        elif not current["revoke_policy_present"]:
            status = "STILL_OPEN"
            summary = "AWSRevokeOlderSessions is absent"
        elif current["revoke_policy_digest"] == preview_action["resource"].get(
            "revoke_policy_digest"
        ):
            status = "STILL_OPEN"
            summary = "AWSRevokeOlderSessions is unchanged from the confirmed preview"
        elif not self._requested_cutoff_is_current(current["revoke_before"], requested_at):
            status = "INDETERMINATE"
            summary = "AWS role-session cutoff is not bound to the recorded mutation request"
        else:
            cutoff = parse_rfc3339(current["revoke_before"], "AWS role-session cutoff")
            age = (self._now().astimezone(timezone.utc) - cutoff).total_seconds()
            if age < AWS_PROPAGATION_SECONDS:
                status = "INDETERMINATE"
                summary = (
                    "AWSRevokeOlderSessions is present but the five-minute propagation "
                    "window has not elapsed"
                )
            else:
                status = "VERIFIED_CLOSED"
                summary = (
                    f"AWSRevokeOlderSessions still denies role sessions issued before "
                    f"{current['revoke_before']} after the propagation window"
                )
        return ObservationResult(
            status,
            summary,
            reference,
            f"aws:{observer['arn']}",
            target.account,
            self.api_origin,
            "aws-iam-role-policy",
        )
