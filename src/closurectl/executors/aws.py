"""Exact AWS IAM role-session revocation with independent observation."""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from ..adapters.aws import AwsCliError, _identity, _run_aws
from ..errors import AdapterError, ExecutionError, ValidationError
from ..execution_models import PREVIEW_TTL_SECONDS, ExecutionTarget, parse_rfc3339
from ..models import PlanAction
from ..serialization import digest_json
from .base import ApplyResult, ObservationResult

AWS_REVOKE_POLICY_PREFIX = "ClosureCtlRevokeOlderSessions-"
AWS_CUTOFF_SKEW_SECONDS = PREVIEW_TTL_SECONDS + 30
AWS_PROPAGATION_SECONDS = 300
AWS_POLICY_SUFFIX_LENGTH = 32


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


def _normalized_policy(policy: Any, policy_name: str) -> dict[str, Any]:
    if (
        not isinstance(policy, dict)
        or set(policy) != {"Version", "Statement"}
        or policy.get("Version") != "2012-10-17"
    ):
        raise ExecutionError(f"{policy_name} has an unexpected policy document")
    statement = policy.get("Statement")
    if isinstance(statement, list) and len(statement) == 1:
        statement = statement[0]
    if not isinstance(statement, dict) or set(statement) != {
        "Effect",
        "Action",
        "Resource",
        "Condition",
    }:
        raise ExecutionError(f"{policy_name} has an unexpected statement")
    if (
        statement.get("Effect") != "Deny"
        or statement.get("Action") != "*"
        or statement.get("Resource") != "*"
    ):
        raise ExecutionError(f"{policy_name} is not the standard deny policy")
    condition = statement.get("Condition")
    if not isinstance(condition, dict) or set(condition) != {"DateLessThan"}:
        raise ExecutionError(f"{policy_name} has an unexpected condition")
    date_less_than = condition.get("DateLessThan")
    if not isinstance(date_less_than, dict) or set(date_less_than) != {"aws:TokenIssueTime"}:
        raise ExecutionError(f"{policy_name} has an unexpected cutoff condition")
    cutoff = date_less_than.get("aws:TokenIssueTime")
    parse_rfc3339(cutoff, f"{policy_name}.aws:TokenIssueTime")
    return _revoke_policy(str(cutoff))


def _bound_policy_name(
    action: PlanAction,
    target: ExecutionTarget,
    *,
    role_id: str,
    cutoff: str,
    document_digest: str,
    operation_id: str,
) -> str:
    binding_digest = digest_json(
        {
            "action_id": action.action_id,
            "target": target.resource_uri,
            "role_id": role_id,
            "cutoff": cutoff,
            "document_digest": document_digest,
            "operation_id": operation_id,
        }
    )
    return f"{AWS_REVOKE_POLICY_PREFIX}{binding_digest[:AWS_POLICY_SUFFIX_LENGTH]}"


def _principal_id(identity: Mapping[str, str]) -> str:
    principal_id = identity["user_id"].split(":", 1)[0]
    if not principal_id:
        raise ExecutionError("AWS STS identity has no stable principal ID")
    return principal_id


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
    def _policy_reference(target: ExecutionTarget, policy_name: str) -> str:
        return f"{target.resource_uri}/policies/{policy_name}"

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
        role_id = role.get("RoleId")
        max_session_duration = role.get("MaxSessionDuration")
        if (
            not isinstance(arn, str)
            or not isinstance(path, str)
            or not isinstance(role_id, str)
            or not role_id
            or isinstance(max_session_duration, bool)
            or not isinstance(max_session_duration, int)
        ):
            raise ExecutionError("AWS IAM role identity is incomplete")
        arn_parts = arn.split(":", 5)
        expected_resource = f"role{path}{target.resource_id}"
        if (
            len(arn_parts) != 6
            or arn_parts[:4] != ["arn", "aws", "iam", ""]
            or arn_parts[4] != target.account
            or arn_parts[5] != expected_resource
        ):
            raise ExecutionError("AWS IAM role ARN does not match the exact target")
        if path.startswith(("/aws-service-role/", "/aws-reserved/sso.amazonaws.com/")):
            raise ExecutionError("AWS-managed IAM roles cannot revoke active sessions")
        return {
            "name": target.resource_id,
            "arn": arn,
            "path": path,
            "role_id": role_id,
            "max_session_duration": max_session_duration,
        }

    @staticmethod
    def _policy(
        profile: str,
        target: ExecutionTarget,
        policy_name: str,
    ) -> dict[str, Any] | None:
        try:
            raw = _run_aws(
                [
                    "iam",
                    "get-role-policy",
                    "--role-name",
                    target.resource_id,
                    "--policy-name",
                    policy_name,
                ],
                profile=profile,
            )
        except AwsCliError as exc:
            if exc.code == "NoSuchEntity":
                return None
            raise
        if (
            not isinstance(raw, dict)
            or raw.get("RoleName") != target.resource_id
            or raw.get("PolicyName") != policy_name
        ):
            raise ExecutionError("AWS IAM get-role-policy returned an unexpected shape")
        document = raw.get("PolicyDocument")
        normalized = _normalized_policy(document, policy_name)
        cutoff = normalized["Statement"]["Condition"]["DateLessThan"]["aws:TokenIssueTime"]
        return {
            "cutoff": cutoff,
            "document_digest": digest_json(normalized),
        }

    def _snapshot(
        self,
        profile: str,
        target: ExecutionTarget,
        policy_name: str,
    ) -> dict[str, Any]:
        role = self._role(profile, target)
        policy = self._policy(profile, target, policy_name)
        return {
            "role": role,
            "policy": policy,
        }

    def _identities(
        self,
    ) -> tuple[Mapping[str, str], Mapping[str, str], str, str]:
        mutation = _identity(self._mutation_profile)
        observer = _identity(self._observer_profile)
        if mutation["account"] != observer["account"]:
            raise ExecutionError("AWS mutation and observer profiles must use the same account")
        mutation_principal = _principal_id(mutation)
        observer_principal = _principal_id(observer)
        if mutation_principal == observer_principal:
            raise ExecutionError("AWS observer must be a different principal")
        return mutation, observer, mutation_principal, observer_principal

    def readiness(self) -> dict[str, Any]:
        """Authenticate both profiles without reading or mutating an IAM role."""
        mutation, _, mutation_principal, observer_principal = self._identities()
        return {
            "provider_account": mutation["account"],
            "api_origin": self.api_origin,
            "mutation_identity": f"aws-principal:{mutation_principal}",
            "observer_identity": f"aws-principal:{observer_principal}",
            "checks": [
                "mutation profile authenticated",
                "observer profile authenticated",
                "profiles use the same AWS account",
                "mutation and observer principals are distinct",
            ],
            "limitations": [
                "Exact-role read and write permissions are checked by execute preview."
            ],
        }

    def binding(self, action: PlanAction, target: ExecutionTarget) -> dict[str, str]:
        del action
        mutation, observer, mutation_principal, observer_principal = self._identities()
        if mutation["account"] != target.account or observer["account"] != target.account:
            raise ExecutionError("AWS profiles and exact role target must use the same account")
        return {
            "provider_account": target.account,
            "api_origin": self.api_origin,
            "mutation_identity": f"aws-principal:{mutation_principal}",
            "observer_identity": f"aws-principal:{observer_principal}",
        }

    def preview(self, action: PlanAction, target: ExecutionTarget) -> dict[str, Any]:
        binding = self.binding(action, target)
        mutation_role = self._role(self._mutation_profile, target)
        observer_role = self._role(self._observer_profile, target)
        if mutation_role != observer_role:
            raise ExecutionError("AWS mutation and observer profiles see different role state")
        cutoff = _utc_seconds(
            self._now().astimezone(timezone.utc) + timedelta(seconds=AWS_CUTOFF_SKEW_SECONDS)
        )
        document = _revoke_policy(cutoff)
        document_digest = digest_json(document)
        operation_id = secrets.token_hex(16)
        policy_name = _bound_policy_name(
            action,
            target,
            role_id=mutation_role["role_id"],
            cutoff=cutoff,
            document_digest=document_digest,
            operation_id=operation_id,
        )
        mutation_policy = self._policy(self._mutation_profile, target, policy_name)
        observer_policy = self._policy(self._observer_profile, target, policy_name)
        if mutation_policy != observer_policy:
            raise ExecutionError("AWS profiles see different exact containment-policy state")
        if mutation_policy is not None:
            raise ExecutionError("preview-bound AWS containment policy already exists")
        return {
            **binding,
            "current_state": f"policy_absent:{policy_name}",
            "effect": (
                f"create {policy_name} and deny every role session issued before {cutoff}; "
                "the policy is never removed automatically"
            ),
            "resource": {
                "role": mutation_role,
                "policy_name": policy_name,
                "operation_id": operation_id,
                "planned_cutoff": cutoff,
                "planned_policy_digest": document_digest,
            },
        }

    @staticmethod
    def _confirmed_policy(
        action: PlanAction,
        target: ExecutionTarget,
        preview_action: Mapping[str, Any],
    ) -> tuple[dict[str, Any], str, str, dict[str, Any], str]:
        resource = preview_action.get("resource")
        if not isinstance(resource, dict) or set(resource) != {
            "role",
            "policy_name",
            "operation_id",
            "planned_cutoff",
            "planned_policy_digest",
        }:
            raise ExecutionError("AWS confirmed preview resource is invalid")
        role = resource.get("role")
        if not isinstance(role, dict) or set(role) != {
            "name",
            "arn",
            "path",
            "role_id",
            "max_session_duration",
        }:
            raise ExecutionError("AWS confirmed preview role identity is invalid")
        if (
            role.get("name") != target.resource_id
            or not isinstance(role.get("arn"), str)
            or not isinstance(role.get("path"), str)
            or not isinstance(role.get("role_id"), str)
            or not role["role_id"]
            or isinstance(role.get("max_session_duration"), bool)
            or not isinstance(role.get("max_session_duration"), int)
        ):
            raise ExecutionError("AWS confirmed preview role identity does not match the target")
        arn_parts = role["arn"].split(":", 5)
        expected_resource = f"role{role['path']}{target.resource_id}"
        if (
            len(arn_parts) != 6
            or arn_parts[:4] != ["arn", "aws", "iam", ""]
            or arn_parts[4] != target.account
            or arn_parts[5] != expected_resource
            or not role["path"].startswith("/")
            or role["path"].startswith(("/aws-service-role/", "/aws-reserved/sso.amazonaws.com/"))
            or not 3_600 <= role["max_session_duration"] <= 43_200
        ):
            raise ExecutionError("AWS confirmed preview role metadata is invalid")
        cutoff = resource.get("planned_cutoff")
        policy_name = resource.get("policy_name")
        operation_id = resource.get("operation_id")
        document_digest = resource.get("planned_policy_digest")
        parse_rfc3339(cutoff, "AWS preview planned_cutoff")
        if (
            not isinstance(policy_name, str)
            or not policy_name.startswith(AWS_REVOKE_POLICY_PREFIX)
            or not isinstance(operation_id, str)
            or not re.fullmatch(r"[a-f0-9]{32}", operation_id)
            or not isinstance(document_digest, str)
        ):
            raise ExecutionError("AWS confirmed preview policy binding is invalid")
        document = _revoke_policy(str(cutoff))
        if digest_json(document) != document_digest:
            raise ExecutionError("AWS confirmed preview policy digest is invalid")
        expected_name = _bound_policy_name(
            action,
            target,
            role_id=role["role_id"],
            cutoff=str(cutoff),
            document_digest=document_digest,
            operation_id=operation_id,
        )
        if policy_name != expected_name:
            raise ExecutionError("AWS policy name is not bound to the confirmed preview")
        return role, policy_name, str(cutoff), document, document_digest

    def _reconcile(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        preview_action: Mapping[str, Any],
        requested_at: str,
        *,
        profile: str,
    ) -> ApplyResult:
        parse_rfc3339(requested_at, "journal.requested_at")
        try:
            preview_role, policy_name, cutoff, _, document_digest = self._confirmed_policy(
                action,
                target,
                preview_action,
            )
        except (ExecutionError, ValidationError) as exc:
            return ApplyResult(
                "INDETERMINATE",
                f"AWS confirmed preview cannot be reconciled: {exc}",
                target.resource_uri,
            )
        reference = self._policy_reference(target, policy_name)
        try:
            current = self._snapshot(profile, target, policy_name)
        except (AdapterError, ExecutionError) as exc:
            return ApplyResult(
                "INDETERMINATE",
                f"AWS role-session reconciliation failed: {exc}",
                reference,
            )
        if current["role"]["role_id"] != preview_role["role_id"]:
            return ApplyResult(
                "INDETERMINATE",
                "AWS role ID changed after preview; the role may have been deleted and recreated",
                reference,
            )
        policy = current["policy"]
        if policy is None:
            return ApplyResult(
                "INDETERMINATE",
                f"{policy_name} is absent; mutation was not repeated",
                reference,
            )
        if policy["cutoff"] != cutoff or policy["document_digest"] != document_digest:
            return ApplyResult(
                "INDETERMINATE",
                f"{policy_name} does not match the confirmed preview",
                reference,
            )
        return ApplyResult(
            "VERIFIED",
            f"{policy_name} denies AWS role sessions issued before {cutoff}",
            reference,
        )

    def validate_confirmed_preview(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        preview_action: Mapping[str, Any],
    ) -> None:
        """Revalidate target state without deriving a new policy or cutoff."""
        preview_role, policy_name, _, _, _ = self._confirmed_policy(
            action,
            target,
            preview_action,
        )
        expected_binding = {
            key: preview_action.get(key)
            for key in (
                "provider_account",
                "api_origin",
                "mutation_identity",
                "observer_identity",
            )
        }
        if self.binding(action, target) != expected_binding:
            raise ExecutionError("AWS identities changed after the confirmed preview")
        mutation = self._snapshot(self._mutation_profile, target, policy_name)
        observer = self._snapshot(self._observer_profile, target, policy_name)
        if mutation != observer:
            raise ExecutionError("AWS profiles see different state after preview")
        if mutation["role"] != preview_role:
            raise ExecutionError("AWS role state changed after preview")
        if mutation["policy"] is not None:
            raise ExecutionError("preview-bound AWS containment policy is no longer absent")

    def apply(
        self,
        action: PlanAction,
        target: ExecutionTarget,
        *,
        preview_action: Mapping[str, Any] | None = None,
        requested_at: str = "",
    ) -> ApplyResult:
        if preview_action is None or not requested_at:
            raise ExecutionError("AWS apply requires the confirmed preview and request time")
        preview_role, policy_name, cutoff, document, _ = self._confirmed_policy(
            action,
            target,
            preview_action,
        )
        if self._now().astimezone(timezone.utc) >= parse_rfc3339(
            cutoff,
            "AWS preview planned_cutoff",
        ):
            return ApplyResult(
                "INDETERMINATE",
                "AWS preview cutoff has passed; mutation was not attempted",
                self._policy_reference(target, policy_name),
            )
        current = self._snapshot(self._mutation_profile, target, policy_name)
        if current["role"]["role_id"] != preview_role["role_id"]:
            return ApplyResult(
                "INDETERMINATE",
                "AWS role ID changed after preview; mutation was not attempted",
                self._policy_reference(target, policy_name),
            )
        if current["policy"] is not None:
            return self._reconcile(
                action,
                target,
                preview_action,
                requested_at,
                profile=self._mutation_profile,
            )
        serialized_document = json.dumps(document, sort_keys=True, separators=(",", ":"))
        try:
            _run_aws(
                [
                    "iam",
                    "put-role-policy",
                    "--role-name",
                    target.resource_id,
                    "--policy-name",
                    policy_name,
                    "--policy-document",
                    serialized_document,
                ],
                profile=self._mutation_profile,
                expect_json=False,
                max_attempts=1,
            )
        except AdapterError:
            pass
        return self._reconcile(
            action,
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
        if preview_action is None or not requested_at:
            raise ExecutionError(
                "AWS reconciliation requires the confirmed preview and request time"
            )
        return self._reconcile(
            action,
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
        try:
            preview_role, policy_name, cutoff_text, _, document_digest = self._confirmed_policy(
                action, target, preview_action or {}
            )
            reference = self._policy_reference(target, policy_name)
        except (ExecutionError, ValidationError) as exc:
            return ObservationResult(
                "INDETERMINATE",
                f"AWS confirmed preview cannot be observed: {exc}",
                target.resource_uri,
                "aws:unknown-observer",
                target.account,
                self.api_origin,
                "aws-iam-role-policy",
            )
        try:
            observer = _identity(self._observer_profile)
            current = self._snapshot(self._observer_profile, target, policy_name)
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
        if requested_at is None:
            status = "INDETERMINATE"
            summary = "AWS revocation policy is not bound to a recorded mutation request"
        elif current["role"]["role_id"] != preview_role["role_id"]:
            status = "INDETERMINATE"
            summary = "AWS role ID changed after preview; the role may have been recreated"
        elif current["policy"] is None:
            status = "STILL_OPEN"
            summary = f"{policy_name} is absent"
        elif (
            current["policy"]["cutoff"] != cutoff_text
            or current["policy"]["document_digest"] != document_digest
        ):
            status = "INDETERMINATE"
            summary = f"{policy_name} does not exactly match the confirmed preview"
        else:
            requested = parse_rfc3339(requested_at, "journal.requested_at")
            cutoff = parse_rfc3339(cutoff_text, "AWS role-session cutoff")
            propagation_start = max(requested, cutoff)
            age = (self._now().astimezone(timezone.utc) - propagation_start).total_seconds()
            if age < AWS_PROPAGATION_SECONDS:
                status = "INDETERMINATE"
                summary = (
                    f"{policy_name} is exact but the five-minute propagation window has not elapsed"
                )
            else:
                status = "VERIFIED_CLOSED"
                summary = (
                    f"{policy_name} still denies role sessions issued before "
                    f"{cutoff_text} after the propagation window"
                )
        return ObservationResult(
            status,
            summary,
            reference,
            f"aws-principal:{_principal_id(observer)}",
            target.account,
            self.api_origin,
            "aws-iam-role-policy",
        )
