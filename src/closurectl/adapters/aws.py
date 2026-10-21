"""Read-only AWS IAM role inventory through isolated AWS CLI profiles."""

from __future__ import annotations

import os
import re
import shutil

# The executable is resolved from PATH, argv is a list, and shell use is disabled.
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Any

from ..errors import AdapterError, ValidationError
from ..receipts import utc_now
from ..serialization import parse_json_text

MAX_ROLES = 50
MAX_OUTPUT_BYTES = 2_000_000
PROFILE_PATTERN = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,128}$")
ROLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_+=,.@-]{1,64}$")
_AWS_ERROR_CODE = re.compile(r"An error occurred \(([^)]+)\)")


class AwsCliError(AdapterError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _profile_name(value: str) -> str:
    if not PROFILE_PATTERN.fullmatch(value):
        raise AdapterError("AWS profile name contains unsupported characters")
    return value


def _role_name(value: str) -> str:
    if not ROLE_NAME_PATTERN.fullmatch(value):
        raise AdapterError(f"invalid AWS IAM role name: {value!r}")
    return value


def _run_aws(
    arguments: list[str],
    *,
    profile: str,
    timeout: float = 30.0,
    expect_json: bool = True,
) -> Any:
    executable = shutil.which("aws")
    if not executable:
        raise AdapterError("AWS CLI v2 is not installed or is not available on PATH")
    normalized_profile = _profile_name(profile)
    allowed_environment = {
        "APPDATA",
        "AWS_CA_BUNDLE",
        "AWS_CONFIG_FILE",
        "AWS_DEFAULT_REGION",
        "AWS_REGION",
        "AWS_SDK_LOAD_CONFIG",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_STS_REGIONAL_ENDPOINTS",
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "NO_COLOR",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in allowed_environment
    }
    environment["AWS_PAGER"] = ""
    environment["AWS_CLI_AUTO_PROMPT"] = "off"
    command = [
        executable,
        *arguments,
        "--profile",
        normalized_profile,
        "--output",
        "json",
        "--no-cli-pager",
        "--no-cli-auto-prompt",
    ]
    try:
        with tempfile.TemporaryDirectory(prefix="closurectl-aws-") as working_directory:
            stdout_path = Path(working_directory) / "stdout"
            stderr_path = Path(working_directory) / "stderr"
            with stdout_path.open("w+b") as stdout_handle, stderr_path.open("w+b") as stderr_handle:
                completed = subprocess.run(  # nosec B603
                    command,
                    check=False,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    timeout=timeout,
                    shell=False,
                    env=environment,
                    cwd=working_directory,
                )
            with stdout_path.open("rb") as handle:
                stdout_bytes = handle.read(MAX_OUTPUT_BYTES + 1)
            with stderr_path.open("rb") as handle:
                stderr_bytes = handle.read(MAX_OUTPUT_BYTES + 1)
    except subprocess.TimeoutExpired as exc:
        raise AdapterError("AWS CLI command timed out; reconcile before retrying") from exc
    except OSError as exc:
        raise AdapterError("AWS CLI could not be started") from exc
    stdout_size = len(stdout_bytes)
    stderr_size = len(stderr_bytes)
    if stdout_size > MAX_OUTPUT_BYTES or stderr_size > MAX_OUTPUT_BYTES:
        raise AdapterError("AWS CLI output exceeded the safety limit")
    try:
        stdout = stdout_bytes.decode("utf-8")
        stderr = stderr_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdapterError("AWS CLI returned non-UTF-8 output") from exc
    if completed.returncode != 0:
        match = _AWS_ERROR_CODE.search(stderr)
        code = match.group(1) if match else "AwsCliFailure"
        raise AwsCliError(code, f"AWS CLI command failed with {code}")
    if not expect_json:
        return stdout.strip()
    if not stdout.strip():
        return None
    try:
        return parse_json_text(stdout, source="AWS CLI output")
    except ValidationError as exc:
        raise AdapterError("AWS CLI returned non-JSON output") from exc


def _identity(profile: str) -> dict[str, str]:
    raw = _run_aws(["sts", "get-caller-identity"], profile=profile)
    if not isinstance(raw, dict):
        raise AdapterError("AWS STS identity response has an unexpected shape")
    account = raw.get("Account")
    arn = raw.get("Arn")
    user_id = raw.get("UserId")
    if not all(isinstance(item, str) and item for item in (account, arn, user_id)):
        raise AdapterError("AWS STS identity response is incomplete")
    if not re.fullmatch(r"[0-9]{12}", account):
        raise AdapterError("AWS account ID must contain 12 digits")
    return {"account": account, "arn": arn, "user_id": user_id}


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return []


def _github_oidc_trust(policy: Any) -> list[dict[str, Any]]:
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    result: list[dict[str, Any]] = []
    allowed_condition_keys = {
        "token.actions.githubusercontent.com:aud",
        "token.actions.githubusercontent.com:sub",
    }
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if "sts:AssumeRoleWithWebIdentity" not in _string_list(statement.get("Action")):
            continue
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        providers = _string_list(principal.get("Federated"))
        github_providers = [
            provider
            for provider in providers
            if provider.endswith(":oidc-provider/token.actions.githubusercontent.com")
        ]
        if not github_providers:
            continue
        conditions: dict[str, list[str]] = {}
        raw_conditions = statement.get("Condition", {})
        if isinstance(raw_conditions, dict):
            for operator, entries in raw_conditions.items():
                if not isinstance(operator, str) or not isinstance(entries, dict):
                    continue
                for key, raw_values in entries.items():
                    if key not in allowed_condition_keys:
                        continue
                    values = _string_list(raw_values)
                    if values:
                        conditions[f"{operator}:{key}"] = sorted(values)
        result.append(
            {
                "providers": sorted(github_providers),
                "conditions": {key: conditions[key] for key in sorted(conditions)},
            }
        )
    return result


def collect_aws_inventory(roles: list[str], *, profile: str) -> dict[str, Any]:
    """Collect allow-listed IAM role and GitHub OIDC trust metadata."""
    if not roles:
        raise AdapterError("provide at least one --role ROLE_NAME")
    if len(roles) > MAX_ROLES:
        raise AdapterError(f"AWS inventory accepts at most {MAX_ROLES} roles")
    normalized_roles = [_role_name(role) for role in roles]
    if len(normalized_roles) != len(set(normalized_roles)):
        raise AdapterError("AWS inventory role names must be unique")
    identity = _identity(profile)
    results: list[dict[str, Any]] = []
    partition = ""

    for role_name in normalized_roles:
        raw_role = _run_aws(["iam", "get-role", "--role-name", role_name], profile=profile)
        if not isinstance(raw_role, dict) or not isinstance(raw_role.get("Role"), dict):
            raise AdapterError(f"AWS IAM role response is invalid for {role_name}")
        role = raw_role["Role"]
        if role.get("RoleName") != role_name:
            raise AdapterError(f"AWS IAM returned a different role for {role_name}")
        arn = role.get("Arn")
        path = role.get("Path")
        role_id = role.get("RoleId")
        if (
            not isinstance(arn, str)
            or not isinstance(path, str)
            or not isinstance(role_id, str)
            or not role_id
        ):
            raise AdapterError(f"AWS IAM role identity is incomplete for {role_name}")
        arn_parts = arn.split(":", 5)
        if len(arn_parts) != 6 or arn_parts[2] != "iam" or arn_parts[4] != identity["account"]:
            raise AdapterError(f"AWS IAM role ARN is invalid for {role_name}")
        current_partition = arn_parts[1]
        if partition and current_partition != partition:
            raise AdapterError("AWS inventory cannot combine roles from different partitions")
        partition = current_partition

        inline = _run_aws(
            ["iam", "list-role-policies", "--role-name", role_name],
            profile=profile,
        )
        attached = _run_aws(
            ["iam", "list-attached-role-policies", "--role-name", role_name],
            profile=profile,
        )
        policy_names = inline.get("PolicyNames") if isinstance(inline, dict) else None
        attached_policies = attached.get("AttachedPolicies") if isinstance(attached, dict) else None
        if not isinstance(policy_names, list) or not all(
            isinstance(item, str) for item in policy_names
        ):
            raise AdapterError(f"AWS inline policy list is invalid for {role_name}")
        if not isinstance(attached_policies, list):
            raise AdapterError(f"AWS attached policy list is invalid for {role_name}")
        safe_attached = []
        for item in attached_policies:
            if not isinstance(item, dict):
                raise AdapterError(f"AWS attached policy metadata is invalid for {role_name}")
            name = item.get("PolicyName")
            policy_arn = item.get("PolicyArn")
            if not isinstance(name, str) or not isinstance(policy_arn, str):
                raise AdapterError(f"AWS attached policy identity is invalid for {role_name}")
            safe_attached.append({"name": name, "arn": policy_arn})

        results.append(
            {
                "name": role_name,
                "role_id": role_id,
                "arn": arn,
                "path": path,
                "service_linked": path.startswith(
                    ("/aws-service-role/", "/aws-reserved/sso.amazonaws.com/")
                ),
                "max_session_duration": role.get("MaxSessionDuration"),
                "created_at": role.get("CreateDate"),
                "last_used_at": (
                    role.get("RoleLastUsed", {}).get("LastUsedDate")
                    if isinstance(role.get("RoleLastUsed"), dict)
                    else None
                ),
                "inline_policy_names": sorted(policy_names),
                "attached_policies": sorted(safe_attached, key=lambda item: item["arn"]),
                "github_oidc_trust": _github_oidc_trust(role.get("AssumeRolePolicyDocument")),
            }
        )

    return {
        "schema_version": "1",
        "adapter": "aws-iam-read-only",
        "collected_at": utc_now(),
        "credential_handle": f"aws-profile:{_profile_name(profile)}",
        "subject": identity,
        "partition": partition,
        "roles": sorted(results, key=lambda item: item["name"]),
        "limitations": [
            "Only explicitly named IAM roles are inventoried.",
            "AWS IAM is eventually consistent; a read does not prove global propagation.",
            "Role session revocation affects all sessions issued before the cutoff.",
            "Service-linked and IAM Identity Center managed roles are not executable.",
        ],
    }
