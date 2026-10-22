"""Read-only npm CLI inventory with strict output allow-listing."""

from __future__ import annotations

import os
import re
import shutil

# The executable is resolved from PATH, argv is a list, and shell use is disabled.
import subprocess  # nosec B404
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from ..errors import AdapterError, ValidationError
from ..receipts import utc_now
from ..serialization import parse_json_text

PACKAGE_PATTERN = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
MAX_PACKAGES = 50
MAX_ITEMS = 1_000
MAX_OUTPUT_BYTES = 2_000_000
DEFAULT_REGISTRY = "https://registry.npmjs.org"
SUPPORTED_NPM_VERSION = "11.18.0"


def _registry_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        parsed.port
    except ValueError as exc:
        raise AdapterError("npm registry URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AdapterError("npm registry must be an HTTPS URL without credentials")
    return value.rstrip("/")


def _run_npm(
    arguments: list[str],
    *,
    timeout: float = 20.0,
    userconfig: str | Path | None = None,
    expect_json: bool = True,
    allow_otp: bool = False,
) -> Any:
    executable = shutil.which("npm")
    if not executable:
        raise AdapterError("npm is not installed or is not available on PATH")
    inherited_otp = os.environ.get("NPM_CONFIG_OTP", "")
    allowed_environment = {
        "APPDATA",
        "CI",
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
    if inherited_otp and allow_otp:
        environment["NPM_CONFIG_OTP"] = inherited_otp
    if userconfig is not None:
        environment["NPM_CONFIG_USERCONFIG"] = str(Path(userconfig).resolve())
    try:
        with tempfile.TemporaryDirectory(prefix="closurectl-npm-") as working_directory:
            empty_global_config = Path(working_directory) / "global.npmrc"
            empty_global_config.write_text("", encoding="utf-8")
            environment["NPM_CONFIG_GLOBALCONFIG"] = str(empty_global_config)
            stdout_path = Path(working_directory) / "stdout"
            stderr_path = Path(working_directory) / "stderr"
            with stdout_path.open("w+b") as stdout_handle, stderr_path.open("w+b") as stderr_handle:
                completed = subprocess.run(  # nosec B603
                    [executable, *arguments],
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
        raise AdapterError("npm command timed out; reconcile before retrying a mutation") from exc
    except OSError as exc:
        raise AdapterError("npm command could not be started") from exc
    if len(stdout_bytes) > MAX_OUTPUT_BYTES or len(stderr_bytes) > MAX_OUTPUT_BYTES:
        raise AdapterError("npm output exceeded the safety limit")
    try:
        stdout = stdout_bytes.decode("utf-8")
        stderr_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdapterError("npm returned non-UTF-8 output") from exc
    if completed.returncode != 0:
        raise AdapterError(f"npm command failed with exit code {completed.returncode}")
    if not expect_json:
        return stdout.strip()
    try:
        return parse_json_text(stdout, source="npm output")
    except ValidationError as exc:
        raise AdapterError("npm returned non-JSON output") from exc


def _safe_token_metadata(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        candidates = raw.get("objects", raw.get("tokens", []))
    else:
        candidates = raw
    if not isinstance(candidates, list):
        raise AdapterError("npm credential metadata has an unexpected shape")
    allowed = {
        "id",
        "name",
        "created",
        "updated",
        "readonly",
        "automation",
        "cidr_whitelist",
    }
    if len(candidates) > MAX_ITEMS:
        raise AdapterError("npm credential metadata exceeded the safety limit")
    if not all(isinstance(item, dict) for item in candidates):
        raise AdapterError("npm credential metadata contains a malformed item")
    normalized: list[dict[str, Any]] = []
    for item in candidates:
        if not isinstance(item.get("id"), str) or not item["id"]:
            raise AdapterError("npm credential metadata is missing a token ID")
        if isinstance(item.get("readonly"), bool):
            normalized.append({key: item[key] for key in sorted(allowed) if key in item})
            continue

        permissions = item.get("permissions")
        bypass_2fa = item.get("bypass_2fa")
        if not isinstance(permissions, list) or not isinstance(bypass_2fa, bool):
            raise AdapterError("npm credential metadata has an unsupported token shape")
        package_actions: list[str] = []
        for permission in permissions:
            if (
                not isinstance(permission, dict)
                or set(permission) != {"name", "action"}
                or not isinstance(permission.get("name"), str)
                or permission.get("action") not in {"read", "write"}
            ):
                raise AdapterError("npm granular token permission metadata is invalid")
            if permission["name"] == "package":
                package_actions.append(permission["action"])
        safe = {
            key: item[key]
            for key in ("id", "name", "created", "updated")
            if isinstance(item.get(key), str) and item[key]
        }
        safe["readonly"] = all(action == "read" for action in package_actions)
        safe["automation"] = bypass_2fa
        cidr = item.get("cidr", [])
        if not isinstance(cidr, list) or not all(isinstance(value, str) for value in cidr):
            raise AdapterError("npm granular token CIDR metadata is invalid")
        safe["cidr_whitelist"] = cidr
        normalized.append(safe)
    return normalized


def require_supported_npm_version() -> None:
    version = _run_npm(["--version"], expect_json=False)
    if version != SUPPORTED_NPM_VERSION:
        raise AdapterError(
            f"npm CLI {SUPPORTED_NPM_VERSION} is required; found {version or 'unknown'}"
        )


def collect_npm_inventory(
    packages: list[str],
    *,
    registry: str = DEFAULT_REGISTRY,
    userconfig: str | Path | None = None,
) -> dict[str, Any]:
    """Ask the authenticated npm CLI for non-secret publication metadata."""
    require_supported_npm_version()
    registry = _registry_url(registry)
    if len(packages) > MAX_PACKAGES:
        raise AdapterError(f"npm inventory accepts at most {MAX_PACKAGES} packages")
    normalized: list[str] = []
    for package in packages:
        if not PACKAGE_PATTERN.fullmatch(package):
            raise AdapterError(f"invalid npm package name: {package!r}")
        normalized.append(package)

    registry_argument = f"--registry={registry}"
    raw_credentials = _run_npm(
        ["token", "list", "--json", registry_argument], userconfig=userconfig
    )
    package_results: list[dict[str, Any]] = []
    for package in normalized:
        owners = _run_npm(
            ["owner", "ls", package, "--json", registry_argument],
            userconfig=userconfig,
        )
        tags = _run_npm(
            ["dist-tag", "ls", package, "--json", registry_argument],
            userconfig=userconfig,
        )
        if not isinstance(owners, dict):
            raise AdapterError(f"npm owner response is invalid for {package}")
        if not isinstance(tags, dict):
            raise AdapterError(f"npm dist-tag response is invalid for {package}")
        if len(owners) > MAX_ITEMS or len(tags) > MAX_ITEMS:
            raise AdapterError(f"npm metadata exceeded the safety limit for {package}")
        if not all(
            isinstance(name, str) and name and isinstance(email, str) and email
            for name, email in owners.items()
        ):
            raise AdapterError(f"npm owner metadata is invalid for {package}")
        if not all(
            isinstance(name, str) and name and isinstance(version, str) and version
            for name, version in tags.items()
        ):
            raise AdapterError(f"npm dist-tag metadata is invalid for {package}")
        package_results.append(
            {
                "name": package,
                "owners": [
                    {"name": name, "email": email} for name, email in sorted(owners.items())
                ],
                "dist_tags": {name: version for name, version in sorted(tags.items())},
            }
        )

    return {
        "schema_version": "1",
        "adapter": "npm-read-only",
        "collected_at": utc_now(),
        "credential_handle": "npm-cli-current-user",
        "registry": registry,
        "credential_metadata": _safe_token_metadata(raw_credentials),
        "packages": package_results,
        "limitations": [
            "The npm CLI decides which metadata is visible to the current identity.",
            "Credential values and partial key material are intentionally discarded.",
            "This inventory does not prove that historical credentials are absent.",
            f"Inventory is limited to {MAX_PACKAGES} packages and {MAX_ITEMS} items per collection.",
        ],
    }
