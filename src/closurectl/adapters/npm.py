"""Read-only npm CLI inventory with strict output allow-listing."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from ..errors import AdapterError
from ..receipts import utc_now

PACKAGE_PATTERN = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
MAX_PACKAGES = 50
MAX_ITEMS = 1_000
MAX_OUTPUT_BYTES = 2_000_000
DEFAULT_REGISTRY = "https://registry.npmjs.org"


def _registry_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
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
            completed = subprocess.run(
                [executable, *arguments],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                env=environment,
                cwd=working_directory,
            )
    except subprocess.TimeoutExpired as exc:
        raise AdapterError("npm command timed out; reconcile before retrying a mutation") from exc
    except OSError as exc:
        raise AdapterError("npm command could not be started") from exc
    if len(completed.stdout.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise AdapterError("npm output exceeded the safety limit")
    if completed.returncode != 0:
        raise AdapterError(f"npm command failed with exit code {completed.returncode}")
    if not expect_json:
        return completed.stdout.strip()
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
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
    return [
        {key: item.get(key) for key in sorted(allowed) if key in item}
        for item in candidates
        if isinstance(item, dict)
    ]


def collect_npm_inventory(
    packages: list[str],
    *,
    registry: str = DEFAULT_REGISTRY,
    userconfig: str | Path | None = None,
) -> dict[str, Any]:
    """Ask the authenticated npm CLI for non-secret publication metadata."""
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
        package_results.append(
            {
                "name": package,
                "owners": [
                    {"name": str(name), "email": str(email)}
                    for name, email in sorted(owners.items())
                ],
                "dist_tags": {str(name): str(version) for name, version in sorted(tags.items())},
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
