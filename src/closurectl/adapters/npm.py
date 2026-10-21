"""Read-only npm CLI inventory with strict output allow-listing."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from ..errors import AdapterError
from ..receipts import utc_now

PACKAGE_PATTERN = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")


def _run_npm(arguments: list[str], *, timeout: float = 20.0) -> Any:
    executable = shutil.which("npm")
    if not executable:
        raise AdapterError("npm is not installed or is not available on PATH")
    try:
        completed = subprocess.run(
            [executable, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdapterError("npm inventory command timed out") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        summary = detail[-1] if detail else "unknown npm error"
        raise AdapterError(f"npm read-only inventory failed: {summary}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AdapterError("npm returned non-JSON inventory output") from exc


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
    return [
        {key: item.get(key) for key in sorted(allowed) if key in item}
        for item in candidates
        if isinstance(item, dict)
    ]


def collect_npm_inventory(packages: list[str]) -> dict[str, Any]:
    """Ask the authenticated npm CLI for non-secret publication metadata."""
    normalized: list[str] = []
    for package in packages:
        if not PACKAGE_PATTERN.fullmatch(package):
            raise AdapterError(f"invalid npm package name: {package!r}")
        normalized.append(package)

    raw_credentials = _run_npm(["token", "list", "--json"])
    package_results: list[dict[str, Any]] = []
    for package in normalized:
        owners = _run_npm(["owner", "ls", package, "--json"])
        tags = _run_npm(["dist-tag", "ls", package, "--json"])
        if not isinstance(owners, dict):
            raise AdapterError(f"npm owner response is invalid for {package}")
        if not isinstance(tags, dict):
            raise AdapterError(f"npm dist-tag response is invalid for {package}")
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
        "credential_metadata": _safe_token_metadata(raw_credentials),
        "packages": package_results,
        "limitations": [
            "The npm CLI decides which metadata is visible to the current identity.",
            "Credential values and partial key material are intentionally discarded.",
            "This inventory does not prove that historical credentials are absent.",
        ],
    }
