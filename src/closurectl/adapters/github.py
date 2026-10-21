"""Read-only GitHub inventory without credential persistence."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from ..errors import AdapterError
from ..receipts import utc_now

REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REPOSITORY_PERMISSION_FIELDS = {"admin", "maintain", "push", "triage", "pull"}


def _https_origin(url: str) -> tuple[str, int]:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or 443
    except ValueError as exc:
        raise AdapterError("GitHub API URL is invalid") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AdapterError(
            "GitHub API URL must be HTTPS and must not contain credentials, query, or fragment"
        )
    return parsed.hostname.lower(), port


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _https_origin(req.full_url) != _https_origin(newurl):
            raise urllib.error.HTTPError(
                newurl,
                code,
                "refusing to forward GitHub credentials across origins",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class GitHubResponse:
    body: Any
    scopes: tuple[str, ...]


class GitHubClient:
    def __init__(
        self,
        credential: str,
        *,
        api_url: str = "https://api.github.com",
        timeout: float = 15.0,
    ) -> None:
        if not credential:
            raise AdapterError("GITHUB_TOKEN is not set; pass credentials through the environment")
        self._credential = credential
        self._api_url = api_url.rstrip("/")
        _https_origin(self._api_url)
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_SameOriginRedirectHandler())

    def get(self, path: str) -> GitHubResponse:
        request = urllib.request.Request(
            f"{self._api_url}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._credential}",
                "User-Agent": "closurectl/0.1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
                scopes = tuple(
                    sorted(
                        scope.strip()
                        for scope in response.headers.get("X-OAuth-Scopes", "").split(",")
                        if scope.strip()
                    )
                )
                return GitHubResponse(body=body, scopes=scopes)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise AdapterError(
                    "GitHub API redirect was blocked to protect credentials"
                ) from exc
            if exc.code in {401, 403}:
                raise AdapterError(
                    f"GitHub denied read-only inventory ({exc.code}); check credential "
                    "scope and rate limits"
                ) from exc
            raise AdapterError(f"GitHub API returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise AdapterError(f"cannot reach GitHub API: {exc.reason}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AdapterError("GitHub API returned an unreadable response") from exc


def _validate_repository(repository: str) -> str:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise AdapterError(f"invalid repository {repository!r}; expected OWNER/REPOSITORY")
    owner, name = repository.split("/", 1)
    return f"{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}"


def collect_github_inventory(
    credential: str,
    repositories: list[str],
    *,
    api_url: str = "https://api.github.com",
) -> dict[str, Any]:
    """Collect bounded metadata. The credential is never returned or fingerprinted."""
    if not repositories:
        raise AdapterError("provide at least one --repo OWNER/REPOSITORY")
    client = GitHubClient(credential, api_url=api_url)
    user_response = client.get("/user")
    if not isinstance(user_response.body, dict):
        raise AdapterError("GitHub /user response has an unexpected shape")
    subject = {
        "login": user_response.body.get("login"),
        "id": user_response.body.get("id"),
        "type": user_response.body.get("type"),
    }
    scopes = set(user_response.scopes)
    results: list[dict[str, Any]] = []

    for repository in repositories:
        encoded = _validate_repository(repository)
        repo_response = client.get(f"/repos/{encoded}")
        if not isinstance(repo_response.body, dict):
            raise AdapterError(f"unexpected repository response for {repository}")
        scopes.update(repo_response.scopes)

        workflows_response = client.get(f"/repos/{encoded}/actions/workflows?per_page=100")
        runs_response = client.get(f"/repos/{encoded}/actions/runs?status=queued&per_page=100")
        keys_response = client.get(f"/repos/{encoded}/keys?per_page=100")
        for response in (workflows_response, runs_response, keys_response):
            scopes.update(response.scopes)

        workflows_body = workflows_response.body
        runs_body = runs_response.body
        keys_body = keys_response.body
        if not isinstance(workflows_body, dict) or not isinstance(
            workflows_body.get("workflows"), list
        ):
            raise AdapterError(f"unexpected workflows response for {repository}")
        if not isinstance(runs_body, dict) or not isinstance(runs_body.get("workflow_runs"), list):
            raise AdapterError(f"unexpected runs response for {repository}")
        if not isinstance(keys_body, list):
            raise AdapterError(f"unexpected deploy-key response for {repository}")

        workflows = [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "path": item.get("path"),
                "state": item.get("state"),
            }
            for item in workflows_body["workflows"]
            if isinstance(item, dict)
        ]
        queued_runs = [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "event": item.get("event"),
                "status": item.get("status"),
                "created_at": item.get("created_at"),
                "html_url": item.get("html_url"),
            }
            for item in runs_body["workflow_runs"]
            if isinstance(item, dict)
        ]
        deploy_keys = [
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "read_only": item.get("read_only"),
                "verified": item.get("verified"),
                "created_at": item.get("created_at"),
            }
            for item in keys_body
            if isinstance(item, dict)
        ]
        raw_permissions = repo_response.body.get("permissions", {})
        permissions = (
            {
                key: raw_permissions[key]
                for key in sorted(REPOSITORY_PERMISSION_FIELDS)
                if key in raw_permissions and isinstance(raw_permissions[key], bool)
            }
            if isinstance(raw_permissions, dict)
            else {}
        )
        results.append(
            {
                "full_name": repo_response.body.get("full_name"),
                "private": repo_response.body.get("private"),
                "archived": repo_response.body.get("archived"),
                "default_branch": repo_response.body.get("default_branch"),
                "permissions": permissions,
                "workflows": workflows,
                "workflow_count": workflows_body.get("total_count", len(workflows)),
                "workflow_results_bounded": len(workflows) >= 100,
                "queued_runs": queued_runs,
                "queued_run_count": runs_body.get("total_count", len(queued_runs)),
                "queued_run_results_bounded": len(queued_runs) >= 100,
                "deploy_keys": deploy_keys,
                "deploy_key_results_bounded": len(deploy_keys) >= 100,
            }
        )

    return {
        "schema_version": "1",
        "adapter": "github-read-only",
        "collected_at": utc_now(),
        "credential_handle": "environment:GITHUB_TOKEN",
        "subject": subject,
        "oauth_scopes": sorted(scopes),
        "repositories": results,
        "limitations": [
            "The inventory is bounded to 100 items per collection endpoint.",
            "An empty list may reflect missing permission, not absence.",
            "This inventory does not prove revocation closure.",
        ],
    }
