"""Read-only GitHub inventory without credential persistence."""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .. import __version__
from ..errors import AdapterError, ValidationError
from ..receipts import utc_now
from ..serialization import parse_json_text

REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REPOSITORY_PERMISSION_FIELDS = {"admin", "maintain", "push", "triage", "pull"}
PAGE_SIZE = 100
MAX_COLLECTION_ITEMS = 500
MAX_RESPONSE_BYTES = 2_000_000


def _response_body(raw_body: bytes) -> Any:
    if not raw_body:
        return None
    try:
        return parse_json_text(raw_body.decode("utf-8"), source="GitHub API response")
    except (UnicodeDecodeError, ValidationError) as exc:
        raise AdapterError("GitHub API returned an unreadable response") from exc


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
    status: int = 200
    has_next: bool = False


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

    @property
    def api_url(self) -> str:
        return self._api_url

    def request(
        self,
        method: str,
        path: str,
        *,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> GitHubResponse:
        if method not in {"GET", "POST", "PUT"}:
            raise AdapterError(f"unsupported GitHub API method: {method}")
        if not path.startswith("/") or "://" in path:
            raise AdapterError("GitHub API path must be origin-relative")
        request = urllib.request.Request(
            f"{self._api_url}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._credential}",
                "User-Agent": f"closurectl/{__version__}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            data=b"" if method in {"POST", "PUT"} else None,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw_body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw_body) > MAX_RESPONSE_BYTES:
                    raise AdapterError("GitHub API response exceeded the safety limit")
                body = _response_body(raw_body)
                scopes = tuple(
                    sorted(
                        scope.strip()
                        for scope in response.headers.get("X-OAuth-Scopes", "").split(",")
                        if scope.strip()
                    )
                )
                status = int(response.status)
                if status not in accepted_statuses:
                    raise AdapterError(f"GitHub API returned unexpected HTTP {status}")
                link = response.headers.get("Link", "")
                has_next = any('rel="next"' in item for item in link.split(",") if item.strip())
                return GitHubResponse(
                    body=body,
                    scopes=scopes,
                    status=status,
                    has_next=has_next,
                )
        except urllib.error.HTTPError as exc:
            if exc.code in accepted_statuses:
                raw_body = exc.read(MAX_RESPONSE_BYTES + 1)
                if len(raw_body) > MAX_RESPONSE_BYTES:
                    raise AdapterError("GitHub API response exceeded the safety limit") from exc
                try:
                    body = _response_body(raw_body)
                except AdapterError:
                    body = None
                return GitHubResponse(body=body, scopes=(), status=exc.code)
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

    def get(self, path: str) -> GitHubResponse:
        return self.request("GET", path)

    def post(
        self, path: str, *, accepted_statuses: tuple[int, ...] = (200, 202, 204)
    ) -> GitHubResponse:
        return self.request("POST", path, accepted_statuses=accepted_statuses)

    def put(
        self, path: str, *, accepted_statuses: tuple[int, ...] = (200, 202, 204)
    ) -> GitHubResponse:
        return self.request("PUT", path, accepted_statuses=accepted_statuses)


def _validate_repository(repository: str) -> str:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise AdapterError(f"invalid repository {repository!r}; expected OWNER/REPOSITORY")
    owner, name = repository.split("/", 1)
    return f"{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}"


def _collect_pages(
    client: GitHubClient,
    path: str,
    *,
    collection_key: str | None,
) -> tuple[list[Any], int, bool, set[str]]:
    collected: list[Any] = []
    scopes: set[str] = set()
    total = 0
    page = 1
    while len(collected) < MAX_COLLECTION_ITEMS:
        separator = "&" if "?" in path else "?"
        page_path = path if page == 1 else f"{path}{separator}page={page}"
        response = client.get(page_path)
        scopes.update(response.scopes)
        body = response.body
        if collection_key is None:
            if not isinstance(body, list):
                raise AdapterError("GitHub collection response has an unexpected shape")
            items = body
            total = len(collected) + len(items)
        else:
            if not isinstance(body, dict) or not isinstance(body.get(collection_key), list):
                raise AdapterError("GitHub collection response has an unexpected shape")
            items = body[collection_key]
            raw_total = body.get("total_count")
            total = (
                raw_total
                if isinstance(raw_total, int) and not isinstance(raw_total, bool)
                else max(total, len(collected) + len(items))
            )
        remaining = MAX_COLLECTION_ITEMS - len(collected)
        collected.extend(items[:remaining])
        if len(collected) >= MAX_COLLECTION_ITEMS:
            if response.has_next or len(items) > remaining:
                total = max(total, MAX_COLLECTION_ITEMS + 1)
            break
        if len(items) < PAGE_SIZE:
            break
        if collection_key is None and not response.has_next:
            break
        if collection_key is not None and len(collected) >= total:
            break
        page += 1
    return collected, total, total > len(collected), scopes


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

        try:
            workflow_items, workflow_total, workflow_truncated, workflow_scopes = _collect_pages(
                client,
                f"/repos/{encoded}/actions/workflows?per_page={PAGE_SIZE}",
                collection_key="workflows",
            )
            run_items, run_total, run_truncated, run_scopes = _collect_pages(
                client,
                f"/repos/{encoded}/actions/runs?per_page={PAGE_SIZE}",
                collection_key="workflow_runs",
            )
            key_items, key_total, key_truncated, key_scopes = _collect_pages(
                client,
                f"/repos/{encoded}/keys?per_page={PAGE_SIZE}",
                collection_key=None,
            )
        except AdapterError as exc:
            raise AdapterError(f"unexpected collection response for {repository}: {exc}") from exc
        scopes.update(workflow_scopes | run_scopes | key_scopes)
        if not all(isinstance(item, dict) for item in workflow_items):
            raise AdapterError(f"GitHub workflow collection is malformed for {repository}")
        if not all(isinstance(item, dict) for item in run_items):
            raise AdapterError(f"GitHub run collection is malformed for {repository}")
        if not all(isinstance(item, dict) for item in key_items):
            raise AdapterError(f"GitHub deploy-key collection is malformed for {repository}")

        workflows = [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "path": item.get("path"),
                "state": item.get("state"),
            }
            for item in workflow_items
        ]
        active_runs = [
            {
                "id": item.get("id"),
                "workflow_id": item.get("workflow_id"),
                "name": item.get("name"),
                "event": item.get("event"),
                "status": item.get("status"),
                "run_attempt": item.get("run_attempt"),
                "head_sha": item.get("head_sha"),
                "created_at": item.get("created_at"),
                "html_url": item.get("html_url"),
            }
            for item in run_items
            if item.get("status") != "completed"
        ]
        deploy_keys = [
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "read_only": item.get("read_only"),
                "verified": item.get("verified"),
                "created_at": item.get("created_at"),
            }
            for item in key_items
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
                "workflow_count": workflow_total,
                "workflow_results_truncated": workflow_truncated,
                "active_runs": active_runs,
                "run_count_scanned": min(run_total, MAX_COLLECTION_ITEMS),
                "run_results_truncated": run_truncated,
                "deploy_keys": deploy_keys,
                "deploy_key_count": key_total,
                "deploy_key_results_truncated": key_truncated,
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
            f"Collections are capped at {MAX_COLLECTION_ITEMS} items with explicit truncation.",
            "An empty list may reflect missing permission, not absence.",
            "This inventory does not prove revocation closure.",
        ],
    }
