from __future__ import annotations

import io
import json
import os
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from closurectl.adapters.github import (
    GitHubClient,
    GitHubResponse,
    _collect_pages,
    _https_origin,
    _SameOriginRedirectHandler,
    collect_github_inventory,
)
from closurectl.adapters.npm import (
    MAX_OUTPUT_BYTES,
    _registry_url,
    _run_npm,
    _safe_token_metadata,
    collect_npm_inventory,
    require_supported_npm_version,
)
from closurectl.errors import AdapterError


class AdapterTests(unittest.TestCase):
    @staticmethod
    def _http_error(code: int) -> urllib.error.HTTPError:
        return urllib.error.HTTPError(
            "https://api.github.test/user",
            code,
            "provider failure",
            {},
            io.BytesIO(b"{}"),
        )

    def test_github_api_requires_https(self) -> None:
        with self.assertRaisesRegex(AdapterError, "must be HTTPS"):
            _https_origin("http://api.github.test")

    def test_github_redirect_cannot_change_origin(self) -> None:
        handler = _SameOriginRedirectHandler()
        request = urllib.request.Request("https://api.github.com/user")
        with self.assertRaisesRegex(urllib.error.HTTPError, "refusing to forward") as raised:
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://attacker.invalid/collect",
            )
        raised.exception.close()

    def test_github_rate_limit_and_server_errors_fail_closed(self) -> None:
        client = GitHubClient("credential", api_url="https://api.github.test")
        for status in (429, 500):
            with self.subTest(status=status):
                error = self._http_error(status)
                try:
                    with patch.object(client._opener, "open", side_effect=error):
                        with self.assertRaisesRegex(AdapterError, f"HTTP {status}"):
                            client.get("/user")
                finally:
                    error.close()

    def test_github_malformed_json_fails_closed(self) -> None:
        class Response:
            status = 200
            headers: dict[str, str] = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, amount=-1):
                del amount
                return b"{not-json"

        client = GitHubClient("credential", api_url="https://api.github.test")
        with patch.object(client._opener, "open", return_value=Response()):
            with self.assertRaisesRegex(AdapterError, "unreadable"):
                client.get("/user")

    def test_github_response_size_is_bounded(self) -> None:
        class Response:
            status = 200
            headers: dict[str, str] = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, amount=-1):
                return b"x" * amount

        client = GitHubClient("credential", api_url="https://api.github.test")
        with patch.object(client._opener, "open", return_value=Response()):
            with self.assertRaisesRegex(AdapterError, "safety limit"):
                client.get("/user")

    def test_github_pagination_boundaries(self) -> None:
        class Client:
            def __init__(self, count: int) -> None:
                self.items = list(range(count))
                self.calls = 0

            def get(self, path: str) -> GitHubResponse:
                del path
                self.calls += 1
                page = self.calls
                start = (page - 1) * 100
                end = min(start + 100, len(self.items))
                return GitHubResponse(
                    self.items[start:end],
                    (),
                    has_next=end < len(self.items),
                )

        expectations = {
            99: (99, False, 1),
            100: (100, False, 1),
            101: (101, False, 2),
            500: (500, False, 5),
            501: (501, True, 5),
        }
        for count, (expected_total, truncated, calls) in expectations.items():
            with self.subTest(count=count):
                client = Client(count)
                items, total, was_truncated, _ = _collect_pages(
                    client,
                    "/repos/example/project/keys?per_page=100",
                    collection_key=None,
                )
                self.assertEqual(len(items), min(count, 500))
                self.assertEqual(total, expected_total)
                self.assertEqual(was_truncated, truncated)
                self.assertEqual(client.calls, calls)

    @patch("closurectl.adapters.github.GitHubClient.get")
    def test_github_inventory_allowlists_metadata(self, get) -> None:
        def response(path: str) -> GitHubResponse:
            if path == "/user":
                return GitHubResponse(
                    {"login": "maintainer", "id": 7, "type": "User"},
                    ("repo",),
                )
            if path == "/repos/example/project":
                return GitHubResponse(
                    {
                        "full_name": "example/project",
                        "private": False,
                        "archived": False,
                        "default_branch": "main",
                        "permissions": {"admin": True},
                        "unexpected_secret": "must-not-leak",
                    },
                    ("repo", "workflow"),
                )
            if "workflows?" in path:
                return GitHubResponse(
                    {
                        "total_count": 1,
                        "workflows": [
                            {
                                "id": 1,
                                "name": "Release",
                                "path": ".github/workflows/release.yml",
                                "state": "active",
                            }
                        ],
                    },
                    (),
                )
            if "runs?" in path:
                return GitHubResponse({"total_count": 0, "workflow_runs": []}, ())
            if path.endswith("/keys?per_page=100"):
                return GitHubResponse([], ())
            raise AssertionError(path)

        get.side_effect = response
        result = collect_github_inventory("do-not-persist", ["example/project"])
        rendered = json.dumps(result)
        self.assertNotIn("do-not-persist", rendered)
        self.assertNotIn("must-not-leak", rendered)
        self.assertEqual(result["oauth_scopes"], ["repo", "workflow"])

    @patch("closurectl.adapters.npm._run_npm")
    def test_npm_inventory_discards_partial_credential_keys(self, run_npm) -> None:
        run_npm.side_effect = [
            "11.18.0",
            [
                {
                    "id": "credential-id",
                    "name": "release",
                    "key": "npm_partial_key",
                    "token": "plaintext-should-never-appear",
                    "readonly": False,
                }
            ],
            {"maintainer": "maintainer@example.test"},
            {"latest": "1.2.3"},
        ]
        result = collect_npm_inventory(["example-package"])
        rendered = json.dumps(result)
        self.assertNotIn("npm_partial_key", rendered)
        self.assertNotIn("plaintext-should-never-appear", rendered)
        self.assertIn("credential-id", rendered)

    def test_npm_granular_tokens_are_normalized_without_token_values(self) -> None:
        metadata = _safe_token_metadata(
            [
                {
                    "id": "granular-read",
                    "name": "read-only",
                    "key": "npm_partial_key",
                    "token": "plaintext-should-never-appear",
                    "created": "2026-10-22T11:00:00Z",
                    "updated": "2026-10-22T11:00:00Z",
                    "expiry": "2026-10-29T11:00:00Z",
                    "bypass_2fa": False,
                    "cidr": [],
                    "permissions": [{"name": "package", "action": "read"}],
                    "scopes": [{"name": None, "type": "package"}],
                },
                {
                    "id": "granular-write",
                    "name": "publisher",
                    "key": "another_partial_key",
                    "token": "another-plaintext-value",
                    "bypass_2fa": True,
                    "cidr": ["192.0.2.0/24"],
                    "permissions": [{"name": "package", "action": "write"}],
                    "scopes": [{"name": "@example", "type": "scope"}],
                },
            ]
        )
        self.assertTrue(metadata[0]["readonly"])
        self.assertFalse(metadata[0]["automation"])
        self.assertFalse(metadata[1]["readonly"])
        self.assertTrue(metadata[1]["automation"])
        self.assertEqual(metadata[1]["cidr_whitelist"], ["192.0.2.0/24"])
        rendered = json.dumps(metadata)
        self.assertNotIn("npm_partial_key", rendered)
        self.assertNotIn("plaintext", rendered)
        self.assertNotIn("permissions", rendered)
        self.assertNotIn("scopes", rendered)

    def test_npm_registry_rejects_invalid_ports(self) -> None:
        for registry in (
            "https://registry.npmjs.org:invalid",
            "https://registry.npmjs.org:65536",
        ):
            with self.subTest(registry=registry):
                with self.assertRaisesRegex(AdapterError, "invalid"):
                    _registry_url(registry)

    @patch("closurectl.adapters.npm._run_npm", return_value="11.17.0")
    def test_npm_cli_version_is_exact(self, run_npm) -> None:
        del run_npm
        with self.assertRaisesRegex(AdapterError, "11.18.0 is required"):
            require_supported_npm_version()

    @patch("closurectl.adapters.npm.subprocess.run")
    @patch("closurectl.adapters.npm.shutil.which", return_value="npm")
    def test_npm_child_receives_only_allowlisted_environment(self, which, run) -> None:
        del which

        def complete(*args, **kwargs):
            del args
            kwargs["stdout"].write(b"{}")
            return type("Completed", (), {"returncode": 0})()

        run.side_effect = complete
        with patch.dict(
            os.environ,
            {
                "GITHUB_TOKEN": "must-not-reach-npm",
                "CLOSURECTL_GITHUB_OBSERVER_TOKEN": "also-secret",
                "NPM_CONFIG_OTP": "one-time-code",
            },
        ):
            _run_npm(["whoami", "--json"], userconfig="recovery.npmrc")
        child_environment = run.call_args.kwargs["env"]
        self.assertNotIn("GITHUB_TOKEN", child_environment)
        self.assertNotIn("CLOSURECTL_GITHUB_OBSERVER_TOKEN", child_environment)
        self.assertNotIn("NPM_CONFIG_OTP", child_environment)

    @patch("closurectl.adapters.npm.subprocess.run")
    @patch("closurectl.adapters.npm.shutil.which", return_value="npm")
    def test_npm_stdout_and_stderr_are_bounded(self, which, run) -> None:
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
                    _run_npm(["whoami", "--json"])


if __name__ == "__main__":
    unittest.main()
