from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from closurectl.adapters.github import (
    GitHubResponse,
    _https_origin,
    _SameOriginRedirectHandler,
    collect_github_inventory,
)
from closurectl.adapters.npm import collect_npm_inventory
from closurectl.errors import AdapterError


class AdapterTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
