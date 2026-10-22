from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from closurectl.cli import main
from closurectl.errors import ValidationError
from closurectl.incident import (
    build_authority_graph,
    create_incident_draft,
    validate_incident_draft,
)
from closurectl.planner import plan_closure
from closurectl.receipts import utc_now
from closurectl.serialization import read_json, write_json


def github_inventory(*, truncated: bool = False) -> dict:
    return {
        "schema_version": "1",
        "adapter": "github-read-only",
        "collected_at": "2026-10-21T12:00:00Z",
        "credential_handle": "environment:GITHUB_TOKEN",
        "subject": {"login": "maintainer", "id": 7, "type": "User"},
        "oauth_scopes": ["repo", "workflow"],
        "repositories": [
            {
                "full_name": "example/project",
                "private": False,
                "archived": False,
                "default_branch": "main",
                "permissions": {"admin": True},
                "workflows": [
                    {
                        "id": 42,
                        "name": "Release",
                        "path": ".github/workflows/release.yml",
                        "state": "active",
                    },
                    {
                        "id": 43,
                        "name": "Disabled",
                        "path": ".github/workflows/disabled.yml",
                        "state": "disabled_manually",
                    },
                ],
                "workflow_count": 3 if truncated else 2,
                "workflow_results_truncated": truncated,
                "active_runs": [
                    {
                        "id": 99,
                        "workflow_id": 42,
                        "name": "Release",
                        "event": "push",
                        "status": "in_progress",
                        "run_attempt": 1,
                        "head_sha": "a" * 40,
                        "created_at": "2026-10-21T12:00:00Z",
                        "html_url": "https://github.com/example/project/actions/runs/99",
                    }
                ],
                "run_count_scanned": 1,
                "run_results_truncated": False,
                "deploy_keys": [
                    {
                        "id": 5,
                        "title": "production",
                        "read_only": False,
                        "verified": True,
                        "created_at": "2026-10-01T12:00:00Z",
                    }
                ],
                "deploy_key_count": 1,
                "deploy_key_results_truncated": False,
            }
        ],
        "limitations": ["bounded"],
    }


def npm_inventory() -> dict:
    return {
        "schema_version": "1",
        "adapter": "npm-read-only",
        "collected_at": "2026-10-21T12:01:00Z",
        "credential_handle": "npm-cli-current-user",
        "registry": "https://registry.npmjs.org",
        "credential_metadata": [
            {
                "id": "token-id-123",
                "name": "release",
                "readonly": False,
            }
        ],
        "packages": [
            {
                "name": "example-package",
                "owners": [{"name": "maintainer", "email": "maintainer@example.test"}],
                "dist_tags": {"latest": "1.0.0"},
            }
        ],
        "limitations": ["bounded"],
    }


class IncidentDraftTests(unittest.TestCase):
    def test_selected_inventory_paths_build_an_executable_plan(self) -> None:
        draft = create_incident_draft(
            "Compromised release",
            [github_inventory(), npm_inventory()],
            now=lambda: "2026-10-21T12:02:00Z",
        )
        candidate_ids = {item["candidate_id"] for item in draft["candidates"]}
        self.assertIn("github:example/project:disable-workflow:42", candidate_ids)
        self.assertIn("github:example/project:cancel-run:99", candidate_ids)
        self.assertIn("github:example/project:deploy-key:5", candidate_ids)
        self.assertIn("npm:registry.npmjs.org:revoke-token:token-id-123", candidate_ids)
        self.assertNotIn("github:example/project:disable-workflow:43", candidate_ids)
        for candidate in draft["candidates"]:
            self.assertRegex(candidate["provenance"]["source_digest"], r"^[a-f0-9]{64}$")
            self.assertTrue(candidate["provenance"]["evidence_paths"])
        workflow = next(
            item
            for item in draft["candidates"]
            if item["candidate_id"] == "github:example/project:disable-workflow:42"
        )
        self.assertIn("workflow", workflow["nodes"][1]["label"].lower())
        self.assertNotIn("repository access", workflow["nodes"][1]["label"].lower())

        selected = [
            "github:example/project:disable-workflow:42",
            "github:example/project:cancel-run:99",
            "npm:registry.npmjs.org:revoke-token:token-id-123",
        ]
        graph = build_authority_graph(draft, selected, draft["draft_digest"])
        plan = plan_closure(graph)
        self.assertEqual(plan.status, "PLANNED")
        self.assertEqual(
            {(action.provider, action.operation) for action in plan.actions},
            {
                ("github", "disable_workflow"),
                ("github", "cancel_run"),
                ("npm", "revoke_token"),
            },
        )

    def test_build_requires_exact_digest_and_known_selection(self) -> None:
        draft = create_incident_draft(
            "Incident",
            [github_inventory()],
            now=lambda: "2026-10-21T12:02:00Z",
        )
        selected = ["github:example/project:disable-workflow:42"]
        with self.assertRaisesRegex(ValidationError, "exact draft digest"):
            build_authority_graph(draft, selected, "0" * 64)
        with self.assertRaisesRegex(ValidationError, "unknown incident candidates"):
            build_authority_graph(draft, ["missing"], draft["draft_digest"])

    def test_truncated_inventory_forces_a_blocked_graph(self) -> None:
        draft = create_incident_draft(
            "Incomplete incident",
            [github_inventory(truncated=True)],
            now=lambda: "2026-10-21T12:02:00Z",
        )
        mandatory = [item for item in draft["candidates"] if item["mandatory"]]
        self.assertEqual(
            [item["candidate_id"] for item in mandatory],
            ["github:example/project:inventory-gap"],
        )
        graph = build_authority_graph(
            draft,
            ["github:example/project:disable-workflow:42"],
            draft["draft_digest"],
        )
        self.assertEqual(plan_closure(graph).status, "BLOCKED")

    def test_tampered_draft_is_rejected(self) -> None:
        draft = create_incident_draft(
            "Incident",
            [npm_inventory()],
            now=lambda: "2026-10-21T12:02:00Z",
        )
        tampered = copy.deepcopy(draft)
        tampered["candidates"][0]["summary"] = "changed"
        with self.assertRaisesRegex(ValidationError, "draft_digest"):
            validate_incident_draft(tampered)

    def test_cli_draft_and_build_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path = root / "github.json"
            draft_path = root / "draft.json"
            graph_path = root / "graph.json"
            inventory = github_inventory()
            inventory["collected_at"] = utc_now()
            write_json(inventory_path, inventory)
            self.assertEqual(
                main(
                    [
                        "incident",
                        "draft",
                        "--title",
                        "CLI incident",
                        "--github-inventory",
                        str(inventory_path),
                        "--out",
                        str(draft_path),
                    ]
                ),
                0,
            )
            draft = read_json(draft_path)
            self.assertEqual(
                main(
                    [
                        "incident",
                        "build",
                        str(draft_path),
                        "--select",
                        "github:example/project:disable-workflow:42",
                        "--confirm",
                        draft["draft_digest"],
                        "--out",
                        str(graph_path),
                    ]
                ),
                0,
            )
            graph = read_json(graph_path)
            self.assertEqual(graph["title"], "CLI incident")
            self.assertEqual(len(graph["edges"]), 1)

    def test_interactive_wizard_requires_selection_and_digest(self) -> None:
        inventory = github_inventory()
        inventory["repositories"][0]["permissions"] = {"pull": True}
        inventory["repositories"][0]["active_runs"] = []
        inventory["repositories"][0]["run_count_scanned"] = 0
        inventory["repositories"][0]["deploy_keys"] = []
        inventory["repositories"][0]["deploy_key_count"] = 0
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            draft = create_incident_draft(
                "Wizard incident",
                [inventory],
                now=lambda: "2026-10-21T12:02:00Z",
            )
            draft_path = root / "draft.json"
            graph_path = root / "graph.json"
            write_json(draft_path, draft)
            with (
                patch("closurectl.cli.sys.stdin.isatty", return_value=True),
                patch("closurectl.cli.sys.stdout.isatty", return_value=True),
                patch("builtins.input", side_effect=["invalid", "yes", "CREATE GRAPH"]),
            ):
                result = main(
                    [
                        "incident",
                        "wizard",
                        str(draft_path),
                        "--out",
                        str(graph_path),
                    ]
                )
            self.assertEqual(result, 0)
            self.assertEqual(len(read_json(graph_path)["edges"]), 1)

    def test_inventory_freshness_future_and_strict_truncation(self) -> None:
        stale = github_inventory()
        stale["collected_at"] = "2026-10-21T10:00:00Z"
        with self.assertRaisesRegex(ValidationError, "older than"):
            create_incident_draft(
                "Stale",
                [stale],
                now=lambda: "2026-10-21T12:02:00Z",
            )

        future = github_inventory()
        future["collected_at"] = "2026-10-21T12:03:00Z"
        with self.assertRaisesRegex(ValidationError, "future"):
            create_incident_draft(
                "Future",
                [future],
                now=lambda: "2026-10-21T12:02:00Z",
            )

        malformed = github_inventory()
        malformed["repositories"][0]["workflow_results_truncated"] = 1
        with self.assertRaisesRegex(ValidationError, "true or false"):
            create_incident_draft(
                "Malformed",
                [malformed],
                now=lambda: "2026-10-21T12:02:00Z",
            )

    def test_readonly_npm_tokens_do_not_create_publication_candidates(self) -> None:
        inventory = npm_inventory()
        inventory["credential_metadata"][0]["readonly"] = True
        draft = create_incident_draft(
            "Readonly npm token",
            [inventory],
            now=lambda: "2026-10-21T12:02:00Z",
        )
        self.assertFalse(
            any(candidate["resource_kind"] == "token" for candidate in draft["candidates"])
        )

    def test_duplicate_and_conflicting_inventory_resources_are_rejected(self) -> None:
        duplicate = github_inventory()
        duplicate["repositories"].append(copy.deepcopy(duplicate["repositories"][0]))
        with self.assertRaisesRegex(ValidationError, "duplicate GitHub repository"):
            create_incident_draft(
                "Duplicate",
                [duplicate],
                now=lambda: "2026-10-21T12:02:00Z",
            )

        conflict = github_inventory()
        conflict["repositories"][0]["default_branch"] = "release"
        with self.assertRaisesRegex(ValidationError, "duplicate or conflicting"):
            create_incident_draft(
                "Conflict",
                [github_inventory(), conflict],
                now=lambda: "2026-10-21T12:02:00Z",
            )

    def test_wizard_requires_tty_and_refuses_overwrite(self) -> None:
        inventory = github_inventory()
        draft = create_incident_draft(
            "Wizard safety",
            [inventory],
            now=lambda: "2026-10-21T12:02:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            draft_path = root / "draft.json"
            output_path = root / "graph.json"
            write_json(draft_path, draft)
            with (
                patch("closurectl.cli.sys.stdin.isatty", return_value=False),
                patch("closurectl.cli.sys.stdout.isatty", return_value=True),
            ):
                self.assertEqual(
                    main(
                        [
                            "incident",
                            "wizard",
                            str(draft_path),
                            "--out",
                            str(output_path),
                        ]
                    ),
                    2,
                )
            output_path.write_text("do not replace", encoding="utf-8")
            with (
                patch("closurectl.cli.sys.stdin.isatty", return_value=True),
                patch("closurectl.cli.sys.stdout.isatty", return_value=True),
                patch(
                    "builtins.input",
                    side_effect=["yes", "no", "no", "no", "CREATE GRAPH"],
                ),
            ):
                self.assertEqual(
                    main(
                        [
                            "incident",
                            "wizard",
                            str(draft_path),
                            "--out",
                            str(output_path),
                        ]
                    ),
                    2,
                )
            self.assertEqual(output_path.read_text(encoding="utf-8"), "do not replace")


if __name__ == "__main__":
    unittest.main()
