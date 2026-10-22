from __future__ import annotations

import unittest

from closurectl.adapters.github import GitHubResponse
from closurectl.errors import AdapterError
from closurectl.execution_models import parse_execution_target
from closurectl.executors.github import (
    GITHUB_RECONCILE_ATTEMPTS,
    GITHUB_RECONCILE_INTERVAL_SECONDS,
    GitHubExecutor,
)
from closurectl.models import PlanAction


def action(operation: str = "disable_workflow") -> PlanAction:
    workflow = operation == "disable_workflow"
    return PlanAction(
        action_id=f"close:{operation}",
        edge_id=operation,
        provider="github",
        operation=operation,
        target=(
            "github://example/project/actions/workflows/42"
            if workflow
            else "github://example/project/actions/runs/99"
        ),
        phase="stop_minting" if workflow else "cancel_pending",
        cost=1,
        reason="test",
    )


class FakeGitHubClient:
    def __init__(self, identity: tuple[str, int], resources: list[dict] | None = None) -> None:
        self.identity = identity
        self.api_url = "https://api.github.test"
        self.resources = list(resources or [])
        self.posts: list[str] = []
        self.puts: list[str] = []
        self.error: AdapterError | None = None

    def get(self, path: str) -> GitHubResponse:
        if self.error:
            raise self.error
        if path == "/user":
            return GitHubResponse(
                {"login": self.identity[0], "id": self.identity[1], "type": "User"},
                (),
            )
        if not self.resources:
            raise AssertionError(f"no resource response available for {path}")
        return GitHubResponse(self.resources.pop(0), ())

    def put(self, path: str, *, accepted_statuses=(204,)) -> GitHubResponse:
        self.puts.append(path)
        return GitHubResponse(None, (), 204)

    def post(self, path: str, *, accepted_statuses=(202, 409)) -> GitHubResponse:
        self.posts.append(path)
        return GitHubResponse(None, (), 409)


def executor(mutation: FakeGitHubClient, observer: FakeGitHubClient) -> GitHubExecutor:
    result = GitHubExecutor.__new__(GitHubExecutor)
    result._mutation = mutation
    result._observer = observer
    result._attempts = 2
    result._interval = 0
    result._sleep = lambda _: None
    return result


class GitHubExecutorTests(unittest.TestCase):
    def test_default_reconciliation_window_allows_async_cancellation(self) -> None:
        self.assertGreaterEqual(
            (GITHUB_RECONCILE_ATTEMPTS - 1) * GITHUB_RECONCILE_INTERVAL_SECONDS,
            20,
        )

    def test_preview_requires_distinct_break_glass_identity(self) -> None:
        workflow = {
            "id": 42,
            "name": "Release",
            "path": ".github/workflows/release.yml",
            "state": "active",
        }
        subject = action()
        target = parse_execution_target(subject)
        client = executor(
            FakeGitHubClient(("maintainer", 1), [workflow]),
            FakeGitHubClient(("maintainer", 1)),
        )
        with self.assertRaisesRegex(Exception, "different account"):
            client.preview(subject, target)

    def test_disable_workflow_reconciles_after_put(self) -> None:
        active = {"id": 42, "name": "Release", "path": "release.yml", "state": "active"}
        disabled = {
            "id": 42,
            "name": "Release",
            "path": "release.yml",
            "state": "disabled_manually",
        }
        mutation = FakeGitHubClient(("mutator", 1), [active, disabled])
        client = executor(mutation, FakeGitHubClient(("observer", 2)))
        subject = action()
        result = client.apply(subject, parse_execution_target(subject))
        self.assertEqual(result.state, "VERIFIED")
        self.assertEqual(
            mutation.puts,
            ["/repos/example/project/actions/workflows/42/disable"],
        )

    def test_cancel_run_reconciles_a_conflict_without_retry(self) -> None:
        running = {
            "id": 99,
            "workflow_id": 42,
            "run_attempt": 1,
            "head_sha": "a" * 40,
            "status": "in_progress",
            "conclusion": None,
        }
        cancelled = {**running, "status": "completed", "conclusion": "cancelled"}
        mutation = FakeGitHubClient(("mutator", 1), [running, cancelled])
        client = executor(mutation, FakeGitHubClient(("observer", 2)))
        subject = action("cancel_run")
        result = client.apply(subject, parse_execution_target(subject))
        self.assertEqual(result.state, "VERIFIED")
        self.assertEqual(
            mutation.posts,
            ["/repos/example/project/actions/runs/99/cancel"],
        )

    def test_reconciliation_timeout_is_indeterminate(self) -> None:
        running = {
            "id": 99,
            "workflow_id": 42,
            "run_attempt": 1,
            "head_sha": "a" * 40,
            "status": "in_progress",
            "conclusion": None,
        }
        mutation = FakeGitHubClient(("mutator", 1), [running, running, running])
        client = executor(mutation, FakeGitHubClient(("observer", 2)))
        subject = action("cancel_run")
        result = client.apply(subject, parse_execution_target(subject))
        self.assertEqual(result.state, "INDETERMINATE")
        self.assertEqual(len(mutation.posts), 1)

    def test_observer_denial_is_not_closed(self) -> None:
        observer = FakeGitHubClient(("observer", 2))
        observer.error = AdapterError("GitHub denied read-only inventory (403)")
        client = executor(FakeGitHubClient(("mutator", 1)), observer)
        subject = action()
        result = client.observe(
            subject,
            parse_execution_target(subject),
            requested_at=None,
        )
        self.assertEqual(result.status, "INDETERMINATE")


if __name__ == "__main__":
    unittest.main()
