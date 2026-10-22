from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from closurectl.errors import ExecutionError, ValidationError
from closurectl.execution import (
    apply_execution,
    create_execution_preview,
    observe_execution,
    read_execution_journal,
)
from closurectl.execution_models import parse_execution_target, parse_rfc3339
from closurectl.executors.base import ApplyResult, ObservationResult
from closurectl.models import AuthorityGraph, PlanAction
from closurectl.planner import plan_closure
from closurectl.serialization import digest_json


def executable_graph(*, two_actions: bool = False) -> AuthorityGraph:
    edges = [
        {
            "id": "disable-release",
            "source": "root",
            "target": "sink",
            "kind": "can_mint",
            "label": "Disable release workflow",
            "revocable": True,
            "cost": 1,
            "enforcement": {
                "provider": "github",
                "operation": "disable_workflow",
                "target": "github://example/project/actions/workflows/42",
                "phase": "stop_minting",
            },
        }
    ]
    if two_actions:
        edges.append(
            {
                "id": "cancel-run",
                "source": "root",
                "target": "sink",
                "kind": "pending_effect",
                "label": "Cancel release run",
                "revocable": True,
                "cost": 1,
                "enforcement": {
                    "provider": "github",
                    "operation": "cancel_run",
                    "target": "github://example/project/actions/runs/99",
                    "phase": "cancel_pending",
                },
            }
        )
    return AuthorityGraph.from_dict(
        {
            "schema_version": "1",
            "title": "Executable incident",
            "nodes": [
                {"id": "root", "kind": "root", "label": "Compromised authority"},
                {"id": "sink", "kind": "sink", "label": "Protected effect"},
            ],
            "edges": edges,
            "roots": ["root"],
            "sinks": ["sink"],
        }
    )


class FakeExecutor:
    provider = "github"

    def __init__(self, results: list[str] | None = None) -> None:
        self.results = list(results or ["VERIFIED"])
        self.applied: list[str] = []
        self.reconciled: list[str] = []
        self.current_state: str | None = None
        self.observed_identity = "github:observer#2"
        self.binding_observer_identity = "github:observer#2"
        self.api_origin = "https://api.github.test"
        self.reconcile_state = "VERIFIED"

    def preview(self, action, target):
        kind = target.resource_kind
        return {
            "provider_account": target.repository,
            "api_origin": self.api_origin,
            "mutation_identity": "github:mutator#1",
            "observer_identity": self.binding_observer_identity,
            "current_state": self.current_state or ("active" if kind == "workflow" else "queued"),
            "effect": "test exact action",
            "resource": {"id": int(target.resource_id), "kind": kind},
        }

    def binding(self, action, target):
        del action
        return {
            "provider_account": target.repository,
            "api_origin": self.api_origin,
            "mutation_identity": "github:mutator#1",
            "observer_identity": self.binding_observer_identity,
        }

    def apply(self, action, target, *, preview_action, requested_at):
        del preview_action, requested_at
        self.applied.append(action.action_id)
        state = self.results.pop(0)
        return ApplyResult(state, f"result is {state}", target.resource_uri)

    def reconcile(self, action, target, *, preview_action, requested_at):
        del preview_action, requested_at
        self.reconciled.append(action.action_id)
        return ApplyResult(self.reconcile_state, "reconciled", target.resource_uri)

    def observe(self, action, target, *, requested_at, preview_action):
        del requested_at, preview_action
        return ObservationResult(
            "VERIFIED_CLOSED",
            "independent test observation",
            target.resource_uri,
            self.observed_identity,
            target.repository,
            self.api_origin,
            "test-state",
        )


class ExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
        self.graph = executable_graph()
        self.plan = plan_closure(self.graph)
        self.executor = FakeExecutor()
        self.executors = {"github": self.executor}
        self.preview = create_execution_preview(
            self.graph,
            self.plan,
            self.executors,
            now=lambda: self.now,
        )

    def test_preview_and_journal_match_published_schemas(self) -> None:
        schemas = Path(__file__).resolve().parents[1] / "schemas"
        preview_schema = json.loads(
            (schemas / "execution-preview.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(preview_schema).validate(self.preview)
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "execution.jsonl"
            apply_execution(
                self.graph,
                self.plan,
                self.preview,
                self.preview["preview_digest"],
                journal,
                self.executors,
                now=lambda: self.now,
            )
            event_schema = json.loads(
                (schemas / "execution-journal-event.schema.json").read_text(encoding="utf-8")
            )
            validator = Draft202012Validator(event_schema)
            for event in read_execution_journal(journal):
                validator.validate(event)

    def test_exact_targets_and_phase_are_required(self) -> None:
        target = parse_execution_target(self.plan.actions[0])
        self.assertEqual(target.repository, "example/project")
        invalid = PlanAction(
            action_id="close:bad",
            edge_id="bad",
            provider="github",
            operation="disable_workflow",
            target="release.yml",
            phase="stop_minting",
            cost=1,
            reason="unsafe alias",
        )
        with self.assertRaisesRegex(ValidationError, "GitHub targets"):
            parse_execution_target(invalid)

    def test_github_owner_and_repository_casing_is_preserved(self) -> None:
        action = PlanAction(
            action_id="close:mixed-case",
            edge_id="mixed-case",
            provider="github",
            operation="disable_workflow",
            target="github://patcGM/ClosureCtl-Lab/actions/workflows/42",
            phase="stop_minting",
            cost=1,
            reason="test canonical GitHub casing",
        )
        target = parse_execution_target(action)
        self.assertEqual(target.account, "patcGM")
        self.assertEqual(target.repository, "patcGM/ClosureCtl-Lab")
        self.assertEqual(target.resource_uri, action.target)

    def test_targets_reject_ports_noncanonical_paths_and_option_tokens(self) -> None:
        base = self.plan.actions[0]
        invalid_targets = (
            "github://example:443/project/actions/workflows/42",
            "github://example//project/actions/workflows/42",
            "github://example/project/actions/workflows/42/",
            "github://example/../actions/workflows/42",
        )
        for target in invalid_targets:
            with self.subTest(target=target):
                invalid = PlanAction(
                    action_id=base.action_id,
                    edge_id=base.edge_id,
                    provider=base.provider,
                    operation=base.operation,
                    target=target,
                    phase=base.phase,
                    cost=base.cost,
                    reason=base.reason,
                )
                with self.assertRaises(ValidationError):
                    parse_execution_target(invalid)

        npm = PlanAction(
            action_id="close:npm",
            edge_id="npm",
            provider="npm",
            operation="revoke_token",
            target="npm://registry.npmjs.org/tokens/--force",
            phase="revoke_roots",
            cost=1,
            reason="test",
        )
        with self.assertRaises(ValidationError):
            parse_execution_target(npm)

    def test_rfc3339_parser_is_strict(self) -> None:
        self.assertEqual(
            parse_rfc3339("2026-10-21T12:00:00Z", "timestamp"),
            self.now,
        )
        for value in (
            "2026-10-21 12:00:00Z",
            "2026-10-21T12:00:00z",
            "2026-10-21T12:00Z",
            "2026-10-21T12:00:00",
            "2026-02-30T12:00:00Z",
            "2026-10-21T12:00:00+24:00",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValidationError, "RFC 3339"):
                    parse_rfc3339(value, "timestamp")

    def test_confirmed_apply_writes_hash_chained_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "execution.jsonl"
            summary = apply_execution(
                self.graph,
                self.plan,
                self.preview,
                self.preview["preview_digest"],
                journal,
                self.executors,
                now=lambda: self.now + timedelta(seconds=1),
            )
            self.assertTrue(summary["complete"])
            self.assertEqual(self.executor.applied, ["close:disable-release"])
            events = read_execution_journal(journal)
            self.assertEqual(
                [event["state"] for event in events],
                ["PREVIEWED", "REQUESTED", "RECONCILING", "VERIFIED"],
            )

            resumed = apply_execution(
                self.graph,
                self.plan,
                self.preview,
                self.preview["preview_digest"],
                journal,
                self.executors,
                resume=True,
            )
            self.assertTrue(resumed["complete"])
            self.assertEqual(self.executor.applied, ["close:disable-release"])

    def test_confirmation_and_expiry_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "execution.jsonl"
            with self.assertRaisesRegex(ExecutionError, "confirmation digest"):
                apply_execution(
                    self.graph,
                    self.plan,
                    self.preview,
                    "0" * 64,
                    journal,
                    self.executors,
                    now=lambda: self.now,
                )
            with self.assertRaisesRegex(ExecutionError, "expired"):
                apply_execution(
                    self.graph,
                    self.plan,
                    self.preview,
                    self.preview["preview_digest"],
                    journal,
                    self.executors,
                    now=lambda: self.now + timedelta(hours=1),
                )
            extended = json.loads(json.dumps(self.preview))
            extended["expires_at"] = "2026-10-22T12:00:00Z"
            extended["preview_digest"] = digest_json(
                {key: value for key, value in extended.items() if key != "preview_digest"}
            )
            with self.assertRaisesRegex(ValidationError, "exactly 900 seconds"):
                apply_execution(
                    self.graph,
                    self.plan,
                    extended,
                    extended["preview_digest"],
                    journal,
                    self.executors,
                    now=lambda: self.now,
                )

    def test_concurrent_provider_change_requires_a_new_preview(self) -> None:
        self.executor.current_state = "disabled_manually"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ExecutionError, "state changed after preview"):
                apply_execution(
                    self.graph,
                    self.plan,
                    self.preview,
                    self.preview["preview_digest"],
                    Path(directory) / "execution.jsonl",
                    self.executors,
                    now=lambda: self.now,
                )
        self.assertEqual(self.executor.applied, [])

    def test_api_origin_change_requires_a_new_preview(self) -> None:
        self.executor.api_origin = "https://github.enterprise.test/api/v3"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ExecutionError, "API origin changed"):
                apply_execution(
                    self.graph,
                    self.plan,
                    self.preview,
                    self.preview["preview_digest"],
                    Path(directory) / "execution.jsonl",
                    self.executors,
                    now=lambda: self.now,
                )
        self.assertEqual(self.executor.applied, [])

    def test_resume_revalidates_journal_success_with_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "execution.jsonl"
            apply_execution(
                self.graph,
                self.plan,
                self.preview,
                self.preview["preview_digest"],
                journal,
                self.executors,
                now=lambda: self.now,
            )
            self.executor.reconcile_state = "INDETERMINATE"
            with self.assertRaisesRegex(ExecutionError, "no longer reconciles"):
                apply_execution(
                    self.graph,
                    self.plan,
                    self.preview,
                    self.preview["preview_digest"],
                    journal,
                    self.executors,
                    resume=True,
                )

    def test_resume_rejects_changed_credential_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "execution.jsonl"
            apply_execution(
                self.graph,
                self.plan,
                self.preview,
                self.preview["preview_digest"],
                journal,
                self.executors,
                now=lambda: self.now,
            )
            self.executor.binding_observer_identity = "github:other-account#9"
            with self.assertRaisesRegex(ExecutionError, "credential identity changed"):
                apply_execution(
                    self.graph,
                    self.plan,
                    self.preview,
                    self.preview["preview_digest"],
                    journal,
                    self.executors,
                    resume=True,
                )

    def test_journal_tampering_breaks_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "execution.jsonl"
            apply_execution(
                self.graph,
                self.plan,
                self.preview,
                self.preview["preview_digest"],
                journal,
                self.executors,
                now=lambda: self.now,
            )
            content = journal.read_text(encoding="utf-8").replace(
                "result is VERIFIED",
                "forged success",
            )
            journal.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "digest"):
                read_execution_journal(journal)

    def test_journal_rejects_duplicate_keys_and_float_sequences(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "execution.jsonl"
            apply_execution(
                self.graph,
                self.plan,
                self.preview,
                self.preview["preview_digest"],
                journal,
                self.executors,
                now=lambda: self.now,
            )
            first_line = journal.read_text(encoding="utf-8").splitlines()[0]
            journal.write_text(
                first_line[:-1] + ',"sequence":1}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValidationError, "duplicate JSON"):
                read_execution_journal(journal)

            event = json.loads(first_line)
            event["sequence"] = 1.0
            event["event_digest"] = digest_json(
                {key: value for key, value in event.items() if key != "event_digest"}
            )
            journal.write_text(json.dumps(event) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "sequence"):
                read_execution_journal(journal)

    def test_rehashed_invalid_journal_transition_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "execution.jsonl"
            apply_execution(
                self.graph,
                self.plan,
                self.preview,
                self.preview["preview_digest"],
                journal,
                self.executors,
                now=lambda: self.now,
            )
            events = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
            events[0]["state"] = "VERIFIED"
            previous = ""
            for event in events:
                event["previous_event_digest"] = previous
                event["event_digest"] = digest_json(
                    {key: value for key, value in event.items() if key != "event_digest"}
                )
                previous = event["event_digest"]
            journal.write_text(
                "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValidationError, "transition"):
                apply_execution(
                    self.graph,
                    self.plan,
                    self.preview,
                    self.preview["preview_digest"],
                    journal,
                    self.executors,
                    resume=True,
                )

    def test_resume_never_starts_from_an_empty_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ExecutionError, "non-empty"):
                apply_execution(
                    self.graph,
                    self.plan,
                    self.preview,
                    self.preview["preview_digest"],
                    Path(directory) / "execution.jsonl",
                    self.executors,
                    resume=True,
                    now=lambda: self.now + timedelta(days=1),
                )
        self.assertEqual(self.executor.applied, [])

    def test_indeterminate_action_stops_later_phase(self) -> None:
        graph = executable_graph(two_actions=True)
        plan = plan_closure(graph)
        executor = FakeExecutor(["INDETERMINATE", "VERIFIED"])
        preview = create_execution_preview(
            graph,
            plan,
            {"github": executor},
            now=lambda: self.now,
        )
        with tempfile.TemporaryDirectory() as directory:
            summary = apply_execution(
                graph,
                plan,
                preview,
                preview["preview_digest"],
                Path(directory) / "execution.jsonl",
                {"github": executor},
                now=lambda: self.now,
            )
        self.assertFalse(summary["complete"])
        self.assertEqual(executor.applied, ["close:disable-release"])
        self.assertIn("close:cancel-run", summary["unresolved_actions"])

    def test_observation_is_separate_evidence_v2(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "execution.jsonl"
            apply_execution(
                self.graph,
                self.plan,
                self.preview,
                self.preview["preview_digest"],
                journal,
                self.executors,
                now=lambda: self.now,
            )
            evidence = observe_execution(
                self.graph,
                self.plan,
                self.preview,
                journal,
                self.executors,
            )
        self.assertEqual(evidence["schema_version"], "2")
        self.assertEqual(evidence["observations"][0]["status"], "VERIFIED_CLOSED")
        self.assertEqual(evidence["observations"][0]["observer_identity"], "github:observer#2")

    def test_changed_observer_identity_is_indeterminate(self) -> None:
        self.executor.observed_identity = "github:unexpected#3"
        with tempfile.TemporaryDirectory() as directory:
            evidence = observe_execution(
                self.graph,
                self.plan,
                self.preview,
                Path(directory) / "execution.jsonl",
                self.executors,
            )
        self.assertEqual(evidence["observations"][0]["status"], "INDETERMINATE")
        self.assertIn("differs from the confirmed preview", evidence["observations"][0]["summary"])


if __name__ == "__main__":
    unittest.main()
