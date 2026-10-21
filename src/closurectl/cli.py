"""Command-line interface for closurectl."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .adapters.aws import collect_aws_inventory
from .adapters.github import collect_github_inventory
from .adapters.npm import collect_npm_inventory
from .demo import closed_evidence, compromised_maintainer_graph
from .errors import ClosureCtlError, ValidationError
from .execution import (
    apply_execution,
    create_execution_preview,
    observe_execution,
    read_execution_journal,
)
from .executors.aws import AwsExecutor
from .executors.github import GitHubExecutor
from .executors.npm import NpmExecutor
from .incident import (
    build_authority_graph,
    create_incident_draft,
    validate_incident_draft,
)
from .models import AuthorityGraph, ClosurePlan
from .planner import plan_closure
from .receipts import (
    create_receipt,
    generate_keypair,
    utc_now,
    verify_receipt,
)
from .reporting import render_html_report, write_html_report
from .serialization import read_json, write_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="closurectl",
        description=("Plan and verify revocation closure for a declared authority graph."),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--json",
        action="store_true",
        help="write a machine-readable result to stdout",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate an authority graph")
    validate.add_argument("graph", help="path to graph JSON")

    plan = commands.add_parser("plan", help="compute a least-cost closure cut")
    plan.add_argument("graph", help="path to graph JSON")
    plan.add_argument("-o", "--out", required=True, help="closure plan output path")

    keygen = commands.add_parser("keygen", help="create an Ed25519 receipt keypair")
    keygen.add_argument("--private-key", required=True, help="private PEM output path")
    keygen.add_argument("--public-key", required=True, help="public PEM output path")

    receipt = commands.add_parser("receipt", help="sign closure observations for a plan")
    receipt.add_argument("graph", help="path to the authority graph JSON")
    receipt.add_argument("plan", help="path to closure plan JSON")
    receipt.add_argument("evidence", help="path to evidence JSON")
    receipt.add_argument("--private-key", required=True, help="Ed25519 private key")
    receipt.add_argument("-o", "--out", required=True, help="receipt output path")

    verify = commands.add_parser("verify", help="verify a receipt digest and signature")
    verify.add_argument("receipt", help="path to receipt JSON")
    verify.add_argument("--public-key", required=True, help="Ed25519 public key")
    verify.add_argument("--graph", required=True, help="authority graph used by the plan")
    verify.add_argument("--plan", required=True, help="closure plan to recompute and compare")

    inventory = commands.add_parser(
        "inventory", help="collect bounded, read-only provider metadata"
    )
    providers = inventory.add_subparsers(dest="provider", required=True)

    github = providers.add_parser("github", help="inventory GitHub repositories")
    github.add_argument(
        "--repo",
        action="append",
        required=True,
        help="OWNER/REPOSITORY; repeat for multiple repositories",
    )
    github.add_argument(
        "--api-url",
        default=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        help="GitHub API base URL (defaults to GITHUB_API_URL or github.com)",
    )
    github.add_argument("-o", "--out", required=True, help="inventory output path")

    npm = providers.add_parser("npm", help="inventory npm publication metadata")
    npm.add_argument(
        "--package",
        action="append",
        default=[],
        help="package name; repeat for multiple packages",
    )
    npm.add_argument(
        "--registry",
        default=os.environ.get("NPM_CONFIG_REGISTRY", "https://registry.npmjs.org"),
        help="HTTPS npm registry (defaults to NPM_CONFIG_REGISTRY or npmjs.org)",
    )
    npm.add_argument("-o", "--out", required=True, help="inventory output path")

    aws = providers.add_parser("aws", help="inventory exact AWS IAM roles")
    aws.add_argument(
        "--role",
        action="append",
        required=True,
        help="IAM role name; repeat for multiple roles",
    )
    aws.add_argument(
        "--profile",
        default=os.environ.get("AWS_PROFILE", ""),
        help="read-only AWS CLI profile (defaults to AWS_PROFILE)",
    )
    aws.add_argument("-o", "--out", required=True, help="inventory output path")

    incident = commands.add_parser(
        "incident",
        help="turn provider inventories into a human-confirmed authority graph",
    )
    incident_modes = incident.add_subparsers(dest="incident_mode", required=True)

    incident_draft = incident_modes.add_parser(
        "draft",
        help="propose review candidates from secret-free provider inventories",
    )
    incident_draft.add_argument("--title", required=True, help="incident title")
    incident_draft.add_argument(
        "--github-inventory",
        action="append",
        default=[],
        help="GitHub inventory JSON; repeat to combine snapshots",
    )
    incident_draft.add_argument(
        "--npm-inventory",
        action="append",
        default=[],
        help="npm inventory JSON; repeat to combine snapshots",
    )
    incident_draft.add_argument(
        "--aws-inventory",
        action="append",
        default=[],
        help="AWS IAM inventory JSON; repeat to combine snapshots",
    )
    incident_draft.add_argument("-o", "--out", required=True, help="draft output path")

    incident_build = incident_modes.add_parser(
        "build",
        help="build a graph from explicitly selected draft candidates",
    )
    incident_build.add_argument("draft", help="incident draft JSON")
    incident_build.add_argument(
        "--select",
        action="append",
        default=[],
        help="candidate ID to include; repeat for multiple paths",
    )
    incident_build.add_argument("--confirm", required=True, help="exact incident draft digest")
    incident_build.add_argument("-o", "--out", required=True, help="authority graph output path")

    incident_wizard = incident_modes.add_parser(
        "wizard",
        help="interactively review every candidate and build an authority graph",
    )
    incident_wizard.add_argument("draft", help="incident draft JSON")
    incident_wizard.add_argument("-o", "--out", required=True, help="authority graph output path")

    execute = commands.add_parser(
        "execute",
        help="preview or perform an exact, allow-listed provider mutation",
    )
    execution_modes = execute.add_subparsers(dest="execution_mode", required=True)

    preview = execution_modes.add_parser("preview", help="create a short-lived mutation preview")
    preview.add_argument("graph", help="path to the authority graph JSON")
    preview.add_argument("plan", help="path to the closure plan JSON")
    preview.add_argument("-o", "--out", required=True, help="preview output path")
    preview.add_argument(
        "--experimental",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    for mode in ("apply", "resume"):
        command = execution_modes.add_parser(
            mode,
            help=(
                "apply a confirmed preview"
                if mode == "apply"
                else "reconcile an interrupted execution without blind retries"
            ),
        )
        command.add_argument("graph", help="path to the authority graph JSON")
        command.add_argument("plan", help="path to the closure plan JSON")
        command.add_argument("preview", help="path to the execution preview JSON")
        command.add_argument("--confirm", required=True, help="exact preview SHA-256 digest")
        command.add_argument("--journal", required=True, help="append-only journal path")
        command.add_argument(
            "--experimental",
            action="store_true",
            help=argparse.SUPPRESS,
        )

    observe = commands.add_parser(
        "observe",
        help="independently observe provider state and write evidence v2",
    )
    observe.add_argument("graph", help="path to the authority graph JSON")
    observe.add_argument("plan", help="path to the closure plan JSON")
    observe.add_argument("preview", help="path to the execution preview JSON")
    observe.add_argument("--journal", required=True, help="execution journal path")
    observe.add_argument("-o", "--out", required=True, help="evidence output path")

    report = commands.add_parser(
        "report",
        help="render a verified, self-contained HTML closure report",
    )
    report.add_argument("graph", help="path to the authority graph JSON")
    report.add_argument("plan", help="path to the closure plan JSON")
    report.add_argument("receipt", help="path to the signed closure receipt JSON")
    report.add_argument("--public-key", required=True, help="Ed25519 public verification key")
    report.add_argument("--journal", help="optional append-only execution journal")
    report.add_argument("-o", "--out", required=True, help="HTML report output path")

    demo = commands.add_parser("demo", help="generate and verify a self-contained demo incident")
    demo.add_argument("--dir", default="closurectl-demo", help="directory for demo artifacts")
    return parser


def _load_graph(path: str) -> AuthorityGraph:
    return AuthorityGraph.from_dict(read_json(path))


def _load_verified_plan(graph_path: str, plan_path: str) -> ClosurePlan:
    graph = _load_graph(graph_path)
    supplied = ClosurePlan.from_dict(read_json(plan_path))
    recomputed = plan_closure(graph)
    if supplied.to_dict() != recomputed.to_dict():
        raise ValidationError(
            "closure plan does not match a fresh computation from the supplied graph"
        )
    return recomputed


def _load_graph_and_verified_plan(
    graph_path: str, plan_path: str
) -> tuple[AuthorityGraph, ClosurePlan]:
    graph = _load_graph(graph_path)
    supplied = ClosurePlan.from_dict(read_json(plan_path))
    recomputed = plan_closure(graph)
    if supplied.to_dict() != recomputed.to_dict():
        raise ValidationError(
            "closure plan does not match a fresh computation from the supplied graph"
        )
    return graph, recomputed


def _provider_executors(plan: ClosurePlan) -> dict[str, Any]:
    providers = {action.provider for action in plan.actions}
    executors: dict[str, Any] = {}
    if "github" in providers:
        executors["github"] = GitHubExecutor(
            os.environ.get("GITHUB_TOKEN", ""),
            os.environ.get("CLOSURECTL_GITHUB_OBSERVER_TOKEN", ""),
            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
    if "npm" in providers:
        mutation_config = os.environ.get("CLOSURECTL_NPM_MUTATION_USERCONFIG", "")
        recovery_config = os.environ.get("CLOSURECTL_NPM_RECOVERY_USERCONFIG", "")
        if not mutation_config or not recovery_config:
            raise ValidationError(
                "set CLOSURECTL_NPM_MUTATION_USERCONFIG and CLOSURECTL_NPM_RECOVERY_USERCONFIG"
            )
        executors["npm"] = NpmExecutor(
            mutation_config,
            recovery_config,
            registry=os.environ.get("CLOSURECTL_NPM_REGISTRY", "https://registry.npmjs.org"),
        )
    if "aws" in providers:
        mutation_profile = os.environ.get("CLOSURECTL_AWS_MUTATION_PROFILE", "")
        observer_profile = os.environ.get("CLOSURECTL_AWS_OBSERVER_PROFILE", "")
        if not mutation_profile or not observer_profile:
            raise ValidationError(
                "set CLOSURECTL_AWS_MUTATION_PROFILE and CLOSURECTL_AWS_OBSERVER_PROFILE"
            )
        executors["aws"] = AwsExecutor(mutation_profile, observer_profile)
    return executors


def _emit_json(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _prompt_candidate_selection(draft: dict[str, Any]) -> tuple[list[str], str]:
    selected: list[str] = []
    print(f"incident: {draft['title']}")
    print(f"draft:    {draft['draft_digest']}")
    print("Inventory paths are proposals, not proof. Review every assumption.")
    for candidate in draft["candidates"]:
        print()
        print(f"[{candidate['candidate_id']}] {candidate['summary']}")
        print(f"  assumption: {candidate['assumption']}")
        if candidate["mandatory"]:
            print("  mandatory: incomplete inventory forces this blocking path")
            selected.append(candidate["candidate_id"])
            continue
        try:
            answer = input("  include this path? [y/N] ").strip().lower()
        except EOFError as exc:
            raise ValidationError("incident wizard input ended before review completed") from exc
        if answer in {"y", "yes"}:
            selected.append(candidate["candidate_id"])
        elif answer not in {"", "n", "no"}:
            raise ValidationError("incident wizard answers must be yes or no")
    try:
        confirmation = input("Type the exact draft digest to build the graph: ").strip()
    except EOFError as exc:
        raise ValidationError("incident wizard input ended before digest confirmation") from exc
    return selected, confirmation


def _print_plan(plan: ClosurePlan) -> None:
    print(f"status: {plan.status}")
    print(f"graph:  {plan.graph_digest}")
    print(f"plan:   {plan.digest}")
    if plan.status == "BLOCKED":
        print("No finite declared closure cut exists.")
        if plan.blocked_path:
            print("unclosable path: " + " -> ".join(plan.blocked_path))
        return
    print(f"cost:   {plan.total_cost}")
    print(f"actions: {len(plan.actions)}")
    for number, action in enumerate(plan.actions, start=1):
        print(
            f"  {number}. [{action.phase}] {action.provider}:{action.operation} -> {action.target}"
        )


def _run_demo(directory: str) -> None:
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=True)
    graph_path = output / "authority-graph.json"
    plan_path = output / "closure-plan.json"
    evidence_path = output / "evidence.json"
    private_path = output / "demo-private.pem"
    public_path = output / "demo-public.pem"
    receipt_path = output / "closure-receipt.json"

    graph_dict = compromised_maintainer_graph()
    write_json(graph_path, graph_dict)
    graph = AuthorityGraph.from_dict(graph_dict)
    plan = plan_closure(graph)
    write_json(plan_path, plan.to_dict())
    generate_keypair(private_path, public_path)
    evidence = closed_evidence(plan, utc_now())
    write_json(evidence_path, evidence)
    receipt = create_receipt(plan, evidence, private_path)
    write_json(receipt_path, receipt)
    verification = verify_receipt(receipt, public_path, plan)

    print("Demo models authority that survives a root credential revocation.")
    _print_plan(plan)
    print(f"receipt: {verification['closure_state']}")
    print(f"verified: {verification['receipt_digest']}")
    print(f"artifacts: {output.resolve()}")
    print("The demo private key is disposable. Never use it for a real incident.")


def _execute(arguments: argparse.Namespace) -> int:
    if arguments.command == "validate":
        graph = _load_graph(arguments.graph)
        if arguments.json:
            _emit_json(
                {
                    "valid": True,
                    "title": graph.title,
                    "graph_digest": graph.digest,
                    "nodes": len(graph.nodes),
                    "edges": len(graph.edges),
                    "roots": len(graph.roots),
                    "sinks": len(graph.sinks),
                }
            )
        else:
            print(f"valid: {graph.title}")
            print(f"digest: {graph.digest}")
            print(
                f"nodes: {len(graph.nodes)}, edges: {len(graph.edges)}, "
                f"roots: {len(graph.roots)}, sinks: {len(graph.sinks)}"
            )
        return 0

    if arguments.command == "plan":
        plan = plan_closure(_load_graph(arguments.graph))
        write_json(arguments.out, plan.to_dict())
        if arguments.json:
            _emit_json(
                {
                    "status": plan.status,
                    "graph_digest": plan.graph_digest,
                    "plan_digest": plan.digest,
                    "actions": len(plan.actions),
                    "written": str(Path(arguments.out).resolve()),
                }
            )
        else:
            _print_plan(plan)
            print(f"written: {Path(arguments.out).resolve()}")
        return 3 if plan.status == "BLOCKED" else 0

    if arguments.command == "keygen":
        generate_keypair(arguments.private_key, arguments.public_key)
        if arguments.json:
            _emit_json(
                {
                    "private_key": str(Path(arguments.private_key).resolve()),
                    "public_key": str(Path(arguments.public_key).resolve()),
                }
            )
        else:
            print(f"private key: {Path(arguments.private_key).resolve()}")
            print(f"public key:  {Path(arguments.public_key).resolve()}")
            print("Store the private key outside the incident host.")
        return 0

    if arguments.command == "receipt":
        plan = _load_verified_plan(arguments.graph, arguments.plan)
        evidence = read_json(arguments.evidence)
        receipt = create_receipt(plan, evidence, arguments.private_key)
        write_json(arguments.out, receipt)
        result = {
            "closure_state": receipt["closure_state"],
            "receipt_digest": receipt["receipt_digest"],
            "written": str(Path(arguments.out).resolve()),
        }
        if arguments.json:
            _emit_json(result)
        else:
            print(f"closure state: {result['closure_state']}")
            print(f"receipt digest: {result['receipt_digest']}")
            print(f"written: {result['written']}")
        return 0 if receipt["closure_state"] == "CLOSED" else 4

    if arguments.command == "verify":
        plan = _load_verified_plan(arguments.graph, arguments.plan)
        receipt = read_json(arguments.receipt)
        result = verify_receipt(receipt, arguments.public_key, plan)
        if arguments.json:
            _emit_json({"signature": "VALID", **result})
        else:
            print("signature: VALID")
            print(f"closure state: {result['closure_state']}")
            print(f"issued at: {result['issued_at']}")
            print(f"receipt digest: {result['receipt_digest']}")
        return 0 if result["closure_state"] == "CLOSED" else 4

    if arguments.command == "inventory":
        if arguments.provider == "github":
            credential = os.environ.get("GITHUB_TOKEN", "")
            snapshot = collect_github_inventory(
                credential,
                arguments.repo,
                api_url=arguments.api_url,
            )
        elif arguments.provider == "npm":
            snapshot = collect_npm_inventory(
                arguments.package,
                registry=arguments.registry,
            )
        else:
            if not arguments.profile:
                raise ValidationError("set AWS_PROFILE or pass --profile")
            snapshot = collect_aws_inventory(arguments.role, profile=arguments.profile)
        write_json(arguments.out, snapshot)
        destination = str(Path(arguments.out).resolve())
        if arguments.json:
            _emit_json(
                {
                    "provider": arguments.provider,
                    "written": destination,
                    "read_only": True,
                }
            )
        else:
            print(f"read-only inventory written: {destination}")
            print("Only allow-listed metadata was written; review it before sharing.")
        return 0

    if arguments.command == "incident":
        if arguments.incident_mode == "draft":
            inventory_paths = [
                *arguments.github_inventory,
                *arguments.npm_inventory,
                *arguments.aws_inventory,
            ]
            if not inventory_paths:
                raise ValidationError("provide at least one GitHub or npm inventory")
            draft = create_incident_draft(
                arguments.title,
                [read_json(path) for path in inventory_paths],
            )
            write_json(arguments.out, draft)
            result = {
                "draft_digest": draft["draft_digest"],
                "candidates": len(draft["candidates"]),
                "mandatory_candidates": sum(
                    1 for candidate in draft["candidates"] if candidate["mandatory"]
                ),
                "written": str(Path(arguments.out).resolve()),
            }
            if arguments.json:
                _emit_json(result)
            else:
                print(f"draft: {result['draft_digest']}")
                print(f"candidates: {result['candidates']}")
                print(f"mandatory blocking paths: {result['mandatory_candidates']}")
                for candidate in draft["candidates"]:
                    marker = "mandatory" if candidate["mandatory"] else "selectable"
                    print(f"  [{marker}] {candidate['candidate_id']}: {candidate['summary']}")
                print(f"written: {result['written']}")
            return 0

        draft = validate_incident_draft(read_json(arguments.draft))
        if arguments.incident_mode == "wizard":
            if arguments.json:
                raise ValidationError("--json cannot be combined with the interactive wizard")
            selected, confirmation = _prompt_candidate_selection(draft)
        else:
            selected = arguments.select
            confirmation = arguments.confirm
        graph = build_authority_graph(draft, selected, confirmation)
        write_json(arguments.out, graph.to_dict())
        result = {
            "graph_digest": graph.digest,
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "roots": len(graph.roots),
            "sinks": len(graph.sinks),
            "written": str(Path(arguments.out).resolve()),
        }
        if arguments.json:
            _emit_json(result)
        else:
            print(f"graph: {result['graph_digest']}")
            print(f"selected paths: {result['edges']}")
            print(f"written: {result['written']}")
        return 0

    if arguments.command == "execute":
        graph, plan = _load_graph_and_verified_plan(arguments.graph, arguments.plan)
        executors = _provider_executors(plan)
        if arguments.execution_mode == "preview":
            preview = create_execution_preview(graph, plan, executors)
            write_json(arguments.out, preview)
            result = {
                "preview_digest": preview["preview_digest"],
                "expires_at": preview["expires_at"],
                "actions": len(preview["actions"]),
                "written": str(Path(arguments.out).resolve()),
            }
            if arguments.json:
                _emit_json(result)
            else:
                print(f"preview: {result['preview_digest']}")
                print(f"expires: {result['expires_at']}")
                print(f"actions: {result['actions']}")
                print(f"written: {result['written']}")
            return 0
        preview = read_json(arguments.preview)
        summary = apply_execution(
            graph,
            plan,
            preview,
            arguments.confirm,
            arguments.journal,
            executors,
            resume=arguments.execution_mode == "resume",
        )
        if arguments.json:
            _emit_json(summary)
        else:
            print(f"verified actions: {summary['verified_actions']}/{summary['total_actions']}")
            print(f"journal: {summary['journal']}")
            if summary["unresolved_actions"]:
                print("unresolved: " + ", ".join(summary["unresolved_actions"]))
        return 0 if summary["complete"] else 5

    if arguments.command == "observe":
        graph, plan = _load_graph_and_verified_plan(arguments.graph, arguments.plan)
        executors = _provider_executors(plan)
        evidence = observe_execution(
            graph,
            plan,
            read_json(arguments.preview),
            arguments.journal,
            executors,
        )
        write_json(arguments.out, evidence)
        states = [item["status"] for item in evidence["observations"]]
        result = {
            "closed": states.count("VERIFIED_CLOSED"),
            "total": len(states),
            "written": str(Path(arguments.out).resolve()),
        }
        if arguments.json:
            _emit_json(result)
        else:
            print(f"verified closed: {result['closed']}/{result['total']}")
            print(f"written: {result['written']}")
        return 0 if result["closed"] == result["total"] else 5

    if arguments.command == "report":
        graph, plan = _load_graph_and_verified_plan(arguments.graph, arguments.plan)
        receipt = read_json(arguments.receipt)
        verification = verify_receipt(receipt, arguments.public_key, plan)
        events = read_execution_journal(arguments.journal) if arguments.journal else []
        write_html_report(
            arguments.out,
            render_html_report(
                graph,
                plan,
                receipt,
                verification,
                journal_events=events,
            ),
        )
        result = {
            "closure_state": verification["closure_state"],
            "receipt_digest": verification["receipt_digest"],
            "journal_events": len(events),
            "written": str(Path(arguments.out).resolve()),
        }
        if arguments.json:
            _emit_json(result)
        else:
            print(f"closure state: {result['closure_state']}")
            print("receipt signature: VALID")
            print(f"timeline events: {result['journal_events']}")
            print(f"written: {result['written']}")
        return 0 if verification["closure_state"] == "CLOSED" else 4

    if arguments.command == "demo":
        _run_demo(arguments.dir)
        return 0

    raise AssertionError(f"unhandled command: {arguments.command}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        return _execute(parser.parse_args(argv))
    except ClosureCtlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        detail = exc.strerror or exc.__class__.__name__
        print(f"error: local I/O failed: {detail}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return 130
