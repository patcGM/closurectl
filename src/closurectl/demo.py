"""Self-contained scenario used by the quickstart and CI."""

from __future__ import annotations

from typing import Any

from .models import ClosurePlan


def compromised_maintainer_graph() -> dict[str, Any]:
    return {
        "schema_version": "1",
        "title": "Compromised maintainer workstation",
        "roots": ["incident:stolen-authority-epoch"],
        "sinks": [
            "sink:github-repository",
            "sink:npm-publishing",
            "sink:production",
        ],
        "nodes": [
            {
                "id": "incident:stolen-authority-epoch",
                "kind": "authority_epoch",
                "label": "Authority copied before containment",
            },
            {
                "id": "github:session",
                "kind": "credential_handle",
                "label": "Compromised GitHub session",
            },
            {
                "id": "github:oidc-minter",
                "kind": "delegation",
                "label": "Actions workflow able to mint cloud sessions",
            },
            {
                "id": "github:queued-deploy",
                "kind": "pending_effect",
                "label": "Deployment authorized before revocation",
            },
            {
                "id": "npm:publication-credential",
                "kind": "credential_handle",
                "label": "Compromised npm publication credential",
            },
            {
                "id": "aws:derived-session",
                "kind": "derived_authority",
                "label": "Already-issued AWS role session",
            },
            {
                "id": "sink:github-repository",
                "kind": "consequential_sink",
                "label": "Repository administration",
            },
            {
                "id": "sink:npm-publishing",
                "kind": "consequential_sink",
                "label": "Package publication",
            },
            {
                "id": "sink:production",
                "kind": "consequential_sink",
                "label": "Production deployment",
            },
        ],
        "edges": [
            {
                "id": "copied-github-session",
                "source": "incident:stolen-authority-epoch",
                "target": "github:session",
                "kind": "copied_before_response",
                "label": "Attacker already possesses the GitHub authority",
                "revocable": False,
                "cost": 1,
            },
            {
                "id": "github-repository-access",
                "source": "github:session",
                "target": "sink:github-repository",
                "kind": "can_administer",
                "label": "Revoke the compromised GitHub session",
                "revocable": True,
                "cost": 2,
                "enforcement": {
                    "provider": "github",
                    "operation": "revoke_session",
                    "target": "maintainer-session",
                    "phase": "revoke_roots",
                },
            },
            {
                "id": "github-can-mint-oidc",
                "source": "github:session",
                "target": "github:oidc-minter",
                "kind": "can_mint",
                "label": "Disable the compromised OIDC publication workflow",
                "revocable": True,
                "cost": 1,
                "enforcement": {
                    "provider": "github",
                    "operation": "disable_workflow",
                    "target": "release.yml",
                    "phase": "stop_minting",
                },
            },
            {
                "id": "oidc-reaches-production",
                "source": "github:oidc-minter",
                "target": "sink:production",
                "kind": "can_deploy",
                "label": "OIDC workflow can deploy to production",
                "revocable": False,
                "cost": 1,
            },
            {
                "id": "copied-npm-credential",
                "source": "incident:stolen-authority-epoch",
                "target": "npm:publication-credential",
                "kind": "copied_before_response",
                "label": "Attacker already possesses npm publication authority",
                "revocable": False,
                "cost": 1,
            },
            {
                "id": "npm-can-publish",
                "source": "npm:publication-credential",
                "target": "sink:npm-publishing",
                "kind": "can_publish",
                "label": "Revoke the compromised npm publication credential",
                "revocable": True,
                "cost": 1,
                "enforcement": {
                    "provider": "npm",
                    "operation": "revoke_publication_credential",
                    "target": "affected-maintainer",
                    "phase": "revoke_roots",
                },
            },
            {
                "id": "queued-before-response",
                "source": "incident:stolen-authority-epoch",
                "target": "github:queued-deploy",
                "kind": "authorized_before_response",
                "label": "A queued deployment survives root credential revocation",
                "revocable": False,
                "cost": 1,
            },
            {
                "id": "queued-deploy-can-commit",
                "source": "github:queued-deploy",
                "target": "sink:production",
                "kind": "pending_effect",
                "label": "Cancel the previously authorized deployment",
                "revocable": True,
                "cost": 1,
                "enforcement": {
                    "provider": "github",
                    "operation": "cancel_workflow_run",
                    "target": "queued-production-deploy",
                    "phase": "cancel_pending",
                },
            },
            {
                "id": "session-issued-before-response",
                "source": "incident:stolen-authority-epoch",
                "target": "aws:derived-session",
                "kind": "derived_before_response",
                "label": "An AWS session was issued before root revocation",
                "revocable": False,
                "cost": 1,
            },
            {
                "id": "aws-session-can-deploy",
                "source": "aws:derived-session",
                "target": "sink:production",
                "kind": "can_deploy",
                "label": "Invalidate the already-issued AWS role session",
                "revocable": True,
                "cost": 2,
                "enforcement": {
                    "provider": "aws",
                    "operation": "invalidate_role_sessions",
                    "target": "production-deployer",
                    "phase": "revoke_descendants",
                },
            },
        ],
    }


def closed_evidence(plan: ClosurePlan, checked_at: str) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "plan_digest": plan.digest,
        "observations": [
            {
                "action_id": action.action_id,
                "status": "VERIFIED_CLOSED",
                "checked_at": checked_at,
                "summary": f"Demo verifier observed denial after {action.operation}",
                "reference": f"demo://{action.action_id}",
            }
            for action in plan.actions
        ],
    }
