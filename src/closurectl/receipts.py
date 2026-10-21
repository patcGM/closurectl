"""Integrity-protected closure receipts using Ed25519 signatures."""

from __future__ import annotations

import base64
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import __version__
from .errors import SignatureError, ValidationError
from .models import ClosurePlan
from .serialization import canonical_json, digest_json

ALLOWED_OBSERVATION_STATES = {
    "VERIFIED_CLOSED",
    "STILL_OPEN",
    "INDETERMINATE",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_exact_fields(
    value: dict[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    context: str,
) -> None:
    optional = optional or set()
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise ValidationError(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")


def _validate_timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty RFC 3339 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include a UTC offset")
    return value


def _exclusive_write(path: Path, content: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor != -1:
            os.close(descriptor)


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    private_destination = Path(private_path)
    public_destination = Path(public_path)
    private_identity = os.path.normcase(str(private_destination.resolve()))
    public_identity = os.path.normcase(str(public_destination.resolve()))
    if private_identity == public_identity:
        raise ValidationError("private and public key paths must be different")
    private_destination.parent.mkdir(parents=True, exist_ok=True)
    public_destination.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        _exclusive_write(private_destination, private_bytes, 0o600)
        try:
            _exclusive_write(public_destination, public_bytes, 0o644)
        except FileExistsError:
            private_destination.unlink(missing_ok=True)
            raise
        try:
            private_destination.chmod(0o600)
        except OSError:
            pass
    except FileExistsError as exc:
        raise ValidationError("refusing to overwrite an existing signing key") from exc


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise SignatureError(f"cannot load private key: {path}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError("signing key is not Ed25519")
    return key


def _load_public_key(path: str | Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise SignatureError(f"cannot load public key: {path}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError("verification key is not Ed25519")
    return key


def _validate_evidence(
    plan: ClosurePlan, evidence: dict[str, Any]
) -> tuple[list[dict[str, str]], list[str]]:
    if not isinstance(evidence, dict):
        raise ValidationError("invalid evidence schema")
    _require_exact_fields(
        evidence,
        required={"schema_version", "plan_digest", "observations"},
        context="evidence",
    )
    if evidence.get("schema_version") != "1":
        raise ValidationError("invalid evidence schema")
    if evidence.get("plan_digest") != plan.digest:
        raise ValidationError("evidence plan_digest does not match the plan")
    raw_observations = evidence.get("observations")
    if not isinstance(raw_observations, list):
        raise ValidationError("evidence.observations must be an array")

    expected = {action.action_id for action in plan.actions}
    observations: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in raw_observations:
        if not isinstance(raw, dict):
            raise ValidationError("each observation must be an object")
        _require_exact_fields(
            raw,
            required={"action_id", "status", "checked_at", "summary"},
            optional={"reference"},
            context="observation",
        )
        action_id = raw.get("action_id")
        status = raw.get("status")
        checked_at = raw.get("checked_at")
        summary = raw.get("summary")
        reference = raw.get("reference", "")
        if not all(
            isinstance(item, str) for item in (action_id, status, checked_at, summary, reference)
        ):
            raise ValidationError("observation fields must be strings")
        if action_id not in expected:
            raise ValidationError(f"observation references unknown action: {action_id}")
        if action_id in seen:
            raise ValidationError(f"duplicate observation for action: {action_id}")
        if status not in ALLOWED_OBSERVATION_STATES:
            allowed = ", ".join(sorted(ALLOWED_OBSERVATION_STATES))
            raise ValidationError(f"observation.status must be one of: {allowed}")
        if not checked_at or not summary:
            raise ValidationError("checked_at and summary must not be empty")
        _validate_timestamp(checked_at, "observation.checked_at")
        seen.add(action_id)
        observations.append(
            {
                "action_id": action_id,
                "status": status,
                "checked_at": checked_at,
                "summary": summary,
                "reference": reference,
            }
        )
    observations.sort(key=lambda item: item["action_id"])
    return observations, sorted(expected - seen)


def _closure_state(
    plan: ClosurePlan, observations: list[dict[str, str]], missing: list[str]
) -> str:
    if plan.status == "BLOCKED":
        return "BLOCKED"
    states = [item["status"] for item in observations]
    closed = states.count("VERIFIED_CLOSED")
    opened = states.count("STILL_OPEN")
    unknown = states.count("INDETERMINATE") + len(missing)
    if closed == len(plan.actions) and not missing:
        return "CLOSED"
    if closed > 0:
        return "PARTIAL"
    if opened > 0:
        return "OPEN"
    if unknown > 0:
        return "INDETERMINATE"
    return "INDETERMINATE"


def create_receipt(
    plan: ClosurePlan,
    evidence: dict[str, Any],
    private_key_path: str | Path,
    *,
    issued_at: str | None = None,
) -> dict[str, Any]:
    observations, missing = _validate_evidence(plan, evidence)
    receipt_time = _validate_timestamp(issued_at or utc_now(), "receipt.issued_at")
    payload: dict[str, Any] = {
        "schema_version": "1",
        "tool": {"name": "closurectl", "version": __version__},
        "issued_at": receipt_time,
        "plan_digest": plan.digest,
        "graph_digest": plan.graph_digest,
        "closure_state": _closure_state(plan, observations, missing),
        "observations": observations,
        "missing_actions": missing,
        "scope_statement": (
            "This receipt covers only the declared graph, plan, and observations. "
            "It does not prove global attacker eviction."
        ),
    }
    payload_bytes = canonical_json(payload)
    signature = _load_private_key(private_key_path).sign(payload_bytes)
    return {
        **payload,
        "receipt_digest": digest_json(payload),
        "signature": {
            "algorithm": "Ed25519",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_receipt(
    receipt: dict[str, Any],
    public_key_path: str | Path,
    plan: ClosurePlan,
) -> dict[str, str]:
    if not isinstance(receipt, dict):
        raise SignatureError("invalid receipt schema")
    try:
        _require_exact_fields(
            receipt,
            required={
                "schema_version",
                "tool",
                "issued_at",
                "plan_digest",
                "graph_digest",
                "closure_state",
                "observations",
                "missing_actions",
                "scope_statement",
                "receipt_digest",
                "signature",
            },
            context="receipt",
        )
        if receipt.get("schema_version") != "1":
            raise ValidationError("invalid receipt schema")
        tool = receipt.get("tool")
        if not isinstance(tool, dict):
            raise ValidationError("receipt.tool must be an object")
        _require_exact_fields(tool, required={"name", "version"}, context="receipt.tool")
        if (
            tool.get("name") != "closurectl"
            or not isinstance(tool.get("version"), str)
            or not tool["version"].strip()
        ):
            raise ValidationError("invalid receipt tool identity")
        _validate_timestamp(receipt.get("issued_at"), "receipt.issued_at")
        if receipt.get("plan_digest") != plan.digest:
            raise ValidationError("receipt plan_digest does not match the plan")
        if receipt.get("graph_digest") != plan.graph_digest:
            raise ValidationError("receipt graph_digest does not match the plan")
        if (
            not isinstance(receipt.get("scope_statement"), str)
            or not receipt["scope_statement"].strip()
        ):
            raise ValidationError("receipt.scope_statement must not be empty")
    except ValidationError as exc:
        raise SignatureError(str(exc)) from exc

    signature_block = receipt.get("signature")
    if not isinstance(signature_block, dict):
        raise SignatureError("receipt has no signature")
    try:
        _require_exact_fields(
            signature_block,
            required={"algorithm", "value"},
            context="receipt.signature",
        )
    except ValidationError as exc:
        raise SignatureError(str(exc)) from exc
    if signature_block.get("algorithm") != "Ed25519":
        raise SignatureError("unsupported signature algorithm")
    supplied_digest = receipt.get("receipt_digest")
    if not isinstance(supplied_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", supplied_digest):
        raise SignatureError("receipt_digest is not a lowercase SHA-256 digest")
    payload = {
        key: value for key, value in receipt.items() if key not in {"receipt_digest", "signature"}
    }
    computed_digest = digest_json(payload)
    if supplied_digest != computed_digest:
        raise SignatureError("receipt digest does not match its contents")
    try:
        signature = base64.b64decode(signature_block.get("value", ""), validate=True)
    except (ValueError, TypeError) as exc:
        raise SignatureError("receipt signature is not valid base64") from exc
    try:
        _load_public_key(public_key_path).verify(signature, canonical_json(payload))
    except InvalidSignature as exc:
        raise SignatureError("receipt signature verification failed") from exc

    try:
        observations, missing = _validate_evidence(
            plan,
            {
                "schema_version": "1",
                "plan_digest": receipt["plan_digest"],
                "observations": receipt["observations"],
            },
        )
    except ValidationError as exc:
        raise SignatureError(str(exc)) from exc
    if receipt["observations"] != observations:
        raise SignatureError("receipt observations are not canonically ordered")
    if receipt["missing_actions"] != missing:
        raise SignatureError("receipt missing_actions does not match the plan")
    expected_state = _closure_state(plan, observations, missing)
    if receipt["closure_state"] != expected_state:
        raise SignatureError(f"receipt closure_state must be {expected_state} for its observations")
    return {
        "receipt_digest": computed_digest,
        "closure_state": str(receipt.get("closure_state")),
        "issued_at": str(receipt.get("issued_at")),
    }
